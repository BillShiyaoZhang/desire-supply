"""IAM current-policy acceptance and consent-grant command boundary.

The handlers deliberately depend only on the narrow operation-scoped mapping
unit of work.  A receipt, legal evidence, audit event, and each closed outbox
event are committed atomically; no provider call occurs inside the boundary.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
import unicodedata
from typing import Any, Mapping, Optional, Sequence, Tuple

from ..domain.errors import IamError
from ..domain.policies import (
    ConsentExpiryRule,
    ConsentOffer,
    ConsentOfferChoice,
    ConsentPurpose,
    ConsentScopeDerivation,
    ConsentScopeType,
    DataCategory,
    PolicyAcceptance,
    PolicyBundle,
    PolicyBundleStatus,
    PolicyDocument,
    PolicyDocumentStatus,
    PolicyLegalEffect,
    canonical_consent_offer_bytes,
)
from ..ports.policy_consent_commands import (
    PolicyConsentCommitOutcomeUnknownError,
    PolicyConsentKeyUnavailableError,
    PolicyConsentSchemaUnavailableError,
    PolicyConsentStorageUnavailableError,
    PolicyConsentTelemetryEvent,
)


POLICY_CONSENT_COMMAND_BEHAVIOR_NOT_AVAILABLE = (
    "IAM_POLICY_CONSENT_COMMAND_BEHAVIOR_NOT_AVAILABLE"
)
_CANONICALIZATION_VERSION = "restricted-canonical-json-v1"
_IDENTITY_DOMAIN = "iam-self-command-idempotency-key-v1"
_RECIPIENT_BINDING_DOMAIN = b"iam-consent-recipient-reference-v1\x00"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ETAG = re.compile(r'^"v[1-9][0-9]*"$')
_SUPPORTED_CATEGORIES = (
    DataCategory.PROFILE,
    DataCategory.MATCHING,
    DataCategory.RESEARCH,
)


class PolicyRequirementScopeType(str, Enum):
    USER_ROLE = "USER_ROLE"
    ORGANIZATION_ROLE = "ORGANIZATION_ROLE"


@dataclass(frozen=True)
class PolicyRequirementReference:
    selector_digest: str
    scope_type: PolicyRequirementScopeType
    scope_id: Optional[str]

    def __post_init__(self) -> None:
        try:
            scope_type = PolicyRequirementScopeType(self.scope_type)
        except (TypeError, ValueError) as error:
            raise IamError("INVALID_REQUEST") from error
        if (
            not isinstance(self.selector_digest, str)
            or len(self.selector_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.selector_digest)
        ):
            raise IamError("INVALID_REQUEST")
        if scope_type is PolicyRequirementScopeType.USER_ROLE:
            if self.scope_id is not None:
                raise IamError("INVALID_REQUEST")
        elif not isinstance(self.scope_id, str) or not self.scope_id:
            raise IamError("INVALID_REQUEST")
        object.__setattr__(self, "scope_type", scope_type)


@dataclass(frozen=True)
class PolicyConsentActor:
    actor_user_id: str
    current_session_id: str
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str


@dataclass(frozen=True)
class AcceptCurrentPoliciesCommand:
    policy_requirement: PolicyRequirementReference
    policy_bundle_id: str
    policy_acceptances: Tuple[PolicyAcceptance, ...]
    expected_user_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class GrantConsentCommand:
    policy_requirement: PolicyRequirementReference
    policy_bundle_id: str
    consent_choice: ConsentOfferChoice
    expected_user_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class PolicyConsentCommandResult:
    operation_id: str
    replayed: bool
    http_status: int
    json_body: Mapping[str, Any] = field(repr=False)
    response_entity_tag: str
    current_user_entity_tag: str

    def body_copy(self) -> dict[str, Any]:
        from copy import deepcopy

        return deepcopy(dict(self.json_body))


@dataclass(frozen=True)
class _CommandProfile:
    command_name: str
    operation_id: str
    path: str
    http_status: int
    response_schema: str
    request_body: Mapping[str, Any] = field(repr=False)
    payload_projection: Mapping[str, Any] = field(repr=False)


@dataclass(frozen=True)
class _PreparedCommand:
    now: datetime
    snapshot: Mapping[str, Mapping[Any, Any]] = field(repr=False)
    session: Mapping[str, Any] = field(repr=False)
    profile: _CommandProfile
    active_material: Mapping[str, Any] = field(repr=False)
    identity_digests: Mapping[str, str] = field(repr=False)
    payload_key_ids: Tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class _Authority:
    selector: Mapping[str, Any] = field(repr=False)
    role_grant: Mapping[str, Any] = field(repr=False)
    source_invitation: Mapping[str, Any] = field(repr=False)
    role: str
    purpose: str
    scope_type: PolicyRequirementScopeType
    scope_id: Optional[str]
    organization_id: Optional[str]
    membership: Optional[Mapping[str, Any]] = field(default=None, repr=False)


class _PolicyConsentHandler:
    def __init__(
        self,
        *,
        uow_factory: Any,
        clock: Any,
        id_source: Any,
        keyring: Any,
        event_validator: Any,
        safe_response_validator: Any,
        telemetry: Optional[Any] = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._id_source = id_source
        self._keyring = keyring
        self._event_validator = event_validator
        self._safe_response_validator = safe_response_validator
        self._telemetry = telemetry

    def _prepare(
        self,
        *,
        actor: PolicyConsentActor,
        command: object,
    ) -> tuple[_PreparedCommand, Optional[PolicyConsentCommandResult]]:
        now = self._now()
        snapshot = self._snapshot()
        profile = _command_profile(command, actor.actor_user_id)
        raw_session = snapshot.get("sessions", {}).get(actor.current_session_id)
        identity_key_ids, payload_key_ids = self._preflight_keys(raw_session)
        session = _require_current_session(snapshot, actor=actor, now=now)
        identity_digests = {
            key_id: self._keyed_digest(
                key_id,
                _canonical_bytes(
                    {
                        "domain": _IDENTITY_DOMAIN,
                        "idempotency_key": getattr(command, "idempotency_key"),
                    }
                ),
            )
            for key_id in identity_key_ids
        }
        active_identity_key_id = self._keyring.idempotency_key_digest_key_id
        active_payload_key_id = self._keyring.payload_hash_key_id
        active_material = {
            "principal_kind": "USER",
            "principal_id": actor.actor_user_id,
            "command_name": profile.command_name,
            "command_version": 1,
            "idempotency_key_digest": identity_digests[active_identity_key_id],
            "idempotency_key_digest_key_id": active_identity_key_id,
            "payload_hash": self._keyed_digest(
                active_payload_key_id,
                _canonical_bytes(profile.payload_projection),
            ),
            "payload_hash_key_id": active_payload_key_id,
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "target_type": "User",
            "target_id": actor.actor_user_id,
            "http_method": "POST",
            "canonical_path": profile.path,
            "if_match_version": getattr(command, "expected_user_version"),
        }
        prepared = _PreparedCommand(
            now=now,
            snapshot=snapshot,
            session=session,
            profile=profile,
            active_material=active_material,
            identity_digests=identity_digests,
            payload_key_ids=payload_key_ids,
        )
        receipt = _find_receipt(
            snapshot,
            actor_id=actor.actor_user_id,
            command_name=profile.command_name,
            identity_digests=identity_digests,
        )
        if receipt is None:
            return prepared, None
        result = self._replay_result(
            receipt=receipt,
            prepared=prepared,
            command=command,
        )
        self._record_telemetry(
            operation_id=profile.operation_id,
            outcome_code="SUCCEEDED",
            replayed=True,
            changed=False,
            trace_id=actor.trace_id,
        )
        return prepared, result

    def _snapshot(self) -> Mapping[str, Mapping[Any, Any]]:
        try:
            snapshot = self._uow_factory.store.snapshot()
        except PolicyConsentStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if not isinstance(snapshot, Mapping):
            raise IamError("SERVICE_UNAVAILABLE")
        return snapshot

    def _now(self) -> datetime:
        now = self._clock.now()
        if not _is_utc(now):
            raise IamError("SERVICE_UNAVAILABLE")
        return now.astimezone(timezone.utc)

    def _preflight_keys(
        self, raw_session: object
    ) -> tuple[Tuple[str, ...], Tuple[str, ...]]:
        active_identity = getattr(
            self._keyring, "idempotency_key_digest_key_id", None
        )
        active_payload = getattr(self._keyring, "payload_hash_key_id", None)
        identity_ids = _closed_key_ids(
            getattr(
                self._keyring,
                "retained_idempotency_key_digest_key_ids",
                (active_identity,),
            ),
            active_identity,
        )
        payload_ids = _closed_key_ids(
            getattr(
                self._keyring,
                "retained_payload_hash_key_ids",
                (active_payload,),
            ),
            active_payload,
        )
        session_ids: tuple[object, ...] = ()
        if isinstance(raw_session, Mapping):
            session_ids = (
                raw_session.get("handle_digest_key_id"),
                raw_session.get("csrf_key_id"),
            )
        for key_id in dict.fromkeys((*identity_ids, *payload_ids, *session_ids)):
            if not isinstance(key_id, str) or not key_id:
                raise IamError("SERVICE_UNAVAILABLE")
            self._keyed_digest(key_id, b"iam-policy-consent-key-preflight-v1")
        return identity_ids, payload_ids

    def _keyed_digest(self, key_id: str, value: bytes) -> str:
        try:
            result = self._keyring.keyed_digest_hex(
                key_id=key_id,
                canonical_bytes=value,
            )
        except PolicyConsentKeyUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if not isinstance(result, str) or _SHA256.fullmatch(result) is None:
            raise IamError("SERVICE_UNAVAILABLE")
        return result

    def _replay_result(
        self,
        *,
        receipt: Mapping[str, Any],
        prepared: _PreparedCommand,
        command: object,
    ) -> PolicyConsentCommandResult:
        identity_key_id = receipt.get("idempotency_key_digest_key_id")
        if (
            not isinstance(identity_key_id, str)
            or prepared.identity_digests.get(identity_key_id)
            != receipt.get("idempotency_key_digest")
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        payload_key_id = receipt.get("payload_hash_key_id")
        if payload_key_id not in prepared.payload_key_ids:
            raise IamError("SERVICE_UNAVAILABLE")
        payload_hash = self._keyed_digest(
            payload_key_id,
            _canonical_bytes(prepared.profile.payload_projection),
        )
        if not hmac.compare_digest(str(receipt.get("payload_hash")), payload_hash):
            raise IamError("IDEMPOTENCY_KEY_REUSED")
        expected_metadata = {
            "principal_kind": "USER",
            "principal_id": prepared.active_material["principal_id"],
            "command_name": prepared.profile.command_name,
            "command_version": 1,
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "target_type": "User",
            "target_id": prepared.active_material["target_id"],
            "http_method": "POST",
            "canonical_path": prepared.profile.path,
            "if_match_version": getattr(command, "expected_user_version"),
        }
        if any(receipt.get(name) != value for name, value in expected_metadata.items()):
            raise IamError("SERVICE_UNAVAILABLE")
        if receipt.get("status") != "COMPLETED":
            raise IamError("SERVICE_UNAVAILABLE")
        if (
            receipt.get("response_schema") != prepared.profile.response_schema
            or receipt.get("response_schema_version") != 1
            or receipt.get("response_http_status") != prepared.profile.http_status
            or not isinstance(receipt.get("response_body"), Mapping)
            or _ETAG.fullmatch(str(receipt.get("response_entity_tag"))) is None
            or _ETAG.fullmatch(str(receipt.get("current_user_entity_tag"))) is None
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        response_body = deepcopy(dict(receipt["response_body"]))
        _require_response_binding(
            response_body,
            command=command,
            profile=prepared.profile,
        )
        self._validate_response(response_body, prepared.profile.response_schema)
        return PolicyConsentCommandResult(
            operation_id=prepared.profile.operation_id,
            replayed=True,
            http_status=prepared.profile.http_status,
            json_body=response_body,
            response_entity_tag=receipt["response_entity_tag"],
            current_user_entity_tag=receipt["current_user_entity_tag"],
        )

    def _new_id(self, kind: str) -> str:
        value = self._id_source.new_id(kind)
        if not isinstance(value, str) or not value:
            raise IamError("SERVICE_UNAVAILABLE")
        return value

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
        except PolicyConsentStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        except IamError:
            raise

    def _commit(self, uow: Any) -> None:
        try:
            uow.commit()
        except PolicyConsentCommitOutcomeUnknownError as error:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from error
        except PolicyConsentStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        except IamError:
            raise
        except Exception as error:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from error

    def _validate_event(self, event: Mapping[str, Any]) -> None:
        try:
            self._event_validator.validate(event)
        except PolicyConsentSchemaUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _validate_response(self, body: Mapping[str, Any], schema_name: str) -> None:
        try:
            self._safe_response_validator.validate(body, schema_name)
        except PolicyConsentSchemaUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _record_telemetry(
        self,
        *,
        operation_id: str,
        outcome_code: str,
        replayed: bool,
        changed: bool,
        trace_id: str,
    ) -> None:
        if self._telemetry is None:
            return
        try:
            self._telemetry.record(
                PolicyConsentTelemetryEvent(
                    operation_id=operation_id,
                    outcome_code=outcome_code,
                    replayed=replayed,
                    change_count_bucket="ONE_OR_MORE" if changed else "ZERO",
                    latency_bucket="NOT_MEASURED",
                    trace_id=trace_id,
                )
            )
        except Exception:
            # Telemetry is deliberately non-authoritative and cannot alter a
            # committed command outcome.
            return


class AcceptCurrentPoliciesHandler(_PolicyConsentHandler):
    def handle(
        self,
        *,
        actor: PolicyConsentActor,
        command: AcceptCurrentPoliciesCommand,
    ) -> PolicyConsentCommandResult:
        prepared, replay = self._prepare(actor=actor, command=command)
        if replay is not None:
            return replay
        changed = False
        try:
            with self._uow_factory.begin() as uow:
                _lock_receipt(uow, prepared.active_material)
                _lock_actor(uow, prepared.snapshot, actor)
                tables = uow.tables
                session = _require_current_session(
                    tables,
                    actor=actor,
                    now=prepared.now,
                )
                raced_receipt = _find_receipt(
                    tables,
                    actor_id=actor.actor_user_id,
                    command_name=prepared.profile.command_name,
                    identity_digests=prepared.identity_digests,
                )
                if raced_receipt is not None:
                    return self._replay_result(
                        receipt=raced_receipt,
                        prepared=prepared,
                        command=command,
                    )
                user = _require_expected_user(
                    tables,
                    actor.actor_user_id,
                    command.expected_user_version,
                )
                authority = _resolve_authority(
                    tables,
                    actor=actor,
                    reference=command.policy_requirement,
                    uow=uow,
                )
                bundle = _require_current_bundle(
                    tables,
                    authority=authority,
                    reference=command.policy_requirement,
                    presented_bundle_id=command.policy_bundle_id,
                    now=prepared.now,
                    uow=uow,
                )
                evaluation = _evaluate_bundle(
                    bundle,
                    now=prepared.now,
                    presented_bundle_id=command.policy_bundle_id,
                    policy_acceptances=command.policy_acceptances,
                    consent_choices=(),
                )
                existing, missing = _required_acceptance_evidence(
                    tables,
                    actor_user_id=actor.actor_user_id,
                    bundle=bundle,
                    requested=evaluation.policy_acceptances,
                )
                receipt_id = self._new_id("command_receipt")
                pending = _pending_receipt(
                    receipt_id=receipt_id,
                    material=prepared.active_material,
                    now=prepared.now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    pending,
                    "accept.receipt_in_progress",
                )
                events: list[Mapping[str, Any]] = []
                documents = {item.document_id: item for item in bundle.documents}
                for index, acceptance in enumerate(missing, start=1):
                    document = documents[acceptance.document_id]
                    acceptance_id = self._new_id("policy_acceptance")
                    fact = _new_acceptance_fact(
                        acceptance_id=acceptance_id,
                        actor=actor,
                        session=session,
                        receipt_id=receipt_id,
                        bundle=bundle,
                        document=document,
                        now=prepared.now,
                    )
                    self._put(
                        uow,
                        "policy_acceptances",
                        acceptance_id,
                        fact,
                        f"accept.policy_acceptance.{index:04d}",
                    )
                    events.append(
                        _event_envelope(
                            event_id=self._new_id("outbox_event"),
                            event_type="PolicyAccepted",
                            aggregate_type="PolicyAcceptance",
                            aggregate_id=acceptance_id,
                            aggregate_version=1,
                            actor=actor,
                            causation_id=receipt_id,
                            organization_id=authority.organization_id,
                            occurred_at=prepared.now,
                            payload={
                                "policy_acceptance_id": acceptance_id,
                                "user_id": actor.actor_user_id,
                                "policy_bundle_id": bundle.policy_bundle_id,
                                "policy_document_id": document.document_id,
                                "policy_document_sha256": document.content_sha256,
                                "legal_effect": document.legal_effect.value,
                            },
                        )
                    )
                after_version = user["aggregate_version"]
                if missing:
                    changed = True
                    after_version += 1
                    updated_user = deepcopy(dict(user))
                    updated_user["aggregate_version"] = after_version
                    self._put(
                        uow,
                        "users",
                        actor.actor_user_id,
                        updated_user,
                        "accept.user",
                    )
                    events.append(
                        _event_envelope(
                            event_id=self._new_id("outbox_event"),
                            event_type="PolicyRequirementsSatisfied",
                            aggregate_type="User",
                            aggregate_id=actor.actor_user_id,
                            aggregate_version=after_version,
                            actor=actor,
                            causation_id=receipt_id,
                            organization_id=authority.organization_id,
                            occurred_at=prepared.now,
                            payload={
                                "user_id": actor.actor_user_id,
                                "policy_bundle_id": bundle.policy_bundle_id,
                            },
                        )
                    )
                response = _requirement_response(authority, bundle)
                self._validate_response(
                    response,
                    prepared.profile.response_schema,
                )
                response_etag = _entity_tag(after_version)
                audit_id = self._new_id("audit_event")
                self._put(
                    uow,
                    "audit_events",
                    audit_id,
                    _audit_event(
                        audit_id=audit_id,
                        actor=actor,
                        session=session,
                        action="POLICY_ACCEPT",
                        authority=authority,
                        receipt_id=receipt_id,
                        before_user_version=user["aggregate_version"],
                        after_user_version=after_version,
                        result="CREATED" if changed else "REUSED",
                        now=prepared.now,
                    ),
                    "accept.audit",
                )
                for index, event in enumerate(events, start=1):
                    self._validate_event(event)
                    checkpoint = (
                        f"accept.outbox.policy_accepted.{index:04d}"
                        if event["event_type"] == "PolicyAccepted"
                        else "accept.outbox.requirements_satisfied"
                    )
                    self._put(
                        uow,
                        "outbox_events",
                        event["event_id"],
                        event,
                        checkpoint,
                    )
                completed = _complete_receipt(
                    pending,
                    profile=prepared.profile,
                    response_body=response,
                    response_entity_tag=response_etag,
                    current_user_entity_tag=response_etag,
                    now=prepared.now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    completed,
                    "accept.receipt_completed",
                )
                self._commit(uow)
        except IamError:
            raise
        except PolicyConsentStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        self._record_telemetry(
            operation_id=prepared.profile.operation_id,
            outcome_code="SUCCEEDED",
            replayed=False,
            changed=changed,
            trace_id=actor.trace_id,
        )
        return PolicyConsentCommandResult(
            operation_id=prepared.profile.operation_id,
            replayed=False,
            http_status=prepared.profile.http_status,
            json_body=response,
            response_entity_tag=response_etag,
            current_user_entity_tag=response_etag,
        )


class GrantConsentHandler(_PolicyConsentHandler):
    def handle(
        self,
        *,
        actor: PolicyConsentActor,
        command: GrantConsentCommand,
    ) -> PolicyConsentCommandResult:
        prepared, replay = self._prepare(actor=actor, command=command)
        if replay is not None:
            return replay
        changed = False
        try:
            with self._uow_factory.begin() as uow:
                _lock_receipt(uow, prepared.active_material)
                _lock_actor(uow, prepared.snapshot, actor)
                tables = uow.tables
                session = _require_current_session(
                    tables,
                    actor=actor,
                    now=prepared.now,
                )
                raced_receipt = _find_receipt(
                    tables,
                    actor_id=actor.actor_user_id,
                    command_name=prepared.profile.command_name,
                    identity_digests=prepared.identity_digests,
                )
                if raced_receipt is not None:
                    return self._replay_result(
                        receipt=raced_receipt,
                        prepared=prepared,
                        command=command,
                    )
                user = _require_expected_user(
                    tables,
                    actor.actor_user_id,
                    command.expected_user_version,
                )
                authority = _resolve_authority(
                    tables,
                    actor=actor,
                    reference=command.policy_requirement,
                    uow=uow,
                )
                bundle = _require_current_bundle(
                    tables,
                    authority=authority,
                    reference=command.policy_requirement,
                    presented_bundle_id=command.policy_bundle_id,
                    now=prepared.now,
                    uow=uow,
                )
                policy_evidence, missing = _required_acceptance_evidence(
                    tables,
                    actor_user_id=actor.actor_user_id,
                    bundle=bundle,
                    requested=None,
                )
                if missing:
                    raise IamError("POLICY_ACCEPTANCE_REQUIRED")
                if command.consent_choice.affirmed is not True:
                    raise IamError("INVALID_REQUEST")
                evaluation = _evaluate_bundle(
                    bundle,
                    now=prepared.now,
                    presented_bundle_id=command.policy_bundle_id,
                    policy_acceptances=tuple(policy_evidence),
                    consent_choices=(command.consent_choice,),
                )
                if len(evaluation.consent_authorizations) != 1:
                    raise IamError("INVALID_REQUEST")
                authorization = evaluation.consent_authorizations[0]
                offer = _offer_for_authorization(bundle, authorization)
                uow.lock(
                    "consent_grants",
                    (
                        _consent_authority_lock_key(
                            actor.actor_user_id,
                            authorization.purpose.value,
                            authorization.scope_type.value,
                            authorization.scope_id,
                        ),
                    ),
                )
                active_rows = _active_authority_grants(
                    tables,
                    actor_user_id=actor.actor_user_id,
                    purpose=authorization.purpose.value,
                    scope_type=authorization.scope_type.value,
                    scope_id=authorization.scope_id,
                )
                expired_rows = [
                    row
                    for row in active_rows
                    if _required_utc(row.get("expires_at"), "SERVICE_UNAVAILABLE")
                    <= prepared.now
                ]
                for index, row in enumerate(expired_rows, start=1):
                    expired = deepcopy(dict(row))
                    expired.update(
                        {
                            "status": "EXPIRED",
                            "aggregate_version": _positive_version(
                                row.get("aggregate_version"),
                                "SERVICE_UNAVAILABLE",
                            )
                            + 1,
                            "updated_at": prepared.now,
                        }
                    )
                    self._put(
                        uow,
                        "consent_grants",
                        row["consent_grant_id"],
                        expired,
                        f"grant.expire.{index:04d}",
                    )
                live_rows = [row for row in active_rows if row not in expired_rows]
                if len(live_rows) > 1:
                    raise IamError("SERVICE_UNAVAILABLE")
                receipt_id = self._new_id("command_receipt")
                pending = _pending_receipt(
                    receipt_id=receipt_id,
                    material=prepared.active_material,
                    now=prepared.now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    pending,
                    "grant.receipt_in_progress",
                )
                event: Optional[Mapping[str, Any]] = None
                if live_rows:
                    grant = live_rows[0]
                    if not _grant_matches_authorization(
                        grant,
                        authorization=authorization,
                        offer=offer,
                        recipient_binding=self._recipient_binding(offer),
                    ):
                        raise IamError("INVALID_STATE_TRANSITION")
                    _validate_grant_evidence(grant)
                else:
                    changed = True
                    grant_id = self._new_id("consent_grant")
                    grant = _new_grant_fact(
                        grant_id=grant_id,
                        actor=actor,
                        session=session,
                        receipt_id=receipt_id,
                        authorization=authorization,
                        offer=offer,
                        recipient_binding=self._recipient_binding(offer),
                        recipient_binding_key_id=self._keyring.payload_hash_key_id,
                        now=prepared.now,
                    )
                    self._put(
                        uow,
                        "consent_grants",
                        grant_id,
                        grant,
                        "grant.consent_grant",
                    )
                    event = _event_envelope(
                        event_id=self._new_id("outbox_event"),
                        event_type="ConsentGranted",
                        aggregate_type="ConsentGrant",
                        aggregate_id=grant_id,
                        aggregate_version=1,
                        actor=actor,
                        causation_id=receipt_id,
                        organization_id=authority.organization_id,
                        occurred_at=prepared.now,
                        payload={
                            "consent_grant_id": grant_id,
                            "user_id": actor.actor_user_id,
                            "status": "ACTIVE",
                            "granted_at": _timestamp(prepared.now),
                            "derived_authorization": {
                                "consent_offer_id": authorization.consent_offer_id,
                                "consent_offer_version": authorization.consent_offer_version,
                                "policy_bundle_id": authorization.policy_bundle_id,
                                "purpose": authorization.purpose.value,
                                "scope_type": authorization.scope_type.value,
                                "scope_id": authorization.scope_id,
                                "data_categories": [
                                    item.value
                                    for item in authorization.data_categories
                                ],
                                "supporting_policy_document_id": (
                                    authorization.supporting_policy_document_id
                                ),
                                "supporting_document_sha256": (
                                    authorization.supporting_document_sha256
                                ),
                                "expires_at": _timestamp(
                                    authorization.expires_at
                                ),
                            },
                        },
                    )
                after_version = user["aggregate_version"]
                if changed:
                    after_version += 1
                    updated_user = deepcopy(dict(user))
                    updated_user["aggregate_version"] = after_version
                    self._put(
                        uow,
                        "users",
                        actor.actor_user_id,
                        updated_user,
                        "grant.user",
                    )
                response = _grant_response(grant)
                self._validate_response(
                    response,
                    prepared.profile.response_schema,
                )
                response_etag = _entity_tag(grant["aggregate_version"])
                current_user_etag = _entity_tag(after_version)
                audit_id = self._new_id("audit_event")
                self._put(
                    uow,
                    "audit_events",
                    audit_id,
                    _audit_event(
                        audit_id=audit_id,
                        actor=actor,
                        session=session,
                        action="CONSENT_GRANT",
                        authority=authority,
                        receipt_id=receipt_id,
                        before_user_version=user["aggregate_version"],
                        after_user_version=after_version,
                        result="CREATED" if changed else "REUSED",
                        now=prepared.now,
                    ),
                    "grant.audit",
                )
                if event is not None:
                    self._validate_event(event)
                    self._put(
                        uow,
                        "outbox_events",
                        event["event_id"],
                        event,
                        "grant.outbox.consent_granted",
                    )
                completed = _complete_receipt(
                    pending,
                    profile=prepared.profile,
                    response_body=response,
                    response_entity_tag=response_etag,
                    current_user_entity_tag=current_user_etag,
                    now=prepared.now,
                )
                self._put(
                    uow,
                    "command_receipts",
                    receipt_id,
                    completed,
                    "grant.receipt_completed",
                )
                self._commit(uow)
        except IamError:
            raise
        except PolicyConsentStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        self._record_telemetry(
            operation_id=prepared.profile.operation_id,
            outcome_code="SUCCEEDED",
            replayed=False,
            changed=changed,
            trace_id=actor.trace_id,
        )
        return PolicyConsentCommandResult(
            operation_id=prepared.profile.operation_id,
            replayed=False,
            http_status=prepared.profile.http_status,
            json_body=response,
            response_entity_tag=response_etag,
            current_user_entity_tag=current_user_etag,
        )

    def _recipient_binding(self, offer: ConsentOffer) -> str:
        return self._keyed_digest(
            self._keyring.payload_hash_key_id,
            _RECIPIENT_BINDING_DOMAIN + offer.recipient_reference.encode("utf-8"),
        )


def _is_utc(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _required_utc(value: object, code: str) -> datetime:
    if not _is_utc(value):
        raise IamError(code)
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _required_utc(value, "SERVICE_UNAVAILABLE").isoformat().replace(
        "+00:00", "Z"
    )


def _positive_version(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise IamError(code)
    return value


def _entity_tag(version: object) -> str:
    return f'"v{_positive_version(version, "SERVICE_UNAVAILABLE")}"'


def _canonical_bytes(value: object) -> bytes:
    def normalize(item: object) -> object:
        if isinstance(item, Mapping):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, datetime):
            return _timestamp(item)
        if isinstance(item, float):
            raise IamError("INVALID_REQUEST")
        return item

    try:
        return json.dumps(
            normalize(value),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except IamError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError) as error:
        raise IamError("INVALID_REQUEST") from error


def _closed_key_ids(values: object, active: object) -> Tuple[str, ...]:
    if not isinstance(active, str) or not active:
        raise IamError("SERVICE_UNAVAILABLE")
    if not isinstance(values, (list, tuple)):
        raise IamError("SERVICE_UNAVAILABLE")
    normalized: list[str] = []
    for value in (*values, active):
        if not isinstance(value, str) or not value:
            raise IamError("SERVICE_UNAVAILABLE")
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _reference_body(reference: PolicyRequirementReference) -> dict[str, Any]:
    if not isinstance(reference, PolicyRequirementReference):
        raise IamError("INVALID_REQUEST")
    try:
        scope_type = PolicyRequirementScopeType(reference.scope_type)
    except (TypeError, ValueError) as error:
        raise IamError("INVALID_REQUEST") from error
    if _SHA256.fullmatch(reference.selector_digest) is None:
        raise IamError("INVALID_REQUEST")
    if scope_type is PolicyRequirementScopeType.USER_ROLE:
        if reference.scope_id is not None:
            raise IamError("INVALID_REQUEST")
    elif not isinstance(reference.scope_id, str) or not reference.scope_id:
        raise IamError("INVALID_REQUEST")
    return {
        "selector_digest": reference.selector_digest,
        "scope_type": scope_type.value,
        "scope_id": reference.scope_id,
    }


def _command_profile(command: object, actor_user_id: str) -> _CommandProfile:
    if not isinstance(actor_user_id, str) or not actor_user_id:
        raise IamError("AUTHENTICATION_REQUIRED")
    raw_key = getattr(command, "idempotency_key", None)
    expected_version = getattr(command, "expected_user_version", None)
    if (
        not isinstance(raw_key, str)
        or not raw_key
        or not isinstance(expected_version, int)
        or isinstance(expected_version, bool)
        or expected_version < 1
    ):
        raise IamError("INVALID_REQUEST")
    if isinstance(command, AcceptCurrentPoliciesCommand):
        reference = _reference_body(command.policy_requirement)
        if not isinstance(command.policy_bundle_id, str) or not command.policy_bundle_id:
            raise IamError("INVALID_REQUEST")
        if not isinstance(command.policy_acceptances, tuple):
            raise IamError("INVALID_REQUEST")
        acceptances = []
        for item in command.policy_acceptances:
            if not isinstance(item, PolicyAcceptance):
                raise IamError("INVALID_REQUEST")
            acceptances.append(
                {
                    "document_id": item.document_id,
                    "content_sha256": item.content_sha256,
                    "affirmed": item.affirmed,
                }
            )
        body = {
            "policy_requirement": reference,
            "policy_bundle_id": command.policy_bundle_id,
            "policy_acceptances": sorted(
                acceptances,
                key=lambda item: (item["document_id"], item["content_sha256"]),
            ),
        }
        command_name = "AcceptCurrentPolicies"
        operation_id = "acceptCurrentPolicies"
        path = "/v1/me/policy-acceptances"
        status = 200
        schema = "PolicyRequirementStatusDto"
    elif isinstance(command, GrantConsentCommand):
        reference = _reference_body(command.policy_requirement)
        choice = command.consent_choice
        if (
            not isinstance(command.policy_bundle_id, str)
            or not command.policy_bundle_id
            or not isinstance(choice, ConsentOfferChoice)
        ):
            raise IamError("INVALID_REQUEST")
        body = {
            "policy_requirement": reference,
            "policy_bundle_id": command.policy_bundle_id,
            "consent_offer_id": choice.consent_offer_id,
            "document_id": choice.document_id,
            "content_sha256": choice.content_sha256,
            "affirmed": choice.affirmed,
        }
        command_name = "GrantConsent"
        operation_id = "grantConsent"
        path = "/v1/me/consents"
        status = 201
        schema = "ConsentGrantDto"
    else:
        raise IamError("INVALID_REQUEST")
    projection = {
        "body": body,
        "canonicalization_version": _CANONICALIZATION_VERSION,
        "command_name": command_name,
        "command_version": 1,
        "http_method": "POST",
        "if_match_version": expected_version,
        "path": path,
        "target_id": actor_user_id,
        "target_kind": "User",
    }
    return _CommandProfile(
        command_name=command_name,
        operation_id=operation_id,
        path=path,
        http_status=status,
        response_schema=schema,
        request_body=body,
        payload_projection=projection,
    )


def _find_receipt(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor_id: str,
    command_name: str,
    identity_digests: Mapping[str, str],
) -> Optional[Mapping[str, Any]]:
    known_digests = set(identity_digests.values())
    matches = [
        receipt
        for receipt in tables.get("command_receipts", {}).values()
        if isinstance(receipt, Mapping)
        and receipt.get("principal_kind") == "USER"
        and receipt.get("principal_id") == actor_id
        and receipt.get("command_name") == command_name
        and receipt.get("command_version") == 1
        and receipt.get("idempotency_key_digest") in known_digests
    ]
    if len(matches) > 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return matches[0] if matches else None


def _session_deadlines_open(session: Mapping[str, Any], now: datetime) -> bool:
    idle = _required_utc(session.get("idle_expires_at"), "SERVICE_UNAVAILABLE")
    absolute = _required_utc(
        session.get("absolute_expires_at"), "SERVICE_UNAVAILABLE"
    )
    return now < idle and now < absolute


def _require_current_session(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor: PolicyConsentActor,
    now: datetime,
) -> Mapping[str, Any]:
    if not isinstance(actor, PolicyConsentActor):
        raise IamError("AUTHENTICATION_REQUIRED")
    session = tables.get("sessions", {}).get(actor.current_session_id)
    if (
        not isinstance(session, Mapping)
        or session.get("session_id") != actor.current_session_id
        or session.get("user_id") != actor.actor_user_id
        or session.get("status") != "ACTIVE"
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    family = tables.get("session_families", {}).get(session.get("session_family_id"))
    user = tables.get("users", {}).get(actor.actor_user_id)
    if (
        not isinstance(family, Mapping)
        or family.get("session_family_id") != session.get("session_family_id")
        or family.get("user_id") != actor.actor_user_id
        or family.get("status") != "ACTIVE"
        or family.get("current_generation") != session.get("generation")
        or not isinstance(user, Mapping)
        or user.get("user_id") != actor.actor_user_id
        or user.get("status") != "ACTIVE"
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    if not _session_deadlines_open(session, now):
        raise IamError("SESSION_EXPIRED")
    auth_transaction = tables.get("auth_transactions", {}).get(
        session.get("auth_transaction_id")
    )
    if (
        not isinstance(auth_transaction, Mapping)
        or auth_transaction.get("auth_transaction_id")
        != session.get("auth_transaction_id")
        or auth_transaction.get("status") != "SUCCEEDED"
        or auth_transaction.get("resolved_user_id") != actor.actor_user_id
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    auth_time = _required_utc(session.get("auth_time"), "SERVICE_UNAVAILABLE")
    amr_codes = session.get("amr_codes")
    if (
        auth_time > now
        or not isinstance(session.get("acr_code"), str)
        or not session.get("acr_code")
        or not isinstance(amr_codes, (tuple, list))
        or not amr_codes
        or any(not isinstance(item, str) or not item for item in amr_codes)
        or len(amr_codes) != len(set(amr_codes))
        or not isinstance(session.get("handle_digest_key_id"), str)
        or not isinstance(session.get("csrf_key_id"), str)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    _positive_version(user.get("aggregate_version"), "SERVICE_UNAVAILABLE")
    return session


def _require_expected_user(
    tables: Mapping[str, Mapping[Any, Any]],
    actor_user_id: str,
    expected_version: int,
) -> Mapping[str, Any]:
    user = tables.get("users", {}).get(actor_user_id)
    if not isinstance(user, Mapping) or user.get("status") != "ACTIVE":
        raise IamError("AUTHENTICATION_REQUIRED")
    version = _positive_version(user.get("aggregate_version"), "SERVICE_UNAVAILABLE")
    if version != expected_version:
        raise IamError("PRECONDITION_FAILED")
    return user


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
    snapshot: Mapping[str, Mapping[Any, Any]],
    actor: PolicyConsentActor,
) -> None:
    session = snapshot.get("sessions", {}).get(actor.current_session_id)
    if not isinstance(session, Mapping):
        raise IamError("AUTHENTICATION_REQUIRED")
    family_id = session.get("session_family_id")
    if not isinstance(family_id, str) or not family_id:
        raise IamError("AUTHENTICATION_REQUIRED")
    uow.lock("session_families", (family_id,))
    uow.lock("sessions", (actor.current_session_id,))
    uow.lock("users", (actor.actor_user_id,))


def _selector_digest(selector: Mapping[str, Any]) -> str:
    if selector.get("canonicalization_version") != "policy-selector-json-v1":
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    values = {}
    for name in (
        "access_purpose",
        "scope_type",
        "target_role",
        "jurisdiction",
        "locale",
    ):
        value = selector.get(name)
        if not isinstance(value, str) or not value:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        values[name] = (
            unicodedata.normalize("NFC", value)
            if name in {"jurisdiction", "locale"}
            else value
        )
    canonical = json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _resolve_authority(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor: PolicyConsentActor,
    reference: PolicyRequirementReference,
    uow: Any,
) -> _Authority:
    reference_body = _reference_body(reference)
    selector_digest = reference_body["selector_digest"]
    if reference.scope_type is PolicyRequirementScopeType.USER_ROLE:
        candidates = [
            item
            for item in tables.get("user_role_grants", {}).values()
            if isinstance(item, Mapping)
            and item.get("user_id") == actor.actor_user_id
            and item.get("policy_selector_digest") == selector_digest
            and item.get("revoked_at") is None
        ]
        if not candidates:
            raise IamError("RESOURCE_NOT_FOUND")
        if len(candidates) != 1:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        grant = candidates[0]
        grant_id = grant.get("role_grant_id")
        if not isinstance(grant_id, str) or not grant_id:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        uow.lock("user_role_grants", (grant_id,))
        role = grant.get("role_code")
        if role != "CREATOR":
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        organization_id = None
        membership = None
        expected_target_scope = "USER"
    else:
        organization_id = reference.scope_id
        organization = tables.get("organizations", {}).get(organization_id)
        if (
            not isinstance(organization, Mapping)
            or organization.get("organization_id") != organization_id
            or organization.get("status") != "ACTIVE"
        ):
            raise IamError("RESOURCE_NOT_FOUND")
        uow.lock("organizations", (organization_id,))
        memberships = [
            item
            for item in tables.get("memberships", {}).values()
            if isinstance(item, Mapping)
            and item.get("user_id") == actor.actor_user_id
            and item.get("organization_id") == organization_id
            and item.get("status") == "ACTIVE"
        ]
        if not memberships:
            raise IamError("RESOURCE_NOT_FOUND")
        if len(memberships) != 1:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        membership = memberships[0]
        membership_id = membership.get("membership_id")
        if not isinstance(membership_id, str) or not membership_id:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        uow.lock("memberships", (membership_id,))
        candidates = [
            item
            for item in tables.get("membership_role_grants", {}).values()
            if isinstance(item, Mapping)
            and item.get("membership_id") == membership_id
            and item.get("organization_id") == organization_id
            and item.get("user_id") == actor.actor_user_id
            and item.get("policy_selector_digest") == selector_digest
            and item.get("revoked_at") is None
        ]
        if not candidates:
            raise IamError("RESOURCE_NOT_FOUND")
        if len(candidates) != 1:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        grant = candidates[0]
        grant_id = grant.get("role_grant_id")
        if not isinstance(grant_id, str) or not grant_id:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        uow.lock("membership_role_grants", (grant_id,))
        role = grant.get("role_code")
        if role not in {"ORG_ADMIN", "DEMAND_OWNER"}:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        expected_target_scope = "ORGANIZATION"
    source_id = grant.get("source_invitation_id")
    if not isinstance(source_id, str) or not source_id:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    uow.lock("invitations", (source_id,))
    source = tables.get("invitations", {}).get(source_id)
    selector = tables.get("policy_selectors", {}).get(selector_digest)
    if not isinstance(selector, Mapping):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if (
        selector.get("selector_digest") != selector_digest
        or _selector_digest(selector) != selector_digest
        or selector.get("scope_type") != reference.scope_type.value
        or selector.get("target_role") != role
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    purpose = selector.get("access_purpose")
    if (
        not isinstance(source, Mapping)
        or source.get("invitation_id") != source_id
        or source.get("status") != "ACCEPTED"
        or source.get("accepted_by_user_id") != actor.actor_user_id
        or source.get("policy_selector_digest") != selector_digest
        or source.get("purpose") != purpose
        or source.get("target_scope") != expected_target_scope
        or source.get("target_role") != role
        or source.get("organization_id") != organization_id
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return _Authority(
        selector=selector,
        role_grant=grant,
        source_invitation=source,
        role=role,
        purpose=purpose,
        scope_type=reference.scope_type,
        scope_id=reference.scope_id,
        organization_id=organization_id,
        membership=membership,
    )


def _require_current_bundle(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    authority: _Authority,
    reference: PolicyRequirementReference,
    presented_bundle_id: str,
    now: datetime,
    uow: Any,
) -> PolicyBundle:
    selector_digest = reference.selector_digest
    uow.lock("policy_selectors", (selector_digest,))
    selector = tables.get("policy_selectors", {}).get(selector_digest)
    if (
        not isinstance(selector, Mapping)
        or selector.get("selector_digest") != selector_digest
        or _selector_digest(selector) != selector_digest
        or selector.get("scope_type") != authority.scope_type.value
        or selector.get("target_role") != authority.role
        or selector.get("access_purpose") != authority.purpose
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    pointer = selector.get("current_bundle_id")
    if not isinstance(pointer, str) or not pointer:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    uow.lock("policy_bundles", (pointer,))
    bundle = tables.get("policy_bundles", {}).get(pointer)
    if not isinstance(bundle, PolicyBundle):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    _validate_current_bundle(bundle, selector_digest=selector_digest, now=now)
    effective = []
    for candidate in tables.get("policy_bundles", {}).values():
        if not isinstance(candidate, PolicyBundle):
            continue
        if (
            candidate.selector_digest == selector_digest
            and candidate.status is PolicyBundleStatus.ACTIVE
            and candidate.effective_at is not None
            and _is_utc(candidate.effective_at)
            and candidate.effective_at <= now
            and (
                candidate.effective_until is None
                or (_is_utc(candidate.effective_until) and now < candidate.effective_until)
            )
        ):
            effective.append(candidate.policy_bundle_id)
    if effective != [pointer]:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if presented_bundle_id != pointer:
        raise IamError("POLICY_BUNDLE_CHANGED")
    uow.lock(
        "policy_documents",
        tuple(sorted(document.document_id for document in bundle.documents)),
    )
    if bundle.consent_offers:
        uow.lock(
            "consent_offers",
            tuple(sorted(offer.consent_offer_id for offer in bundle.consent_offers)),
        )
    return bundle


def _validate_current_bundle(
    bundle: PolicyBundle,
    *,
    selector_digest: str,
    now: datetime,
) -> None:
    if (
        not isinstance(bundle.policy_bundle_id, str)
        or not bundle.policy_bundle_id
        or bundle.selector_digest != selector_digest
        or bundle.status is not PolicyBundleStatus.ACTIVE
        or bundle.superseded_by_bundle_id is not None
        or _SHA256.fullmatch(str(bundle.release_manifest_sha256)) is None
        or not isinstance(bundle.release_signature_algorithm, str)
        or not bundle.release_signature_algorithm
        or not isinstance(bundle.release_signature_key_id, str)
        or not bundle.release_signature_key_id
        or not isinstance(bundle.release_signature, str)
        or not bundle.release_signature
        or not isinstance(bundle.publication_command_id, str)
        or not bundle.publication_command_id
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    effective_at = _required_utc(
        bundle.effective_at,
        "POLICY_CONFIGURATION_UNAVAILABLE",
    )
    effective_until = (
        None
        if bundle.effective_until is None
        else _required_utc(
            bundle.effective_until,
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
    )
    if effective_at > now or (
        effective_until is not None and now >= effective_until
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if not bundle.documents:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    document_ids = [document.document_id for document in bundle.documents]
    if (
        len(document_ids) != len(set(document_ids))
        or len(bundle.required_document_ids) != len(set(bundle.required_document_ids))
        or not set(bundle.required_document_ids).issubset(document_ids)
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    documents = {document.document_id: document for document in bundle.documents}
    for document in bundle.documents:
        _validate_document(document, now=now)
    if any(
        documents[document_id].legal_effect is PolicyLegalEffect.CONSENT_TEXT
        for document_id in bundle.required_document_ids
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    offer_ids = [offer.consent_offer_id for offer in bundle.consent_offers]
    if len(offer_ids) != len(set(offer_ids)):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    for offer in bundle.consent_offers:
        _validate_offer(
            offer,
            bundle=bundle,
            documents=documents,
        )


def _validate_document(document: object, *, now: datetime) -> None:
    if not isinstance(document, PolicyDocument):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if (
        not isinstance(document.document_id, str)
        or not document.document_id
        or _SHA256.fullmatch(document.content_sha256) is None
        or not isinstance(document.legal_effect, PolicyLegalEffect)
        or document.status is not PolicyDocumentStatus.ACTIVE
        or document.superseded_by_document_id is not None
        or not isinstance(document.canonical_body, str)
        or hashlib.sha256(document.canonical_body.encode("utf-8")).hexdigest()
        != document.content_sha256
        or not isinstance(document.publication_command_id, str)
        or not document.publication_command_id
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    effective_at = _required_utc(
        document.effective_at,
        "POLICY_CONFIGURATION_UNAVAILABLE",
    )
    if effective_at > now:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    for value in (
        document.kind,
        document.semantic_version,
        document.locale,
        document.jurisdiction,
    ):
        if not isinstance(value, str) or not value:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")


def _validate_offer(
    offer: object,
    *,
    bundle: PolicyBundle,
    documents: Mapping[str, PolicyDocument],
) -> None:
    if not isinstance(offer, ConsentOffer):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    supporting = documents.get(offer.supporting_document_id)
    if (
        offer.canonicalization_version != "consent-offer-json-v1"
        or offer.policy_bundle_id != bundle.policy_bundle_id
        or offer.purpose is not ConsentPurpose.PILOT_RESEARCH
        or offer.scope_type is not ConsentScopeType.PLATFORM_PARTICIPATION
        or offer.scope_derivation
        is not ConsentScopeDerivation.PLATFORM_PARTICIPATION_NULL_SCOPE
        or offer.data_categories != _SUPPORTED_CATEGORIES
        or offer.expiry_rule
        is not ConsentExpiryRule.EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER
        or offer.expiry_days != 365
        or offer.optional is not True
        or not isinstance(offer.recipient_reference, str)
        or not offer.recipient_reference
        or offer.recipient_reference
        != unicodedata.normalize("NFC", offer.recipient_reference)
        or not isinstance(offer.recipient_label, str)
        or not offer.recipient_label
        or len(offer.recipient_label) > 160
        or supporting is None
        or supporting.legal_effect is not PolicyLegalEffect.CONSENT_TEXT
        or supporting.content_sha256 != offer.supporting_document_sha256
        or _SHA256.fullmatch(str(offer.canonical_offer_sha256)) is None
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    _required_utc(offer.not_after, "POLICY_CONFIGURATION_UNAVAILABLE")
    try:
        digest = hashlib.sha256(canonical_consent_offer_bytes(offer)).hexdigest()
    except (AttributeError, TypeError, ValueError, IamError) as error:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error
    if not hmac.compare_digest(digest, offer.canonical_offer_sha256):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")


def _evaluate_bundle(
    bundle: PolicyBundle,
    *,
    now: datetime,
    presented_bundle_id: str,
    policy_acceptances: Tuple[PolicyAcceptance, ...],
    consent_choices: Tuple[ConsentOfferChoice, ...],
) -> Any:
    try:
        return bundle.evaluate(
            now=now,
            presented_bundle_id=presented_bundle_id,
            policy_acceptances=policy_acceptances,
            consent_choices=consent_choices,
        )
    except IamError as error:
        if error.code in {
            "POLICY_DOCUMENT_MISMATCH",
            "CONSENT_OFFER_MISMATCH",
            "CONSENT_OFFER_EXPIRED",
        }:
            raise IamError("INVALID_REQUEST") from error
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error


def _acceptance_field(
    row: Mapping[str, Any], primary: str, alternate: str
) -> object:
    primary_value = row.get(primary)
    alternate_value = row.get(alternate)
    if (
        primary_value is not None
        and alternate_value is not None
        and primary_value != alternate_value
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return primary_value if primary_value is not None else alternate_value


def _validate_acceptance_evidence(
    row: Mapping[str, Any],
    *,
    actor_user_id: str,
    document: PolicyDocument,
    tables: Mapping[str, Mapping[Any, Any]],
) -> None:
    document_id = _acceptance_field(row, "document_id", "policy_document_id")
    content_sha = _acceptance_field(
        row, "content_sha256", "policy_document_sha256"
    )
    source_bundle_id = _acceptance_field(row, "bundle_id", "policy_bundle_id")
    if (
        row.get("user_id") != actor_user_id
        or document_id != document.document_id
        or content_sha != document.content_sha256
        or not isinstance(source_bundle_id, str)
        or not source_bundle_id
        or row.get("aggregate_version") != 1
        or row.get("source_action")
        not in {"POLICY_ACCEPT", "ACCESS_INVITATION_ACCEPT"}
        or not isinstance(row.get("session_id"), str)
        or not isinstance(row.get("auth_transaction_id"), str)
        or not isinstance(row.get("acr_code"), str)
        or not isinstance(row.get("command_id"), str)
        or not isinstance(row.get("correlation_id"), str)
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    accepted_at = _required_utc(
        row.get("accepted_at"), "POLICY_CONFIGURATION_UNAVAILABLE"
    )
    auth_time = _required_utc(
        row.get("auth_time"), "POLICY_CONFIGURATION_UNAVAILABLE"
    )
    amr_codes = row.get("amr_codes")
    if (
        auth_time > accepted_at
        or not isinstance(amr_codes, (tuple, list))
        or not amr_codes
        or any(not isinstance(item, str) or not item for item in amr_codes)
        or len(amr_codes) != len(set(amr_codes))
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    legal_effect = row.get("legal_effect")
    if legal_effect is not None and legal_effect != document.legal_effect.value:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    source_bundle = tables.get("policy_bundles", {}).get(source_bundle_id)
    if not isinstance(source_bundle, PolicyBundle):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    source_documents = [
        item
        for item in source_bundle.documents
        if item.document_id == document.document_id
    ]
    if (
        len(source_documents) != 1
        or source_documents[0].content_sha256 != document.content_sha256
        or source_documents[0].legal_effect is not document.legal_effect
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")


def _required_acceptance_evidence(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor_user_id: str,
    bundle: PolicyBundle,
    requested: Optional[Tuple[PolicyAcceptance, ...]],
) -> tuple[Tuple[PolicyAcceptance, ...], Tuple[PolicyAcceptance, ...]]:
    documents = {item.document_id: item for item in bundle.documents}
    requested_by_id = (
        {}
        if requested is None
        else {item.document_id: item for item in requested}
    )
    existing_values: list[PolicyAcceptance] = []
    missing_values: list[PolicyAcceptance] = []
    for document_id in bundle.required_document_ids:
        document = documents[document_id]
        candidates = [
            row
            for row in tables.get("policy_acceptances", {}).values()
            if isinstance(row, Mapping)
            and row.get("user_id") == actor_user_id
            and _acceptance_field(row, "document_id", "policy_document_id")
            == document_id
        ]
        exact = [
            row
            for row in candidates
            if _acceptance_field(row, "content_sha256", "policy_document_sha256")
            == document.content_sha256
        ]
        if candidates and len(exact) != len(candidates):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        if len(exact) > 1:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        if exact:
            _validate_acceptance_evidence(
                exact[0],
                actor_user_id=actor_user_id,
                document=document,
                tables=tables,
            )
            existing_values.append(
                PolicyAcceptance(
                    document_id=document_id,
                    content_sha256=document.content_sha256,
                    affirmed=True,
                )
            )
        else:
            if requested is None:
                missing_values.append(
                    PolicyAcceptance(
                        document_id=document_id,
                        content_sha256=document.content_sha256,
                        affirmed=True,
                    )
                )
            else:
                missing_values.append(requested_by_id[document_id])
    return tuple(existing_values), tuple(missing_values)


def _new_acceptance_fact(
    *,
    acceptance_id: str,
    actor: PolicyConsentActor,
    session: Mapping[str, Any],
    receipt_id: str,
    bundle: PolicyBundle,
    document: PolicyDocument,
    now: datetime,
) -> dict[str, Any]:
    return {
        "policy_acceptance_id": acceptance_id,
        "user_id": actor.actor_user_id,
        "document_id": document.document_id,
        "content_sha256": document.content_sha256,
        "bundle_id": bundle.policy_bundle_id,
        "accepted_at": now,
        "session_id": actor.current_session_id,
        "auth_transaction_id": session["auth_transaction_id"],
        "auth_time": session["auth_time"],
        "acr_code": session["acr_code"],
        "amr_codes": tuple(session["amr_codes"]),
        "source_action": "POLICY_ACCEPT",
        "command_id": receipt_id,
        "correlation_id": actor.correlation_id,
        "aggregate_version": 1,
        "created_at": now,
    }


def _pending_receipt(
    *, receipt_id: str, material: Mapping[str, Any], now: datetime
) -> dict[str, Any]:
    return {
        "command_receipt_id": receipt_id,
        **deepcopy(dict(material)),
        "status": "IN_PROGRESS",
        "created_at": now,
    }


def _complete_receipt(
    pending: Mapping[str, Any],
    *,
    profile: _CommandProfile,
    response_body: Mapping[str, Any],
    response_entity_tag: str,
    current_user_entity_tag: str,
    now: datetime,
) -> dict[str, Any]:
    return {
        **deepcopy(dict(pending)),
        "status": "COMPLETED",
        "response_schema": profile.response_schema,
        "response_schema_version": 1,
        "response_http_status": profile.http_status,
        "response_body": deepcopy(dict(response_body)),
        "response_entity_tag": response_entity_tag,
        "current_user_entity_tag": current_user_entity_tag,
        "completed_at": now,
    }


def _requirement_response(
    authority: _Authority, bundle: PolicyBundle
) -> dict[str, Any]:
    return {
        "selector_digest": bundle.selector_digest,
        "purpose": authority.purpose,
        "role": authority.role,
        "scope_type": authority.scope_type.value,
        "scope_id": authority.scope_id,
        "satisfied": True,
        "required_policy_bundle_id": bundle.policy_bundle_id,
        "missing_document_ids": [],
    }


def _require_response_binding(
    response: Mapping[str, Any],
    *,
    command: object,
    profile: _CommandProfile,
) -> None:
    if isinstance(command, AcceptCurrentPoliciesCommand):
        if (
            response.get("selector_digest")
            != command.policy_requirement.selector_digest
            or response.get("scope_type")
            != command.policy_requirement.scope_type.value
            or response.get("scope_id") != command.policy_requirement.scope_id
            or response.get("required_policy_bundle_id")
            != command.policy_bundle_id
            or response.get("satisfied") is not True
            or response.get("missing_document_ids") != []
        ):
            raise IamError("SERVICE_UNAVAILABLE")
    elif isinstance(command, GrantConsentCommand):
        choice = command.consent_choice
        if (
            response.get("consent_offer_id") != choice.consent_offer_id
            or response.get("document_id") != choice.document_id
            or response.get("content_sha256") != choice.content_sha256
            or response.get("purpose") != ConsentPurpose.PILOT_RESEARCH.value
            or response.get("scope_type")
            != ConsentScopeType.PLATFORM_PARTICIPATION.value
            or response.get("scope_id") is not None
        ):
            raise IamError("SERVICE_UNAVAILABLE")
    else:
        raise IamError("SERVICE_UNAVAILABLE")


def _audit_event(
    *,
    audit_id: str,
    actor: PolicyConsentActor,
    session: Mapping[str, Any],
    action: str,
    authority: _Authority,
    receipt_id: str,
    before_user_version: int,
    after_user_version: int,
    result: str,
    now: datetime,
) -> dict[str, Any]:
    return {
        "audit_event_id": audit_id,
        "actor_kind": "USER",
        "actor_id": actor.actor_user_id,
        "original_actor_id": actor.original_actor_id,
        "action": action,
        "target_type": "User",
        "target_id": actor.actor_user_id,
        "organization_id": authority.organization_id,
        "role": authority.role,
        "purpose": authority.purpose,
        "acr_code": session["acr_code"],
        "before_user_version": before_user_version,
        "after_user_version": after_user_version,
        "result": result,
        "command_id": receipt_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "occurred_at": now,
    }


def _event_envelope(
    *,
    event_id: str,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_version: int,
    actor: PolicyConsentActor,
    causation_id: str,
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
        "causation_id": causation_id,
        "trace_id": actor.trace_id,
        "organization_id": organization_id,
        "payload": deepcopy(dict(payload)),
    }


def _offer_for_authorization(bundle: PolicyBundle, authorization: Any) -> ConsentOffer:
    offers = [
        item
        for item in bundle.consent_offers
        if item.consent_offer_id == authorization.consent_offer_id
    ]
    if len(offers) != 1:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return offers[0]


def _consent_authority_lock_key(
    user_id: str, purpose: str, scope_type: str, scope_id: Optional[str]
) -> str:
    return f"{user_id}:{purpose}:{scope_type}:{scope_id or '<NULL>'}"


def _active_authority_grants(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor_user_id: str,
    purpose: str,
    scope_type: str,
    scope_id: Optional[str],
) -> list[Mapping[str, Any]]:
    rows = [
        item
        for item in tables.get("consent_grants", {}).values()
        if isinstance(item, Mapping)
        and item.get("user_id") == actor_user_id
        and item.get("purpose") == purpose
        and item.get("scope_type") == scope_type
        and item.get("scope_id") == scope_id
        and item.get("status") == "ACTIVE"
    ]
    for row in rows:
        if not isinstance(row.get("consent_grant_id"), str):
            raise IamError("SERVICE_UNAVAILABLE")
    return rows


def _grant_matches_authorization(
    row: Mapping[str, Any],
    *,
    authorization: Any,
    offer: ConsentOffer,
    recipient_binding: str,
) -> bool:
    granted_at = _required_utc(row.get("granted_at"), "SERVICE_UNAVAILABLE")
    expires_at = _required_utc(row.get("expires_at"), "SERVICE_UNAVAILABLE")
    expected_expiry = min(offer.not_after, granted_at + timedelta(days=365))
    raw_recipient = row.get("recipient_reference")
    digest_recipient = row.get("recipient_reference_digest")
    recipient_matches = (
        raw_recipient == offer.recipient_reference
        if raw_recipient is not None
        else digest_recipient == recipient_binding
    )
    document_id = row.get(
        "document_id", row.get("supporting_policy_document_id")
    )
    return (
        row.get("consent_offer_id") == authorization.consent_offer_id
        and row.get("consent_offer_version")
        == authorization.consent_offer_version
        and row.get("policy_bundle_id") == authorization.policy_bundle_id
        and row.get("purpose") == authorization.purpose.value
        and row.get("scope_type") == authorization.scope_type.value
        and row.get("scope_id") == authorization.scope_id
        and tuple(row.get("data_categories", ()))
        == tuple(item.value for item in authorization.data_categories)
        and recipient_matches
        and row.get("recipient_label") == offer.recipient_label
        and document_id == authorization.supporting_policy_document_id
        and row.get("content_sha256", row.get("supporting_document_sha256"))
        == authorization.supporting_document_sha256
        and expires_at == expected_expiry
    )


def _validate_grant_evidence(row: Mapping[str, Any]) -> None:
    if (
        row.get("status") != "ACTIVE"
        or _positive_version(row.get("aggregate_version"), "SERVICE_UNAVAILABLE")
        < 1
        or not isinstance(row.get("session_id"), str)
        or not isinstance(row.get("auth_transaction_id"), str)
        or not isinstance(row.get("acr_code"), str)
        or not isinstance(row.get("command_id"), str)
        or not isinstance(row.get("correlation_id"), str)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    auth_time = _required_utc(row.get("auth_time"), "SERVICE_UNAVAILABLE")
    granted_at = _required_utc(row.get("granted_at"), "SERVICE_UNAVAILABLE")
    if auth_time > granted_at:
        raise IamError("SERVICE_UNAVAILABLE")
    amr_codes = row.get("amr_codes")
    if (
        not isinstance(amr_codes, (tuple, list))
        or not amr_codes
        or len(amr_codes) != len(set(amr_codes))
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _new_grant_fact(
    *,
    grant_id: str,
    actor: PolicyConsentActor,
    session: Mapping[str, Any],
    receipt_id: str,
    authorization: Any,
    offer: ConsentOffer,
    recipient_binding: str,
    recipient_binding_key_id: str,
    now: datetime,
) -> dict[str, Any]:
    return {
        "consent_grant_id": grant_id,
        "user_id": actor.actor_user_id,
        "consent_offer_id": authorization.consent_offer_id,
        "consent_offer_version": authorization.consent_offer_version,
        "policy_bundle_id": authorization.policy_bundle_id,
        "purpose": authorization.purpose.value,
        "scope_type": authorization.scope_type.value,
        "scope_id": authorization.scope_id,
        "data_categories": tuple(
            item.value for item in authorization.data_categories
        ),
        "recipient_reference_digest": recipient_binding,
        "recipient_reference_digest_key_id": recipient_binding_key_id,
        "recipient_label": offer.recipient_label,
        "document_id": authorization.supporting_policy_document_id,
        "content_sha256": authorization.supporting_document_sha256,
        "granted_at": now,
        "expires_at": authorization.expires_at,
        "session_id": actor.current_session_id,
        "auth_transaction_id": session["auth_transaction_id"],
        "auth_time": session["auth_time"],
        "acr_code": session["acr_code"],
        "amr_codes": tuple(session["amr_codes"]),
        "command_id": receipt_id,
        "correlation_id": actor.correlation_id,
        "status": "ACTIVE",
        "withdrawn_at": None,
        "aggregate_version": 1,
        "created_at": now,
        "updated_at": now,
    }


def _grant_response(row: Mapping[str, Any]) -> dict[str, Any]:
    version = _positive_version(row.get("aggregate_version"), "SERVICE_UNAVAILABLE")
    document_id = row.get(
        "document_id", row.get("supporting_policy_document_id")
    )
    content_sha = row.get(
        "content_sha256", row.get("supporting_document_sha256")
    )
    return {
        "consent_grant_id": row["consent_grant_id"],
        "consent_offer_id": row["consent_offer_id"],
        "purpose": row["purpose"],
        "scope_type": row["scope_type"],
        "scope_id": row["scope_id"],
        "data_categories": list(row["data_categories"]),
        "recipient_label": row["recipient_label"],
        "document_id": document_id,
        "content_sha256": content_sha,
        "granted_at": _timestamp(row["granted_at"]),
        "expires_at": _timestamp(row["expires_at"]),
        "status": row["status"],
        "aggregate_version": version,
        "entity_tag": _entity_tag(version),
    }


__all__ = [
    "AcceptCurrentPoliciesCommand",
    "AcceptCurrentPoliciesHandler",
    "GrantConsentCommand",
    "GrantConsentHandler",
    "POLICY_CONSENT_COMMAND_BEHAVIOR_NOT_AVAILABLE",
    "PolicyConsentActor",
    "PolicyConsentCommandResult",
    "PolicyRequirementReference",
    "PolicyRequirementScopeType",
]
