"""Signed IAM policy publication and exact-selector activation."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional, Tuple
import unicodedata

from ..domain.errors import IamError
from ..domain.invitations import InvitationPurpose, TargetRole
from ..domain.policies import (
    ConsentOffer,
    ConsentPurpose,
    ConsentScopeType,
    DataCategory,
    PolicyBundle,
    PolicyBundleStatus,
    PolicyDocument,
    PolicyDocumentStatus,
    PolicyLegalEffect,
    canonical_consent_offer_bytes,
)


class PolicySelectorScopeType(str, Enum):
    USER_ROLE = "USER_ROLE"
    ORGANIZATION_ROLE = "ORGANIZATION_ROLE"


class PolicyDocumentKind(str, Enum):
    TERMS = "TERMS"
    PRIVACY_NOTICE = "PRIVACY_NOTICE"
    COMMUNITY_TRANSACTION_COVENANT = "COMMUNITY_TRANSACTION_COVENANT"
    CONSENT_TEXT = "CONSENT_TEXT"


class PolicyPublisherPrincipalKind(str, Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"


class PolicyPublisherOperation(str, Enum):
    POLICY_PUBLISH = "POLICY_PUBLISH"


class PolicyReleaseKeyUsage(str, Enum):
    IAM_POLICY_RELEASE = "IAM_POLICY_RELEASE"


class PolicyReleaseTrustStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class PolicyLegalApprovalDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


_PUBLISH_RECEIPT_CANONICALIZATION = "restricted-canonical-json-v1"
_PUBLISH_RECEIPT_PATH = "/internal/iam/policy-bundles/publish"
_PUBLISH_RECEIPT_RETENTION = timedelta(days=30)
_PUBLISH_RECEIPT_FIELDS = {
    "command_id",
    "principal_kind",
    "principal_id",
    "command_name",
    "command_version",
    "idempotency_key_digest",
    "idempotency_key_digest_key_id",
    "payload_hash",
    "payload_hash_key_id",
    "canonicalization_version",
    "target_kind",
    "target_id",
    "http_method",
    "canonical_path",
    "if_match_version",
    "status",
    "response_schema_version",
    "response_body",
    "reconstruction_metadata",
    "created_at",
    "retain_until",
    "completed_at",
}


@dataclass(frozen=True)
class PolicySelectorFacts:
    canonicalization_version: str
    access_purpose: InvitationPurpose
    scope_type: PolicySelectorScopeType
    target_role: TargetRole
    jurisdiction: str
    locale: str


@dataclass(frozen=True)
class PolicyDocumentRelease:
    document_id: str
    kind: PolicyDocumentKind
    semantic_version: str
    locale: str
    jurisdiction: str
    canonical_body: str = field(repr=False)
    content_sha256: str
    legal_effect: PolicyLegalEffect


@dataclass(frozen=True)
class PolicyReleaseManifest:
    schema_version: str
    policy_bundle_id: str
    selector_digest: str
    selector: PolicySelectorFacts
    supersedes_policy_bundle_id: Optional[str]
    effective_at: datetime
    effective_until: Optional[datetime]
    documents: Tuple[PolicyDocumentRelease, ...]
    required_document_ids: Tuple[str, ...]
    consent_offers: Tuple[ConsentOffer, ...]


@dataclass(frozen=True)
class SignedPolicyRelease:
    manifest: PolicyReleaseManifest
    manifest_sha256: str
    signature_algorithm: str
    signature_key_id: str
    signature: str = field(repr=False)


@dataclass(frozen=True)
class PublishPolicyBundleCommand:
    command_id: str
    release: SignedPolicyRelease


@dataclass(frozen=True)
class PolicyPublisherContext:
    system_id: str
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str
    principal_kind: PolicyPublisherPrincipalKind = (
        PolicyPublisherPrincipalKind.SYSTEM
    )
    workload_credential_id: Optional[str] = None


@dataclass(frozen=True)
class PolicyPublisherAuthorizationAttestation:
    credential_id: str
    principal_kind: PolicyPublisherPrincipalKind
    system_id: str
    operation: PolicyPublisherOperation
    command_id: str
    selector_digest: str
    policy_bundle_id: str
    credential_status: str
    authenticated_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class PolicyReleaseVerificationAttestation:
    canonical_manifest: bytes = field(repr=False)
    manifest_sha256: str
    signature_algorithm: str
    signature_key_id: str
    key_usage: PolicyReleaseKeyUsage
    allowed_manifest_schema_versions: Tuple[str, ...]
    allowed_access_purposes: Tuple[InvitationPurpose, ...]
    allowed_scope_types: Tuple[PolicySelectorScopeType, ...]
    allowed_target_roles: Tuple[TargetRole, ...]
    allowed_jurisdictions: Tuple[str, ...]
    trust_status: PolicyReleaseTrustStatus
    trust_valid_from: datetime
    trust_valid_until: datetime
    verified_at: datetime


@dataclass(frozen=True)
class PolicyLegalApprovalAttestation:
    credential_id: str
    manifest_sha256: str
    signature_key_id: str
    decision: PolicyLegalApprovalDecision
    approver_id: str
    valid_from: datetime
    valid_until: datetime
    revoked_at: Optional[datetime]


@dataclass(frozen=True)
class PublishPolicyBundleResult:
    replayed: bool
    policy_bundle_id: str
    selector_digest: str
    aggregate_version: int


class ConcurrentPolicyPublishError(Exception):
    """The adapter rejected a stale selector/current-bundle write."""


class PolicyPublisherAuthorizationUnavailableError(IamError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class PolicyReleaseVerificationUnavailableError(IamError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class PolicyLegalApprovalUnavailableError(IamError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class PolicyReceiptKeyUnavailableError(IamError):
    def __init__(self) -> None:
        super().__init__("SERVICE_UNAVAILABLE")


class PublishPolicyBundleHandler:
    """Verify a signed release, then atomically advance one selector."""

    def __init__(
        self,
        *,
        uow_factory,
        release_verifier,
        clock,
        workload_authorizer=None,
        legal_approval_port=None,
        receipt_codec=None,
    ) -> None:
        self._uow_factory = uow_factory
        self._release_verifier = release_verifier
        self._clock = clock
        self._workload_authorizer = workload_authorizer
        self._legal_approval_port = legal_approval_port
        self._receipt_codec = receipt_codec

    def handle(
        self,
        *,
        actor: PolicyPublisherContext,
        command: PublishPolicyBundleCommand,
    ) -> PublishPolicyBundleResult:
        now = self._clock.now()
        _require_aware_utc(now)
        manifest = command.release.manifest
        if self._workload_authorizer is not None:
            _require_publisher_authorization(
                self._workload_authorizer,
                actor=actor,
                command=command,
                now=now,
            )

        snapshot = _snapshot(self._uow_factory)
        canonical_manifest: Optional[bytes] = None
        local_manifest_sha256: Optional[str] = None
        receipt_identity_digest: Optional[str] = None
        receipt_identity_key_id: Optional[str] = None
        receipt_payload_hash: Optional[str] = None
        receipt_payload_key_id: Optional[str] = None

        if self._receipt_codec is None:
            receipt_key = _receipt_key(actor=actor, command=command)
            receipt = _find_receipt(snapshot, receipt_key=receipt_key)
            if receipt is not None:
                return _replay_receipt(
                    receipt,
                    actor=actor,
                    command=command,
                )
        else:
            canonical_manifest, local_manifest_sha256 = (
                _canonical_manifest_and_digest(manifest)
            )
            identity_candidates = _receipt_identity_candidates(
                self._receipt_codec,
                command_id=command.command_id,
            )
            receipt = _find_keyed_receipt(
                snapshot,
                actor=actor,
                command=command,
                identity_candidates=identity_candidates,
            )
            if receipt is not None:
                receipt_payload_hash = _receipt_payload_hash(
                    self._receipt_codec,
                    command=command,
                    local_manifest_sha256=local_manifest_sha256,
                    key_id=receipt.get("payload_hash_key_id"),
                )
                return _replay_keyed_receipt(
                    receipt,
                    actor=actor,
                    command=command,
                    identity_candidates=identity_candidates,
                    payload_hash=receipt_payload_hash,
                )
            (
                receipt_identity_key_id,
                receipt_payload_key_id,
            ) = _active_receipt_key_ids(
                self._receipt_codec,
                identity_candidates=identity_candidates,
            )
            receipt_identity_digest = dict(identity_candidates)[
                receipt_identity_key_id
            ]
            receipt_payload_hash = _receipt_payload_hash(
                self._receipt_codec,
                command=command,
                local_manifest_sha256=local_manifest_sha256,
                key_id=receipt_payload_key_id,
            )
            receipt_key = _keyed_receipt_key(
                actor=actor,
                identity_digest=receipt_identity_digest,
            )

        if canonical_manifest is None or local_manifest_sha256 is None:
            canonical_manifest, local_manifest_sha256 = (
                _canonical_manifest_and_digest(manifest)
            )
        published_documents, published_bundle = self._verify_and_materialize(
            command=command,
            now=now,
            canonical_manifest=canonical_manifest,
            local_manifest_sha256=local_manifest_sha256,
        )
        approval = None
        if self._legal_approval_port is not None:
            approval = _require_legal_approval(
                self._legal_approval_port,
                command=command,
                manifest_sha256=local_manifest_sha256,
                now=now,
            )

        try:
            with self._uow_factory.begin() as uow:
                locked_selector = uow.lock(
                    "policy_selectors",
                    manifest.selector_digest,
                )
                selector_version, predecessor = _publication_precondition(
                    tables=uow.tables,
                    locked_selector=locked_selector,
                    manifest=manifest,
                    now=now,
                )
                _require_unclaimed_artifacts(
                    tables=uow.tables,
                    manifest=manifest,
                )

                if locked_selector is None:
                    selector = _new_selector_row(
                        manifest=manifest,
                        now=now,
                    )
                else:
                    selector = dict(locked_selector)
                    selector.update(
                        {
                            "current_bundle_id": manifest.policy_bundle_id,
                            "aggregate_version": selector_version,
                            "updated_at": now,
                        }
                    )

                superseded = None
                if predecessor is not None:
                    superseded = replace(
                        predecessor,
                        status=PolicyBundleStatus.SUPERSEDED,
                        effective_until=manifest.effective_at,
                        superseded_by_bundle_id=manifest.policy_bundle_id,
                        aggregate_version=predecessor.aggregate_version + 1,
                        updated_at=now,
                    )

                if self._receipt_codec is None:
                    pending_receipt = {
                        "principal_kind": "SYSTEM",
                        "principal_id": actor.system_id,
                        "command_name": "PublishPolicyBundle",
                        "command_version": 1,
                        "command_id": command.command_id,
                        "payload_hash": command.release.manifest_sha256,
                        "status": "PENDING",
                        "target_kind": "PolicyBundle",
                        "target_id": manifest.policy_bundle_id,
                        "created_at": now,
                    }
                else:
                    pending_receipt = _new_keyed_pending_receipt(
                        actor=actor,
                        command=command,
                        identity_digest=receipt_identity_digest,
                        identity_key_id=receipt_identity_key_id,
                        payload_hash=receipt_payload_hash,
                        payload_key_id=receipt_payload_key_id,
                        now=now,
                    )
                uow.put(
                    "command_receipts",
                    receipt_key,
                    pending_receipt,
                    checkpoint="command_receipt.pending",
                )

                if superseded is not None:
                    uow.put(
                        "policy_bundles",
                        predecessor.policy_bundle_id,
                        superseded,
                        checkpoint="policy_bundle.supersede",
                    )

                for position, document in enumerate(published_documents):
                    uow.put(
                        "policy_documents",
                        document.document_id,
                        document,
                        checkpoint="policy_document.%d" % position,
                    )
                uow.put(
                    "policy_bundles",
                    published_bundle.policy_bundle_id,
                    published_bundle,
                    checkpoint="policy_bundle.publish",
                )
                uow.put(
                    "policy_selectors",
                    manifest.selector_digest,
                    selector,
                    checkpoint=(
                        "policy_selector.create"
                        if locked_selector is None
                        else "policy_selector.advance"
                    ),
                )

                uow.put(
                    "audit_events",
                    command.command_id,
                    _audit_event(
                        actor=actor,
                        command=command,
                        approval=approval,
                        now=now,
                    ),
                    checkpoint="audit_event.succeeded",
                )
                published_event_id = _event_id(
                    command.command_id,
                    "PolicyBundlePublished",
                )
                uow.put(
                    "outbox_events",
                    published_event_id,
                    _outbox_event(
                        event_id=published_event_id,
                        event_type="PolicyBundlePublished",
                        aggregate_id=manifest.policy_bundle_id,
                        aggregate_version=published_bundle.aggregate_version,
                        actor=actor,
                        now=now,
                        payload={
                            "policy_bundle_id": manifest.policy_bundle_id,
                            "status": PolicyBundleStatus.ACTIVE.value,
                            "effective_at": _timestamp(manifest.effective_at),
                            "superseded_policy_bundle_id": (
                                None
                                if predecessor is None
                                else predecessor.policy_bundle_id
                            ),
                            "policy_document_ids": [
                                document.document_id
                                for document in manifest.documents
                            ],
                            "consent_offer_ids": [
                                offer.consent_offer_id
                                for offer in manifest.consent_offers
                            ],
                        },
                    ),
                    checkpoint="outbox.PolicyBundlePublished",
                )
                if predecessor is not None:
                    superseded_event_id = _event_id(
                        command.command_id,
                        "PolicyBundleSuperseded",
                    )
                    uow.put(
                        "outbox_events",
                        superseded_event_id,
                        _outbox_event(
                            event_id=superseded_event_id,
                            event_type="PolicyBundleSuperseded",
                            aggregate_id=predecessor.policy_bundle_id,
                            aggregate_version=predecessor.aggregate_version + 1,
                            actor=actor,
                            now=now,
                            payload={
                                "policy_bundle_id": predecessor.policy_bundle_id,
                                "status": PolicyBundleStatus.SUPERSEDED.value,
                                "superseded_by_policy_bundle_id": (
                                    manifest.policy_bundle_id
                                ),
                            },
                        ),
                        checkpoint="outbox.PolicyBundleSuperseded",
                    )

                response_body = {
                    "policy_bundle_id": manifest.policy_bundle_id,
                    "selector_digest": manifest.selector_digest,
                    "aggregate_version": published_bundle.aggregate_version,
                }
                completed_receipt = dict(pending_receipt)
                completed_receipt.update(
                    {
                        "status": "COMPLETED",
                        "response_schema_version": 1,
                        "response_body": response_body,
                        "completed_at": now,
                    }
                )
                uow.put(
                    "command_receipts",
                    receipt_key,
                    completed_receipt,
                    checkpoint="command_receipt.complete",
                )
                uow.commit()
        except ConcurrentPolicyPublishError as error:
            raise IamError("PRECONDITION_FAILED") from error

        return PublishPolicyBundleResult(
            replayed=False,
            policy_bundle_id=manifest.policy_bundle_id,
            selector_digest=manifest.selector_digest,
            aggregate_version=published_bundle.aggregate_version,
        )

    def _verify_and_materialize(
        self,
        *,
        command: PublishPolicyBundleCommand,
        now: datetime,
        canonical_manifest: bytes,
        local_manifest_sha256: str,
    ) -> tuple[Tuple[PolicyDocument, ...], PolicyBundle]:
        release = command.release
        try:
            verification = self._release_verifier.verify(release)
        except PolicyReleaseVerificationUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        except IamError:
            raise
        except (AttributeError, TypeError, UnicodeError, ValueError) as error:
            raise IamError("POLICY_RELEASE_INVALID") from error
        try:
            _require_release_verification(
                verification,
                release=release,
                canonical_manifest=canonical_manifest,
                local_manifest_sha256=local_manifest_sha256,
                now=now,
            )
            _validate_manifest(release.manifest, now=now)
            documents = tuple(
                PolicyDocument(
                    document_id=document.document_id,
                    content_sha256=document.content_sha256,
                    legal_effect=document.legal_effect,
                    kind=document.kind.value,
                    semantic_version=document.semantic_version,
                    locale=document.locale,
                    jurisdiction=document.jurisdiction,
                    canonical_body=document.canonical_body,
                    status=PolicyDocumentStatus.ACTIVE,
                    effective_at=release.manifest.effective_at,
                    publication_command_id=command.command_id,
                    created_at=now,
                    updated_at=now,
                )
                for document in release.manifest.documents
            )
            bundle = PolicyBundle(
                policy_bundle_id=release.manifest.policy_bundle_id,
                selector_digest=release.manifest.selector_digest,
                status=PolicyBundleStatus.ACTIVE,
                effective_at=release.manifest.effective_at,
                effective_until=None,
                documents=documents,
                required_document_ids=release.manifest.required_document_ids,
                consent_offers=release.manifest.consent_offers,
                release_manifest_sha256=release.manifest_sha256,
                release_signature_algorithm=release.signature_algorithm,
                release_signature_key_id=release.signature_key_id,
                release_signature=release.signature,
                publication_command_id=command.command_id,
                aggregate_version=1,
                created_at=now,
                updated_at=now,
            )
        except IamError as error:
            if error.code == "POLICY_RELEASE_INVALID":
                raise
            raise IamError("POLICY_RELEASE_INVALID") from error
        except (AttributeError, TypeError, UnicodeError, ValueError) as error:
            raise IamError("POLICY_RELEASE_INVALID") from error
        return documents, bundle


def _snapshot(uow_factory) -> Mapping[str, Mapping[Any, Any]]:
    store = getattr(uow_factory, "store", None)
    snapshot = getattr(store, "snapshot", None)
    if not callable(snapshot):
        raise IamError("SERVICE_UNAVAILABLE")
    return snapshot()


def _require_publisher_authorization(
    authorizer,
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
    now: datetime,
) -> PolicyPublisherAuthorizationAttestation:
    manifest = command.release.manifest
    try:
        attestation = authorizer.authorize(
            actor=actor,
            operation=PolicyPublisherOperation.POLICY_PUBLISH,
            command_id=command.command_id,
            selector_digest=manifest.selector_digest,
            policy_bundle_id=manifest.policy_bundle_id,
            now=now,
        )
    except PolicyPublisherAuthorizationUnavailableError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    except IamError:
        raise
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise IamError("AUTHENTICATION_REQUIRED") from error
    if (
        not isinstance(attestation, PolicyPublisherAuthorizationAttestation)
        or actor.principal_kind != PolicyPublisherPrincipalKind.SYSTEM
        or not isinstance(actor.system_id, str)
        or not actor.system_id
        or not isinstance(actor.workload_credential_id, str)
        or not actor.workload_credential_id
        or attestation.credential_id != actor.workload_credential_id
        or attestation.principal_kind != PolicyPublisherPrincipalKind.SYSTEM
        or attestation.system_id != actor.system_id
        or attestation.operation != PolicyPublisherOperation.POLICY_PUBLISH
        or attestation.command_id != command.command_id
        or attestation.selector_digest != manifest.selector_digest
        or attestation.policy_bundle_id != manifest.policy_bundle_id
        or attestation.credential_status != "ACTIVE"
        or not _is_utc(attestation.authenticated_at)
        or not _is_utc(attestation.valid_until)
        or attestation.authenticated_at > now
        or now >= attestation.valid_until
        or attestation.authenticated_at >= attestation.valid_until
    ):
        raise IamError("AUTHENTICATION_REQUIRED")
    return attestation


def _canonical_manifest_and_digest(
    manifest: PolicyReleaseManifest,
) -> tuple[bytes, str]:
    try:
        canonical_manifest = _canonical_release_manifest_bytes(manifest)
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise IamError("POLICY_RELEASE_INVALID") from error
    return canonical_manifest, hashlib.sha256(canonical_manifest).hexdigest()


def _receipt_identity_candidates(
    receipt_codec,
    *,
    command_id: str,
) -> tuple[tuple[str, str], ...]:
    try:
        candidates = tuple(receipt_codec.identity_candidates(command_id))
    except PolicyReceiptKeyUnavailableError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    except IamError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if (
        not candidates
        or any(
            not isinstance(candidate, tuple)
            or len(candidate) != 2
            or not isinstance(candidate[0], str)
            or not candidate[0]
            or not _is_sha256(candidate[1])
            or candidate[1] == command_id
            for candidate in candidates
        )
        or len({candidate[0] for candidate in candidates}) != len(candidates)
        or len({candidate[1] for candidate in candidates}) != len(candidates)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return candidates


def _active_receipt_key_ids(
    receipt_codec,
    *,
    identity_candidates: tuple[tuple[str, str], ...],
) -> tuple[str, str]:
    identity_key_id = getattr(receipt_codec, "active_identity_key_id", None)
    payload_key_id = getattr(receipt_codec, "active_payload_key_id", None)
    retained_payload_key_ids = getattr(
        receipt_codec,
        "retained_payload_key_ids",
        None,
    )
    if (
        not isinstance(identity_key_id, str)
        or not identity_key_id
        or not isinstance(payload_key_id, str)
        or not payload_key_id
        or identity_key_id == payload_key_id
        or identity_key_id not in dict(identity_candidates)
        or not isinstance(retained_payload_key_ids, tuple)
        or not retained_payload_key_ids
        or any(
            not isinstance(key_id, str) or not key_id
            for key_id in retained_payload_key_ids
        )
        or len(set(retained_payload_key_ids)) != len(retained_payload_key_ids)
        or payload_key_id not in retained_payload_key_ids
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return identity_key_id, payload_key_id


def _receipt_payload_hash(
    receipt_codec,
    *,
    command: PublishPolicyBundleCommand,
    local_manifest_sha256: str,
    key_id: object,
) -> str:
    if not isinstance(key_id, str) or not key_id:
        raise IamError("SERVICE_UNAVAILABLE")
    retained_key_ids = getattr(
        receipt_codec,
        "retained_payload_key_ids",
        None,
    )
    if (
        not isinstance(retained_key_ids, tuple)
        or key_id not in retained_key_ids
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    try:
        payload_hash = receipt_codec.payload_hash(
            command,
            locally_computed_manifest_sha256=local_manifest_sha256,
            key_id=key_id,
        )
    except PolicyReceiptKeyUnavailableError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    except IamError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if (
        not _is_sha256(payload_hash)
        or hmac.compare_digest(payload_hash, local_manifest_sha256)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return payload_hash


def _keyed_receipt_key(
    *,
    actor: PolicyPublisherContext,
    identity_digest: str,
) -> tuple[str, str, str, int, str]:
    return (
        PolicyPublisherPrincipalKind.SYSTEM.value,
        actor.system_id,
        "PublishPolicyBundle",
        1,
        identity_digest,
    )


def _find_keyed_receipt(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
    identity_candidates: tuple[tuple[str, str], ...],
) -> Optional[Mapping[str, Any]]:
    candidate_pairs = set(identity_candidates)
    base_identity = (
        PolicyPublisherPrincipalKind.SYSTEM.value,
        actor.system_id,
        "PublishPolicyBundle",
        1,
    )
    matches = []
    related = []
    for receipt in tables.get("command_receipts", {}).values():
        if not isinstance(receipt, Mapping):
            continue
        receipt_base = (
            receipt.get("principal_kind"),
            receipt.get("principal_id"),
            receipt.get("command_name"),
            receipt.get("command_version"),
        )
        if receipt_base != base_identity:
            continue
        if receipt.get("command_id") == command.command_id:
            related.append(receipt)
        candidate_pair = (
            receipt.get("idempotency_key_digest_key_id"),
            receipt.get("idempotency_key_digest"),
        )
        if candidate_pair in candidate_pairs:
            matches.append(receipt)
    if len(matches) > 1:
        raise IamError("SERVICE_UNAVAILABLE")
    if matches:
        return matches[0]
    if related:
        raise IamError("SERVICE_UNAVAILABLE")
    return None


def _new_keyed_pending_receipt(
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
    identity_digest: object,
    identity_key_id: object,
    payload_hash: object,
    payload_key_id: object,
    now: datetime,
) -> dict[str, Any]:
    if (
        not _is_sha256(identity_digest)
        or not isinstance(identity_key_id, str)
        or not identity_key_id
        or not _is_sha256(payload_hash)
        or not isinstance(payload_key_id, str)
        or not payload_key_id
        or identity_key_id == payload_key_id
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return {
        "command_id": command.command_id,
        "principal_kind": PolicyPublisherPrincipalKind.SYSTEM.value,
        "principal_id": actor.system_id,
        "command_name": "PublishPolicyBundle",
        "command_version": 1,
        "idempotency_key_digest": identity_digest,
        "idempotency_key_digest_key_id": identity_key_id,
        "payload_hash": payload_hash,
        "payload_hash_key_id": payload_key_id,
        "canonicalization_version": _PUBLISH_RECEIPT_CANONICALIZATION,
        "target_kind": "PolicyBundle",
        "target_id": command.release.manifest.policy_bundle_id,
        "http_method": "INTERNAL",
        "canonical_path": _PUBLISH_RECEIPT_PATH,
        "if_match_version": None,
        "status": "IN_PROGRESS",
        "response_schema_version": None,
        "response_body": None,
        "reconstruction_metadata": None,
        "created_at": now,
        "retain_until": now + _PUBLISH_RECEIPT_RETENTION,
        "completed_at": None,
    }


def _receipt_key(
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
) -> tuple[str, str, str, int, str]:
    return (
        "SYSTEM",
        actor.system_id,
        "PublishPolicyBundle",
        1,
        command.command_id,
    )


def _find_receipt(
    tables: Mapping[str, Mapping[Any, Any]],
    *,
    receipt_key: tuple[str, str, str, int, str],
) -> Optional[Mapping[str, Any]]:
    receipts = tables.get("command_receipts", {})
    receipt = receipts.get(receipt_key)
    if receipt is not None:
        return receipt
    for candidate in receipts.values():
        if not isinstance(candidate, Mapping):
            continue
        candidate_key = (
            candidate.get("principal_kind"),
            candidate.get("principal_id"),
            candidate.get("command_name"),
            candidate.get("command_version"),
            candidate.get("command_id"),
        )
        if candidate_key == receipt_key:
            return candidate
    return None


def _replay_receipt(
    receipt: Mapping[str, Any],
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
) -> PublishPolicyBundleResult:
    expected_identity = _receipt_key(actor=actor, command=command)
    actual_identity = (
        receipt.get("principal_kind"),
        receipt.get("principal_id"),
        receipt.get("command_name"),
        receipt.get("command_version"),
        receipt.get("command_id"),
    )
    if actual_identity != expected_identity:
        raise IamError("SERVICE_UNAVAILABLE")
    if receipt.get("payload_hash") != command.release.manifest_sha256:
        raise IamError("IDEMPOTENCY_KEY_REUSED")
    if receipt.get("status") != "COMPLETED":
        raise IamError("COMMAND_IN_PROGRESS")
    response = receipt.get("response_body")
    if not isinstance(response, Mapping):
        raise IamError("SERVICE_UNAVAILABLE")
    policy_bundle_id = response.get("policy_bundle_id")
    selector_digest = response.get("selector_digest")
    aggregate_version = response.get("aggregate_version")
    if (
        not isinstance(policy_bundle_id, str)
        or not policy_bundle_id
        or not _is_sha256(selector_digest)
        or not isinstance(aggregate_version, int)
        or isinstance(aggregate_version, bool)
        or aggregate_version < 1
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return PublishPolicyBundleResult(
        replayed=True,
        policy_bundle_id=policy_bundle_id,
        selector_digest=selector_digest,
        aggregate_version=aggregate_version,
    )


def _replay_keyed_receipt(
    receipt: Mapping[str, Any],
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
    identity_candidates: tuple[tuple[str, str], ...],
    payload_hash: str,
) -> PublishPolicyBundleResult:
    if set(receipt) != _PUBLISH_RECEIPT_FIELDS:
        raise IamError("SERVICE_UNAVAILABLE")
    expected_identity = (
        PolicyPublisherPrincipalKind.SYSTEM.value,
        actor.system_id,
        "PublishPolicyBundle",
        1,
    )
    actual_identity = (
        receipt.get("principal_kind"),
        receipt.get("principal_id"),
        receipt.get("command_name"),
        receipt.get("command_version"),
    )
    receipt_identity = (
        receipt.get("idempotency_key_digest_key_id"),
        receipt.get("idempotency_key_digest"),
    )
    manifest = command.release.manifest
    if (
        actual_identity != expected_identity
        or receipt_identity not in set(identity_candidates)
        or receipt.get("command_id") != command.command_id
        or receipt.get("canonicalization_version")
        != _PUBLISH_RECEIPT_CANONICALIZATION
        or receipt.get("http_method") != "INTERNAL"
        or receipt.get("canonical_path") != _PUBLISH_RECEIPT_PATH
        or receipt.get("target_kind") != "PolicyBundle"
        or receipt.get("target_id") != manifest.policy_bundle_id
        or receipt.get("if_match_version") is not None
        or receipt.get("idempotency_key_digest") == command.command_id
        or receipt.get("idempotency_key_digest_key_id")
        == receipt.get("payload_hash_key_id")
        or not _is_utc(receipt.get("created_at"))
        or not _is_utc(receipt.get("retain_until"))
        or receipt.get("retain_until") <= receipt.get("created_at")
        or receipt.get("reconstruction_metadata") is not None
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    stored_payload_hash = receipt.get("payload_hash")
    if (
        not _is_sha256(stored_payload_hash)
        or not hmac.compare_digest(stored_payload_hash, payload_hash)
    ):
        raise IamError("IDEMPOTENCY_KEY_REUSED")
    status = receipt.get("status")
    if status == "IN_PROGRESS":
        if (
            receipt.get("response_schema_version") is not None
            or receipt.get("response_body") is not None
            or receipt.get("completed_at") is not None
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        raise IamError("COMMAND_IN_PROGRESS")
    if (
        status != "COMPLETED"
        or receipt.get("response_schema_version") != 1
        or not _is_utc(receipt.get("completed_at"))
        or receipt.get("completed_at") < receipt.get("created_at")
        or receipt.get("completed_at") > receipt.get("retain_until")
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    response = receipt.get("response_body")
    if not isinstance(response, Mapping) or set(response) != {
        "policy_bundle_id",
        "selector_digest",
        "aggregate_version",
    }:
        raise IamError("SERVICE_UNAVAILABLE")
    policy_bundle_id = response.get("policy_bundle_id")
    selector_digest = response.get("selector_digest")
    aggregate_version = response.get("aggregate_version")
    if (
        policy_bundle_id != manifest.policy_bundle_id
        or selector_digest != manifest.selector_digest
        or not _is_sha256(selector_digest)
        or not isinstance(aggregate_version, int)
        or isinstance(aggregate_version, bool)
        or aggregate_version < 1
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return PublishPolicyBundleResult(
        replayed=True,
        policy_bundle_id=policy_bundle_id,
        selector_digest=selector_digest,
        aggregate_version=aggregate_version,
    )


def _require_release_verification(
    verification: object,
    *,
    release: SignedPolicyRelease,
    canonical_manifest: bytes,
    local_manifest_sha256: str,
    now: datetime,
) -> None:
    if (
        not _is_sha256(release.manifest_sha256)
        or not hmac.compare_digest(
            release.manifest_sha256,
            local_manifest_sha256,
        )
    ):
        raise IamError("POLICY_RELEASE_INVALID")
    if isinstance(verification, bytes):
        if (
            not hmac.compare_digest(verification, canonical_manifest)
            or not hmac.compare_digest(
                hashlib.sha256(verification).hexdigest(),
                local_manifest_sha256,
            )
        ):
            raise IamError("POLICY_RELEASE_INVALID")
        return
    if not isinstance(verification, PolicyReleaseVerificationAttestation):
        raise IamError("POLICY_RELEASE_INVALID")
    manifest = release.manifest
    selector = manifest.selector
    if (
        not isinstance(verification.canonical_manifest, bytes)
        or not hmac.compare_digest(
            verification.canonical_manifest,
            canonical_manifest,
        )
        or not _is_sha256(verification.manifest_sha256)
        or not hmac.compare_digest(
            verification.manifest_sha256,
            local_manifest_sha256,
        )
        or verification.signature_algorithm != release.signature_algorithm
        or verification.signature_key_id != release.signature_key_id
        or verification.key_usage != PolicyReleaseKeyUsage.IAM_POLICY_RELEASE
        or not _closed_tuple(
            verification.allowed_manifest_schema_versions,
            str,
        )
        or manifest.schema_version
        not in verification.allowed_manifest_schema_versions
        or not _closed_tuple(
            verification.allowed_access_purposes,
            InvitationPurpose,
        )
        or selector.access_purpose
        not in verification.allowed_access_purposes
        or not _closed_tuple(
            verification.allowed_scope_types,
            PolicySelectorScopeType,
        )
        or selector.scope_type not in verification.allowed_scope_types
        or not _closed_tuple(
            verification.allowed_target_roles,
            TargetRole,
        )
        or selector.target_role not in verification.allowed_target_roles
        or not _closed_tuple(
            verification.allowed_jurisdictions,
            str,
        )
        or selector.jurisdiction not in verification.allowed_jurisdictions
        or verification.trust_status != PolicyReleaseTrustStatus.ACTIVE
        or not _is_utc(verification.trust_valid_from)
        or not _is_utc(verification.trust_valid_until)
        or not _is_utc(verification.verified_at)
        or verification.trust_valid_from > verification.verified_at
        or verification.verified_at > now
        or verification.trust_valid_from > now
        or now >= verification.trust_valid_until
        or verification.trust_valid_from >= verification.trust_valid_until
    ):
        raise IamError("POLICY_RELEASE_INVALID")


def _closed_tuple(values: object, item_type: type) -> bool:
    return (
        isinstance(values, tuple)
        and bool(values)
        and all(
            isinstance(value, item_type)
            and (not isinstance(value, str) or bool(value))
            for value in values
        )
        and len(set(values)) == len(values)
    )


def _require_legal_approval(
    legal_approval_port,
    *,
    command: PublishPolicyBundleCommand,
    manifest_sha256: str,
    now: datetime,
) -> PolicyLegalApprovalAttestation:
    try:
        approval = legal_approval_port.require_approval(
            manifest_sha256=manifest_sha256,
            signature_key_id=command.release.signature_key_id,
            now=now,
        )
    except PolicyLegalApprovalUnavailableError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    except IamError:
        raise
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise IamError("POLICY_RELEASE_INVALID") from error
    if (
        not isinstance(approval, PolicyLegalApprovalAttestation)
        or not isinstance(approval.credential_id, str)
        or not approval.credential_id
        or not isinstance(approval.approver_id, str)
        or not approval.approver_id
        or not _is_sha256(approval.manifest_sha256)
        or not hmac.compare_digest(
            approval.manifest_sha256,
            manifest_sha256,
        )
        or approval.signature_key_id != command.release.signature_key_id
        or approval.decision != PolicyLegalApprovalDecision.APPROVED
        or not _is_utc(approval.valid_from)
        or not _is_utc(approval.valid_until)
        or approval.valid_from > now
        or now >= approval.valid_until
        or approval.valid_from >= approval.valid_until
        or approval.revoked_at is not None
    ):
        raise IamError("POLICY_RELEASE_INVALID")
    return approval


def _canonical_release_manifest_bytes(
    manifest: PolicyReleaseManifest,
) -> bytes:
    payload = {
        "schema_version": manifest.schema_version,
        "policy_bundle_id": manifest.policy_bundle_id,
        "selector_digest": manifest.selector_digest,
        "selector": {
            "canonicalization_version": (
                manifest.selector.canonicalization_version
            ),
            "access_purpose": manifest.selector.access_purpose.value,
            "scope_type": manifest.selector.scope_type.value,
            "target_role": manifest.selector.target_role.value,
            "jurisdiction": manifest.selector.jurisdiction,
            "locale": manifest.selector.locale,
        },
        "supersedes_policy_bundle_id": (
            manifest.supersedes_policy_bundle_id
        ),
        "effective_at": _timestamp(manifest.effective_at),
        "effective_until": (
            None
            if manifest.effective_until is None
            else _timestamp(manifest.effective_until)
        ),
        "documents": [
            {
                "document_id": document.document_id,
                "kind": document.kind.value,
                "semantic_version": document.semantic_version,
                "locale": document.locale,
                "jurisdiction": document.jurisdiction,
                "canonical_body": document.canonical_body,
                "content_sha256": document.content_sha256,
                "legal_effect": document.legal_effect.value,
            }
            for document in manifest.documents
        ],
        "required_document_ids": list(manifest.required_document_ids),
        "consent_offers": [
            {
                **json.loads(canonical_consent_offer_bytes(offer)),
                "canonical_offer_sha256": offer.canonical_offer_sha256,
            }
            for offer in manifest.consent_offers
        ],
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validate_manifest(manifest: PolicyReleaseManifest, *, now: datetime) -> None:
    if (
        manifest.schema_version != "iam-policy-release-v1"
        or manifest.selector.canonicalization_version
        != "policy-selector-json-v1"
        or not isinstance(manifest.policy_bundle_id, str)
        or not manifest.policy_bundle_id
        or not _is_sha256(manifest.selector_digest)
        or manifest.selector_digest != _selector_digest(manifest.selector)
        or manifest.effective_until is not None
        or not _is_utc(manifest.effective_at)
        or manifest.effective_at > now
        or not manifest.documents
        or len(manifest.documents) > 50
        or not manifest.required_document_ids
        or len(manifest.consent_offers) > 50
        or manifest.supersedes_policy_bundle_id == manifest.policy_bundle_id
    ):
        raise IamError("POLICY_RELEASE_INVALID")
    selector = manifest.selector
    if any(
        not isinstance(value, str)
        or not value
        or value != unicodedata.normalize("NFC", value)
        for value in (selector.jurisdiction, selector.locale)
    ):
        raise IamError("POLICY_RELEASE_INVALID")
    creator_shape = (
        selector.access_purpose == InvitationPurpose.CREATOR_ENROLLMENT
        and selector.scope_type == PolicySelectorScopeType.USER_ROLE
        and selector.target_role == TargetRole.CREATOR
    )
    organization_shape = (
        selector.access_purpose == InvitationPurpose.ORGANIZATION_MEMBERSHIP
        and selector.scope_type == PolicySelectorScopeType.ORGANIZATION_ROLE
        and selector.target_role in (TargetRole.ORG_ADMIN, TargetRole.DEMAND_OWNER)
    )
    if not (creator_shape or organization_shape):
        raise IamError("POLICY_RELEASE_INVALID")
    document_ids = [document.document_id for document in manifest.documents]
    if (
        len(document_ids) != len(set(document_ids))
        or len(manifest.required_document_ids)
        != len(set(manifest.required_document_ids))
        or any(
            document_id not in document_ids
            for document_id in manifest.required_document_ids
        )
    ):
        raise IamError("POLICY_RELEASE_INVALID")
    for document in manifest.documents:
        if (
            not isinstance(document.document_id, str)
            or not document.document_id
            or not isinstance(document.semantic_version, str)
            or not document.semantic_version
            or not isinstance(document.canonical_body, str)
            or not document.canonical_body
            or not isinstance(document.kind, PolicyDocumentKind)
            or not isinstance(document.legal_effect, PolicyLegalEffect)
            or not isinstance(document.locale, str)
            or not document.locale
            or document.locale != unicodedata.normalize("NFC", document.locale)
            or not isinstance(document.jurisdiction, str)
            or not document.jurisdiction
            or document.jurisdiction
            != unicodedata.normalize("NFC", document.jurisdiction)
            or document.locale != selector.locale
            or document.jurisdiction != selector.jurisdiction
            or not _is_sha256(document.content_sha256)
            or hashlib.sha256(document.canonical_body.encode("utf-8")).hexdigest()
            != document.content_sha256
        ):
            raise IamError("POLICY_RELEASE_INVALID")
    document_identities = [
        (
            document.kind.value,
            document.locale,
            document.jurisdiction,
            document.semantic_version,
        )
        for document in manifest.documents
    ]
    if len(document_identities) != len(set(document_identities)):
        raise IamError("POLICY_RELEASE_INVALID")
    _validate_consent_offers(manifest)


def _validate_consent_offers(manifest: PolicyReleaseManifest) -> None:
    documents_by_id = {
        document.document_id: document for document in manifest.documents
    }
    offer_ids = [offer.consent_offer_id for offer in manifest.consent_offers]
    if len(offer_ids) != len(set(offer_ids)):
        raise IamError("POLICY_RELEASE_INVALID")
    for offer in manifest.consent_offers:
        not_after = getattr(offer, "not_after", None)
        supporting_document = documents_by_id.get(
            offer.supporting_document_id
        )
        if (
            getattr(offer, "canonicalization_version", None)
            != "consent-offer-json-v1"
            or not isinstance(offer.consent_offer_id, str)
            or not offer.consent_offer_id
            or not isinstance(offer.aggregate_version, int)
            or isinstance(offer.aggregate_version, bool)
            or offer.aggregate_version < 1
            or getattr(offer, "policy_bundle_id", None)
            != manifest.policy_bundle_id
            or not isinstance(offer.purpose, ConsentPurpose)
            or offer.purpose != ConsentPurpose.PILOT_RESEARCH
            or not isinstance(offer.scope_type, ConsentScopeType)
            or offer.scope_type != ConsentScopeType.PLATFORM_PARTICIPATION
            or getattr(offer, "scope_derivation", None)
            != "PLATFORM_PARTICIPATION_NULL_SCOPE"
            or not isinstance(offer.data_categories, tuple)
            or offer.data_categories
            != (
                DataCategory.PROFILE,
                DataCategory.MATCHING,
                DataCategory.RESEARCH,
            )
            or not _is_nfc_string(offer.recipient_reference, maximum=128)
            or not _is_nfc_string(
                getattr(offer, "recipient_label", None),
                maximum=160,
            )
            or supporting_document is None
            or supporting_document.content_sha256
            != offer.supporting_document_sha256
            or supporting_document.legal_effect
            != PolicyLegalEffect.CONSENT_TEXT
            or getattr(offer, "expiry_rule", None)
            != "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
            or getattr(offer, "expiry_days", None) != 365
            or not _is_utc(not_after)
            or not_after <= manifest.effective_at
            or getattr(offer, "optional", None) is not True
            or not _is_sha256(
                getattr(offer, "canonical_offer_sha256", None)
            )
        ):
            raise IamError("POLICY_RELEASE_INVALID")
        actual_digest = hashlib.sha256(
            canonical_consent_offer_bytes(offer)
        ).hexdigest()
        if not hmac.compare_digest(
            offer.canonical_offer_sha256,
            actual_digest,
        ):
            raise IamError("POLICY_RELEASE_INVALID")


def _selector_digest(selector: PolicySelectorFacts) -> str:
    canonical = json.dumps(
        {
            "access_purpose": selector.access_purpose.value,
            "scope_type": selector.scope_type.value,
            "target_role": selector.target_role.value,
            "jurisdiction": unicodedata.normalize("NFC", selector.jurisdiction),
            "locale": unicodedata.normalize("NFC", selector.locale),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _publication_precondition(
    *,
    tables: Mapping[str, Mapping[Any, Any]],
    locked_selector: Optional[Mapping[str, Any]],
    manifest: PolicyReleaseManifest,
    now: datetime,
) -> tuple[int, Optional[PolicyBundle]]:
    bundle_rows = tables.get("policy_bundles", {})
    active_bundles = [
        bundle
        for bundle in bundle_rows.values()
        if _bundle_field(bundle, "selector_digest")
        == manifest.selector_digest
        and _bundle_status(bundle) == PolicyBundleStatus.ACTIVE.value
    ]
    if locked_selector is None:
        if active_bundles:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        if manifest.supersedes_policy_bundle_id is not None:
            raise IamError("PRECONDITION_FAILED")
        return 1, None

    if not _selector_matches_manifest(locked_selector, manifest=manifest):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    aggregate_version = locked_selector.get("aggregate_version")
    if (
        not isinstance(aggregate_version, int)
        or isinstance(aggregate_version, bool)
        or aggregate_version < 1
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    current_bundle_id = locked_selector.get("current_bundle_id")
    if current_bundle_id is None:
        if active_bundles:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        if manifest.supersedes_policy_bundle_id is not None:
            raise IamError("PRECONDITION_FAILED")
        return aggregate_version + 1, None
    if not isinstance(current_bundle_id, str) or not current_bundle_id:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    predecessor = bundle_rows.get(current_bundle_id)
    if (
        not isinstance(predecessor, PolicyBundle)
        or predecessor.policy_bundle_id != current_bundle_id
        or predecessor.selector_digest != manifest.selector_digest
        or predecessor.status != PolicyBundleStatus.ACTIVE
        or predecessor.effective_at is None
        or not _is_utc(predecessor.effective_at)
        or predecessor.effective_at > now
        or (
            predecessor.effective_until is not None
            and (
                not _is_utc(predecessor.effective_until)
                or now >= predecessor.effective_until
            )
        )
        or len(active_bundles) != 1
        or _bundle_field(active_bundles[0], "policy_bundle_id")
        != current_bundle_id
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if manifest.supersedes_policy_bundle_id != current_bundle_id:
        raise IamError("PRECONDITION_FAILED")
    if (
        manifest.effective_at <= predecessor.effective_at
    ):
        raise IamError("PRECONDITION_FAILED")
    return aggregate_version + 1, predecessor


def _bundle_field(bundle: object, name: str) -> object:
    if isinstance(bundle, Mapping):
        return bundle.get(name)
    return getattr(bundle, name, None)


def _bundle_status(bundle: object) -> object:
    status = _bundle_field(bundle, "status")
    return getattr(status, "value", status)


def _selector_matches_manifest(
    selector: Mapping[str, Any],
    *,
    manifest: PolicyReleaseManifest,
) -> bool:
    facts = manifest.selector
    return all(
        selector.get(name) == expected
        for name, expected in (
            ("selector_digest", manifest.selector_digest),
            ("canonicalization_version", facts.canonicalization_version),
            ("access_purpose", facts.access_purpose.value),
            ("scope_type", facts.scope_type.value),
            ("target_role", facts.target_role.value),
            ("jurisdiction", facts.jurisdiction),
            ("locale", facts.locale),
        )
    )


def _require_unclaimed_artifacts(
    *,
    tables: Mapping[str, Mapping[Any, Any]],
    manifest: PolicyReleaseManifest,
) -> None:
    if manifest.policy_bundle_id in tables.get("policy_bundles", {}):
        raise IamError("PRECONDITION_FAILED")
    existing_documents = tables.get("policy_documents", {})
    if any(
        document.document_id in existing_documents
        for document in manifest.documents
    ):
        raise IamError("PRECONDITION_FAILED")


def _new_selector_row(
    *,
    manifest: PolicyReleaseManifest,
    now: datetime,
) -> dict[str, Any]:
    selector = manifest.selector
    return {
        "selector_digest": manifest.selector_digest,
        "canonicalization_version": selector.canonicalization_version,
        "access_purpose": selector.access_purpose.value,
        "scope_type": selector.scope_type.value,
        "target_role": selector.target_role.value,
        "jurisdiction": selector.jurisdiction,
        "locale": selector.locale,
        "current_bundle_id": manifest.policy_bundle_id,
        "aggregate_version": 1,
        "created_at": now,
        "updated_at": now,
    }


def _audit_event(
    *,
    actor: PolicyPublisherContext,
    command: PublishPolicyBundleCommand,
    approval: Optional[PolicyLegalApprovalAttestation],
    now: datetime,
) -> dict[str, Any]:
    manifest = command.release.manifest
    event = {
        "audit_event_id": command.command_id,
        "actor_kind": "SYSTEM",
        "actor_id": actor.system_id,
        "original_actor_id": actor.original_actor_id,
        "action": "PublishPolicyBundle",
        "target_type": "PolicyBundle",
        "target_id": manifest.policy_bundle_id,
        "result": "SUCCEEDED",
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "occurred_at": now,
    }
    if approval is not None:
        event.update(
            {
                "approval_credential_id": approval.credential_id,
                "approval_approver_id": approval.approver_id,
                "approved_manifest_sha256": approval.manifest_sha256,
            }
        )
    return event


def _outbox_event(
    *,
    event_id: str,
    event_type: str,
    aggregate_id: str,
    aggregate_version: int,
    actor: PolicyPublisherContext,
    now: datetime,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(now),
        "aggregate_type": "PolicyBundle",
        "aggregate_id": aggregate_id,
        "aggregate_version": aggregate_version,
        "actor_kind": "SYSTEM",
        "actor_id": actor.system_id,
        "original_actor_id": actor.original_actor_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": None,
        "payload": dict(payload),
    }


def _event_id(command_id: str, event_type: str) -> str:
    digest = hashlib.sha256(
        ("iam-policy-event-v1\x00" + command_id + "\x00" + event_type).encode(
            "utf-8"
        )
    ).hexdigest()
    return "evt_" + digest


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _is_nfc_string(value: object, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and value == unicodedata.normalize("NFC", value)
    )


def _is_utc(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _require_aware_utc(value: object) -> None:
    if not _is_utc(value):
        raise IamError("INVALID_SERVER_TIME")


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
