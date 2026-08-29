"""Strict independent fixtures for Publish authorization and receipt REDs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional

from desire_platform.identity_access.application.policy_publication import (
    PolicyLegalApprovalAttestation,
    PolicyLegalApprovalDecision,
    PolicyLegalApprovalUnavailableError,
    PolicyPublisherAuthorizationAttestation,
    PolicyPublisherAuthorizationUnavailableError,
    PolicyPublisherContext,
    PolicyPublisherOperation,
    PolicyPublisherPrincipalKind,
    PolicyReceiptKeyUnavailableError,
    PolicyReleaseKeyUsage,
    PolicyReleaseTrustStatus,
    PolicyReleaseVerificationAttestation,
    PolicyReleaseVerificationUnavailableError,
    PublishPolicyBundleCommand,
    PublishPolicyBundleHandler,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_policy_issue_builders import (
    FixedUtcClock,
    IsolatedPolicyIssueStore,
    POLICY_RELEASE_KEY_ID,
    PublicationFixture,
    StrictPolicyIssueUow,
    StrictPolicyIssueUowFactory,
    StrictReleaseVerifier,
    UTC_NOW,
    canonical_release_manifest_bytes,
    initial_publication_fixture,
)


PUBLISH_PATH = "/internal/iam/policy-bundles/publish"
PUBLISH_RECEIPT_CANONICALIZATION = "restricted-canonical-json-v1"
ACTIVE_IDENTITY_KEY_ID = "iam-receipt-idempotency-hmac-2026-08"
ACTIVE_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-08"
OLD_IDENTITY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
OLD_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"

_IDENTITY_KEYS = {
    ACTIVE_IDENTITY_KEY_ID: hashlib.sha256(
        b"publish-receipt-identity-2026-08"
    ).digest(),
    OLD_IDENTITY_KEY_ID: hashlib.sha256(
        b"publish-receipt-identity-2026-01"
    ).digest(),
}
_PAYLOAD_KEYS = {
    ACTIVE_PAYLOAD_KEY_ID: hashlib.sha256(
        b"publish-receipt-payload-2026-08"
    ).digest(),
    OLD_PAYLOAD_KEY_ID: hashlib.sha256(
        b"publish-receipt-payload-2026-01"
    ).digest(),
}


class CapturingPolicyIssueUowFactory(StrictPolicyIssueUowFactory):
    def __init__(self, *, store: IsolatedPolicyIssueStore) -> None:
        super().__init__(store=store)
        self.captured_writes: list[tuple[str, Any, str, Any]] = []

    def begin(self) -> "CapturingPolicyIssueUow":
        self.begin_count += 1
        return CapturingPolicyIssueUow(self)


class CapturingPolicyIssueUow(StrictPolicyIssueUow):
    factory: CapturingPolicyIssueUowFactory

    def put(
        self,
        table: str,
        key: Any,
        value: Any,
        *,
        checkpoint: str,
    ) -> None:
        self.factory.captured_writes.append(
            (table, key, checkpoint, deepcopy(value))
        )
        super().put(table, key, value, checkpoint=checkpoint)


class StrictPolicyPublisherAuthorizer:
    def __init__(
        self,
        *,
        attestation: PolicyPublisherAuthorizationAttestation,
        unavailable: bool = False,
    ) -> None:
        self.attestation = attestation
        self.unavailable = unavailable
        self.calls: list[dict[str, Any]] = []

    def authorize(
        self,
        *,
        actor: PolicyPublisherContext,
        operation: PolicyPublisherOperation,
        command_id: str,
        selector_digest: str,
        policy_bundle_id: str,
        now,
    ) -> PolicyPublisherAuthorizationAttestation:
        query = {
            "actor": actor,
            "operation": operation,
            "command_id": command_id,
            "selector_digest": selector_digest,
            "policy_bundle_id": policy_bundle_id,
            "now": now,
        }
        self.calls.append(query)
        if self.unavailable:
            raise PolicyPublisherAuthorizationUnavailableError()
        expected = {
            "credential_id": actor.workload_credential_id,
            "principal_kind": PolicyPublisherPrincipalKind.SYSTEM,
            "system_id": actor.system_id,
            "operation": PolicyPublisherOperation.POLICY_PUBLISH,
            "command_id": command_id,
            "selector_digest": selector_digest,
            "policy_bundle_id": policy_bundle_id,
            "credential_status": "ACTIVE",
        }
        if (
            actor.principal_kind != PolicyPublisherPrincipalKind.SYSTEM
            or any(
                getattr(self.attestation, name) != value
                for name, value in expected.items()
            )
            or self.attestation.authenticated_at > now
            or now >= self.attestation.valid_until
        ):
            raise IamError("AUTHENTICATION_REQUIRED")
        return self.attestation


class StrictRichReleaseVerifier:
    def __init__(
        self,
        *,
        attestation: PolicyReleaseVerificationAttestation,
        unavailable: bool = False,
    ) -> None:
        self.attestation = attestation
        self.unavailable = unavailable
        self.calls = []
        self._cryptographic_verifier = StrictReleaseVerifier()

    def verify(self, release) -> PolicyReleaseVerificationAttestation:
        self.calls.append(release)
        if self.unavailable:
            raise PolicyReleaseVerificationUnavailableError()
        canonical_manifest = self._cryptographic_verifier.verify(release)
        if canonical_manifest != self.attestation.canonical_manifest:
            raise IamError("POLICY_RELEASE_INVALID")
        return self.attestation


class StrictPolicyLegalApprovalPort:
    approval_body_sentinel = "SECRET_LEGAL_APPROVAL_BODY_MUST_NOT_PERSIST"

    def __init__(
        self,
        *,
        attestation: Optional[PolicyLegalApprovalAttestation],
        unavailable: bool = False,
    ) -> None:
        self.attestation = attestation
        self.unavailable = unavailable
        self.calls: list[dict[str, Any]] = []

    def require_approval(
        self,
        *,
        manifest_sha256: str,
        signature_key_id: str,
        now,
    ) -> PolicyLegalApprovalAttestation:
        self.calls.append(
            {
                "manifest_sha256": manifest_sha256,
                "signature_key_id": signature_key_id,
                "now": now,
            }
        )
        if self.unavailable:
            raise PolicyLegalApprovalUnavailableError()
        approval = self.attestation
        if (
            approval is None
            or approval.manifest_sha256 != manifest_sha256
            or approval.signature_key_id != signature_key_id
            or approval.decision != PolicyLegalApprovalDecision.APPROVED
            or approval.valid_from > now
            or now >= approval.valid_until
            or approval.revoked_at is not None
        ):
            raise IamError("POLICY_RELEASE_INVALID")
        return approval


class StrictPolicyPublishReceiptCodec:
    def __init__(
        self,
        *,
        identity_keys: Optional[Mapping[str, bytes]] = None,
        payload_keys: Optional[Mapping[str, bytes]] = None,
        active_identity_key_id: str = ACTIVE_IDENTITY_KEY_ID,
        active_payload_key_id: str = ACTIVE_PAYLOAD_KEY_ID,
        retained_identity_key_ids: Optional[tuple[str, ...]] = None,
        retained_payload_key_ids: Optional[tuple[str, ...]] = None,
    ) -> None:
        self.identity_keys = dict(
            _IDENTITY_KEYS if identity_keys is None else identity_keys
        )
        self.payload_keys = dict(
            _PAYLOAD_KEYS if payload_keys is None else payload_keys
        )
        self.active_identity_key_id = active_identity_key_id
        self.active_payload_key_id = active_payload_key_id
        self.retained_identity_key_ids = tuple(
            sorted(
                (OLD_IDENTITY_KEY_ID, ACTIVE_IDENTITY_KEY_ID)
                if retained_identity_key_ids is None
                else retained_identity_key_ids
            )
        )
        self.retained_payload_key_ids = tuple(
            sorted(
                (OLD_PAYLOAD_KEY_ID, ACTIVE_PAYLOAD_KEY_ID)
                if retained_payload_key_ids is None
                else retained_payload_key_ids
            )
        )
        self.identity_calls: list[dict[str, str]] = []
        self.payload_calls: list[dict[str, Any]] = []

    def identity_candidates(
        self,
        command_id: str,
    ) -> tuple[tuple[str, str], ...]:
        return tuple(
            (
                key_id,
                self.identity_digest(command_id, key_id=key_id),
            )
            for key_id in self.retained_identity_key_ids
        )

    def identity_digest(
        self,
        command_id: str,
        *,
        key_id: Optional[str] = None,
    ) -> str:
        selected_key_id = key_id or self.active_identity_key_id
        self.identity_calls.append(
            {"command_id": command_id, "key_id": selected_key_id}
        )
        key = self.identity_keys.get(selected_key_id)
        if key is None:
            raise PolicyReceiptKeyUnavailableError()
        canonical = json.dumps(
            {"command_id": command_id},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()

    def payload_hash(
        self,
        command: PublishPolicyBundleCommand,
        *,
        locally_computed_manifest_sha256: str,
        key_id: Optional[str] = None,
    ) -> str:
        selected_key_id = key_id or self.active_payload_key_id
        body = {
            "manifest_sha256": locally_computed_manifest_sha256,
            "signature_algorithm": command.release.signature_algorithm,
            "signature_key_id": command.release.signature_key_id,
            "signature": command.release.signature,
        }
        projection = {
            "body": body,
            "canonicalization_version": PUBLISH_RECEIPT_CANONICALIZATION,
            "command_name": "PublishPolicyBundle",
            "command_version": 1,
            "http_method": "INTERNAL",
            "if_match_version": None,
            "path": PUBLISH_PATH,
            "target_id": command.release.manifest.policy_bundle_id,
            "target_kind": "PolicyBundle",
        }
        self.payload_calls.append(
            {
                "command": command,
                "key_id": selected_key_id,
                "projection": deepcopy(projection),
            }
        )
        key = self.payload_keys.get(selected_key_id)
        if key is None:
            raise PolicyReceiptKeyUnavailableError()
        canonical = json.dumps(
            projection,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()


@dataclass
class PolicyPublishSecurityFixture:
    store: IsolatedPolicyIssueStore
    uow_factory: CapturingPolicyIssueUowFactory
    actor: PolicyPublisherContext
    command: PublishPolicyBundleCommand
    handler: PublishPolicyBundleHandler
    clock: FixedUtcClock
    workload_authorizer: StrictPolicyPublisherAuthorizer
    release_verifier: Any
    legal_approval: StrictPolicyLegalApprovalPort
    receipt_codec: StrictPolicyPublishReceiptCodec
    selector_digest: str


def secure_publication_fixture(
    *,
    rich_release_verifier: bool = False,
) -> PolicyPublishSecurityFixture:
    base: PublicationFixture = initial_publication_fixture()
    actor = PolicyPublisherContext(
        system_id=base.actor.system_id,
        original_actor_id=base.actor.original_actor_id,
        correlation_id=base.actor.correlation_id,
        causation_id=base.actor.causation_id,
        trace_id=base.actor.trace_id,
        principal_kind=PolicyPublisherPrincipalKind.SYSTEM,
        workload_credential_id="workload_credential_policy_publish_001",
    )
    manifest = base.command.release.manifest
    workload_attestation = PolicyPublisherAuthorizationAttestation(
        credential_id=actor.workload_credential_id,
        principal_kind=PolicyPublisherPrincipalKind.SYSTEM,
        system_id=actor.system_id,
        operation=PolicyPublisherOperation.POLICY_PUBLISH,
        command_id=base.command.command_id,
        selector_digest=manifest.selector_digest,
        policy_bundle_id=manifest.policy_bundle_id,
        credential_status="ACTIVE",
        authenticated_at=UTC_NOW - timedelta(minutes=1),
        valid_until=UTC_NOW + timedelta(minutes=4),
    )
    authorizer = StrictPolicyPublisherAuthorizer(
        attestation=workload_attestation
    )
    canonical_manifest = canonical_release_manifest_bytes(manifest)
    release_attestation = PolicyReleaseVerificationAttestation(
        canonical_manifest=canonical_manifest,
        manifest_sha256=hashlib.sha256(canonical_manifest).hexdigest(),
        signature_algorithm=base.command.release.signature_algorithm,
        signature_key_id=base.command.release.signature_key_id,
        key_usage=PolicyReleaseKeyUsage.IAM_POLICY_RELEASE,
        allowed_manifest_schema_versions=(manifest.schema_version,),
        allowed_access_purposes=(manifest.selector.access_purpose,),
        allowed_scope_types=(manifest.selector.scope_type,),
        allowed_target_roles=(manifest.selector.target_role,),
        allowed_jurisdictions=(manifest.selector.jurisdiction,),
        trust_status=PolicyReleaseTrustStatus.ACTIVE,
        trust_valid_from=UTC_NOW - timedelta(days=30),
        trust_valid_until=UTC_NOW + timedelta(days=30),
        verified_at=UTC_NOW,
    )
    release_verifier = (
        StrictRichReleaseVerifier(attestation=release_attestation)
        if rich_release_verifier
        else base.verifier
    )
    approval_attestation = PolicyLegalApprovalAttestation(
        credential_id="legal_approval_policy_release_001",
        manifest_sha256=release_attestation.manifest_sha256,
        signature_key_id=POLICY_RELEASE_KEY_ID,
        decision=PolicyLegalApprovalDecision.APPROVED,
        approver_id="legal_approver_independent_001",
        valid_from=UTC_NOW - timedelta(days=1),
        valid_until=UTC_NOW + timedelta(days=7),
        revoked_at=None,
    )
    approval = StrictPolicyLegalApprovalPort(
        attestation=approval_attestation
    )
    receipt_codec = StrictPolicyPublishReceiptCodec()
    uow_factory = CapturingPolicyIssueUowFactory(store=base.store)
    handler = PublishPolicyBundleHandler(
        uow_factory=uow_factory,
        release_verifier=release_verifier,
        clock=FixedUtcClock(),
        workload_authorizer=authorizer,
        legal_approval_port=approval,
        receipt_codec=receipt_codec,
    )
    return PolicyPublishSecurityFixture(
        store=base.store,
        uow_factory=uow_factory,
        actor=actor,
        command=base.command,
        handler=handler,
        clock=FixedUtcClock(),
        workload_authorizer=authorizer,
        release_verifier=release_verifier,
        legal_approval=approval,
        receipt_codec=receipt_codec,
        selector_digest=base.selector_digest,
    )


def local_manifest_sha256(command: PublishPolicyBundleCommand) -> str:
    return hashlib.sha256(
        canonical_release_manifest_bytes(command.release.manifest)
    ).hexdigest()


def completed_publish_receipt(
    fixture: PolicyPublishSecurityFixture,
    *,
    codec: StrictPolicyPublishReceiptCodec,
    identity_key_id: str,
    payload_key_id: str,
) -> dict[str, Any]:
    command = fixture.command
    return {
        "command_id": command.command_id,
        "principal_kind": "SYSTEM",
        "principal_id": fixture.actor.system_id,
        "command_name": "PublishPolicyBundle",
        "command_version": 1,
        "idempotency_key_digest": codec.identity_digest(
            command.command_id,
            key_id=identity_key_id,
        ),
        "idempotency_key_digest_key_id": identity_key_id,
        "payload_hash": codec.payload_hash(
            command,
            locally_computed_manifest_sha256=local_manifest_sha256(command),
            key_id=payload_key_id,
        ),
        "payload_hash_key_id": payload_key_id,
        "canonicalization_version": PUBLISH_RECEIPT_CANONICALIZATION,
        "target_kind": "PolicyBundle",
        "target_id": command.release.manifest.policy_bundle_id,
        "http_method": "INTERNAL",
        "canonical_path": PUBLISH_PATH,
        "if_match_version": None,
        "status": "COMPLETED",
        "response_schema_version": 1,
        "response_body": {
            "policy_bundle_id": command.release.manifest.policy_bundle_id,
            "selector_digest": command.release.manifest.selector_digest,
            "aggregate_version": 1,
        },
        "reconstruction_metadata": None,
        "created_at": UTC_NOW,
        "retain_until": UTC_NOW + timedelta(days=30),
        "completed_at": UTC_NOW,
    }


PUBLISH_RECEIPT_FIELDS = {
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
