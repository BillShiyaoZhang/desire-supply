"""Framework-neutral transactional orchestration for Taxonomy v1."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Any, Mapping, Optional, Sequence

from ..domain.model import (
    TaxonomyBundle,
    TaxonomyBundleStatus,
    TaxonomyCodeMeaning,
    TaxonomyCompatibilityLevel,
    TaxonomyDomainError,
    TaxonomyReleaseCandidate,
    ValidatedTaxonomyRelease,
    canonical_taxonomy_artifact_bytes,
    taxonomy_artifact_sha256,
)
from ..ports.commands import (
    TaxonomyApprovalEvidence,
    TaxonomyArtifactSet,
    TaxonomyArtifactUnavailableError,
    TaxonomyAuthorityUnavailableError,
    TaxonomyCommitOutcomeUnknownError,
    TaxonomyConsumerRelease,
    TaxonomySignatureEvidence,
    TaxonomyStorageUnavailableError,
    TaxonomyTrustEvidence,
    TaxonomyTrustUnavailableError,
    TaxonomyWorkloadAuthority,
)
from .commands import (
    ApplyTaxonomyBundleToConsumerCommand,
    PublishTaxonomyBundleCommand,
    RetireTaxonomyBundleCommand,
    TaxonomyActorContext,
    TaxonomyActorKind,
    TaxonomyCommandResult,
)


TAXONOMY_APPLICATION_BEHAVIOR_NOT_AVAILABLE = (
    "TAXONOMY_APPLICATION_BEHAVIOR_NOT_AVAILABLE"
)

PUBLISH_CHECKPOINTS = (
    "receipt.pending",
    "bundle.insert",
    "artifacts.insert",
    "nodes.insert",
    "edges.insert",
    "labels.insert",
    "crosswalk.insert_optional",
    "predecessor.supersede_optional",
    "current.advance",
    "audit.append",
    "outbox.append",
    "receipt.complete",
    "commit",
)
RETIRE_CHECKPOINTS = (
    "receipt.pending",
    "bundle.retire",
    "current.clear_if_current",
    "audit.append",
    "outbox.append",
    "receipt.complete",
    "commit",
)


class TaxonomyApplicationBehaviorNotAvailable(RuntimeError):
    """Compatibility sentinel retained after Memory GREEN."""


class TaxonomyApplicationError(RuntimeError):
    """Closed rejection safe for a future presenter boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_DEPENDENCY_ERRORS = (
    TaxonomyAuthorityUnavailableError,
    TaxonomyArtifactUnavailableError,
    TaxonomyTrustUnavailableError,
)


class _TaxonomyHandler:
    operation = ""

    def __init__(self, **dependencies: Any) -> None:
        self._dependencies = dict(dependencies)

    def handle(
        self, *, actor: TaxonomyActorContext, command: Any
    ) -> TaxonomyCommandResult:
        try:
            now = self._required("clock").now()
            self._authorize_workload(actor=actor, now=now)
            if isinstance(command, ApplyTaxonomyBundleToConsumerCommand):
                return self._apply_consumer(actor=actor, command=command, now=now)

            receipt = self._receipt_binding(actor=actor, command=command)
            replay = self._completed_receipt(receipt)
            if replay is not None:
                return replay
            if isinstance(command, PublishTaxonomyBundleCommand):
                outside = self._prepare_publish(command=command, now=now)
                return self._publish_transaction(
                    actor=actor,
                    command=command,
                    receipt=receipt,
                    outside=outside,
                    now=now,
                )
            if isinstance(command, RetireTaxonomyBundleCommand):
                return self._retire_transaction(
                    actor=actor,
                    command=command,
                    receipt=receipt,
                    now=now,
                )
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        except TaxonomyApplicationError:
            raise
        except TaxonomyDomainError as error:
            raise TaxonomyApplicationError(error.code) from error
        except _DEPENDENCY_ERRORS as error:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error
        except TaxonomyStorageUnavailableError as error:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error

    def _required(self, name: str) -> Any:
        value = self._dependencies.get(name)
        if value is None:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        return value

    def _authorize_workload(
        self, *, actor: TaxonomyActorContext, now: datetime
    ) -> None:
        if actor.actor_kind is not TaxonomyActorKind.SYSTEM:
            raise TaxonomyApplicationError("AUTHENTICATION_REQUIRED")
        authority = self._required("workload_authority").authorize(
            actor=actor, operation=self.operation
        )
        if (
            not isinstance(authority, TaxonomyWorkloadAuthority)
            or authority.workload_principal_id != actor.actor_id
            or authority.workload_credential_id != actor.workload_credential_id
            or authority.credential_status != "ACTIVE"
            or authority.operation != self.operation
            or authority.valid_until <= now
            or len(authority.attestation_id) < 16
            or len(authority.attestation_sha256) != 64
        ):
            raise TaxonomyApplicationError("AUTHENTICATION_REQUIRED")

    def _receipt_binding(
        self, *, actor: TaxonomyActorContext, command: Any
    ) -> dict[str, Any]:
        keyring = self._required("receipt_keyring")
        identity_bytes = _canonical_bytes(
            {
                "canonicalization_version": "taxonomy-receipt-identity-json-v1",
                "operation": self.operation,
                "actor_kind": actor.actor_kind.value,
                "actor_id": actor.actor_id,
                "idempotency_key": command.idempotency_key,
            }
        )
        payload_bytes = _canonical_bytes(
            {
                "canonicalization_version": "taxonomy-command-json-v1",
                "command_version": 1,
                "operation": self.operation,
                "actor_kind": actor.actor_kind.value,
                "actor_id": actor.actor_id,
                "command": _public_value(command, excluded={"idempotency_key"}),
            }
        )
        return {
            "identity_bytes": identity_bytes,
            "payload_bytes": payload_bytes,
            "active_identity_key_id": keyring.active_identity_key_id,
            "active_payload_key_id": keyring.active_payload_key_id,
        }

    def _find_receipt_row(
        self, receipt: Mapping[str, Any]
    ) -> tuple[Optional[str], Any]:
        keyring = self._required("receipt_keyring")
        key_ids = _unique(
            (
                keyring.active_identity_key_id,
                *keyring.retained_identity_key_ids,
            )
        )
        snapshot = self._required("uow_factory").store.snapshot()
        for key_id in key_ids:
            identity = keyring.keyed_digest(key_id, receipt["identity_bytes"])
            row = snapshot.get("receipts", {}).get(identity)
            if row is not None:
                return identity, row
        return None, None

    def _completed_receipt(
        self, receipt: Mapping[str, Any]
    ) -> Optional[TaxonomyCommandResult]:
        identity, row = self._find_receipt_row(receipt)
        if row is None:
            return None
        return self._validate_receipt(
            identity=identity,
            row=row,
            identity_bytes=receipt["identity_bytes"],
            payload_bytes=receipt["payload_bytes"],
            replayed=True,
        )

    def _validate_receipt(
        self,
        *,
        identity: Optional[str],
        row: Any,
        identity_bytes: bytes,
        payload_bytes: bytes,
        replayed: bool,
    ) -> TaxonomyCommandResult:
        expected = {
            "schema_version",
            "canonicalization_version",
            "command_version",
            "operation",
            "identity_key_id",
            "payload_hash_key_id",
            "payload_sha256",
            "status",
            "safe_response",
        }
        if not isinstance(identity, str) or not isinstance(row, Mapping) or set(row) != expected:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        if (
            row["schema_version"] != 1
            or row["canonicalization_version"] != "taxonomy-command-json-v1"
            or row["command_version"] != 1
            or row["operation"] != self.operation
        ):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        keyring = self._required("receipt_keyring")
        identity_keys = _unique(
            (keyring.active_identity_key_id, *keyring.retained_identity_key_ids)
        )
        payload_keys = _unique(
            (keyring.active_payload_key_id, *keyring.retained_payload_key_ids)
        )
        if row["identity_key_id"] not in identity_keys or row["payload_hash_key_id"] not in payload_keys:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        expected_identity = keyring.keyed_digest(
            row["identity_key_id"], identity_bytes
        )
        if expected_identity != identity:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        expected_payload = keyring.keyed_digest(
            row["payload_hash_key_id"], payload_bytes
        )
        if row["payload_sha256"] != expected_payload:
            raise TaxonomyApplicationError("IDEMPOTENCY_KEY_REUSED")
        if row["status"] != "COMPLETED":
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        return self._result_from_safe(row["safe_response"], replayed=replayed)

    def _result_from_safe(
        self, safe: Any, *, replayed: bool
    ) -> TaxonomyCommandResult:
        if not isinstance(safe, Mapping):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        if set(safe) != {
            "schema_version", "response_schema", "http_status", "etag", "body"
        } or safe["schema_version"] != 1 or safe["response_schema"] != "taxonomy-command-result-v1":
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        try:
            self._required("safe_response_validator").validate(
                operation=self.operation, response=safe
            )
        except (AssertionError, TypeError, ValueError) as error:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error
        body = safe["body"]
        if not isinstance(body, Mapping) or set(body) != {
            "target_id",
            "target_status",
            "aggregate_version",
            "event_types",
            "completed_at",
        }:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        if safe["etag"] != f'"v{body["aggregate_version"]}"':
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        try:
            completed_at = datetime.fromisoformat(
                body["completed_at"].replace("Z", "+00:00")
            )
            return TaxonomyCommandResult(
                target_id=body["target_id"],
                target_status=body["target_status"],
                aggregate_version=body["aggregate_version"],
                entity_tag=safe["etag"],
                http_status=safe["http_status"],
                event_types=tuple(body["event_types"]),
                replayed=replayed,
                completed_at=completed_at,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error

    def _safe_response(
        self,
        *,
        target_id: str,
        target_status: str,
        aggregate_version: int,
        http_status: int,
        event_types: Sequence[str],
        now: datetime,
    ) -> dict[str, Any]:
        safe = {
            "schema_version": 1,
            "response_schema": "taxonomy-command-result-v1",
            "http_status": http_status,
            "etag": f'"v{aggregate_version}"',
            "body": {
                "target_id": target_id,
                "target_status": target_status,
                "aggregate_version": aggregate_version,
                "event_types": list(event_types),
                "completed_at": _timestamp(now),
            },
        }
        self._required("safe_response_validator").validate(
            operation=self.operation, response=safe
        )
        return safe

    def _pending_receipt(
        self, *, identity_key_id: str, payload_key_id: str, payload_hash: str
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "canonicalization_version": "taxonomy-command-json-v1",
            "command_version": 1,
            "operation": self.operation,
            "identity_key_id": identity_key_id,
            "payload_hash_key_id": payload_key_id,
            "payload_sha256": payload_hash,
            "status": "PENDING",
            "safe_response": None,
        }

    def _prepare_publish(
        self, *, command: PublishTaxonomyBundleCommand, now: datetime
    ) -> dict[str, Any]:
        artifact_set = self._required("artifact_reader").read_exact(
            references=command.artifacts
        )
        self._validate_artifact_set(command, artifact_set)
        signature = self._required("signature_verifier").verify(
            signature_envelope_id=command.signature_envelope_id,
            trust_record_id=command.trust_record_id,
            release_manifest_sha256=command.release_manifest_sha256,
        )
        self._validate_signature(signature, command, now)
        trust = self._required("trust_verifier").verify(
            trust_record_id=command.trust_record_id,
            signing_key_id=signature.signing_key_id,
            algorithm=signature.algorithm,
            release_manifest_sha256=command.release_manifest_sha256,
        )
        self._validate_trust(trust, signature, command, now)
        approvals = self._required("approval_reader").read_exact(
            domain_approval_id=command.domain_approval_id,
            safety_data_approval_id=command.safety_data_approval_id,
            release_manifest_sha256=command.release_manifest_sha256,
        )
        self._validate_approvals(approvals, command, now)
        snapshot = self._required("uow_factory").store.snapshot()
        predecessor = None
        if command.expected_current_bundle_id is not None:
            predecessor = snapshot.get("releases", {}).get(
                command.expected_current_bundle_id
            )
            if not isinstance(predecessor, TaxonomyReleaseCandidate):
                raise TaxonomyApplicationError("PRECONDITION_FAILED")
        validated = self._required("domain_validator").validate(
            artifact_set=artifact_set,
            predecessor=predecessor,
            permanent_code_registry=tuple(
                snapshot.get("code_registry", {}).values()
            ),
            server_now=now,
        )
        if (
            not isinstance(validated, ValidatedTaxonomyRelease)
            or validated.release_manifest_sha256 != command.release_manifest_sha256
        ):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        return {
            "artifact_set": artifact_set,
            "signature": signature,
            "trust": trust,
            "approvals": tuple(approvals),
            "validated": validated,
        }

    @staticmethod
    def _validate_artifact_set(
        command: PublishTaxonomyBundleCommand,
        artifact_set: Any,
    ) -> None:
        if (
            not isinstance(artifact_set, TaxonomyArtifactSet)
            or tuple(artifact_set.references) != tuple(command.artifacts)
            or artifact_set.candidate.manifest.bundle_id == ""
            or taxonomy_artifact_sha256(artifact_set.candidate.manifest)
            != command.release_manifest_sha256
        ):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        raw = dict(artifact_set.canonical_bytes_by_reference)
        if set(raw) != {item.artifact_reference_id for item in command.artifacts}:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        for reference in command.artifacts:
            value = raw.get(reference.artifact_reference_id)
            if not isinstance(value, bytes) or hashlib.sha256(value).hexdigest() != reference.sha256:
                raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")

    @staticmethod
    def _validate_signature(
        signature: Any,
        command: PublishTaxonomyBundleCommand,
        now: datetime,
    ) -> None:
        if (
            not isinstance(signature, TaxonomySignatureEvidence)
            or signature.signature_envelope_id != command.signature_envelope_id
            or signature.trust_record_id != command.trust_record_id
            or signature.release_manifest_sha256 != command.release_manifest_sha256
            or signature.algorithm != "ED25519"
            or signature.verified_at > now
            or signature.valid_until <= now
        ):
            raise TaxonomyApplicationError("SIGNATURE_INVALID")

    @staticmethod
    def _validate_trust(
        trust: Any,
        signature: TaxonomySignatureEvidence,
        command: PublishTaxonomyBundleCommand,
        now: datetime,
    ) -> None:
        if (
            not isinstance(trust, TaxonomyTrustEvidence)
            or trust.trust_record_id != command.trust_record_id
            or trust.signing_key_id != signature.signing_key_id
            or trust.trust_status != "ACTIVE"
            or trust.allowed_algorithm != signature.algorithm
            or trust.release_manifest_sha256 != command.release_manifest_sha256
            or trust.valid_until <= now
        ):
            raise TaxonomyApplicationError("SIGNATURE_INVALID")

    @staticmethod
    def _validate_approvals(
        approvals: Any,
        command: PublishTaxonomyBundleCommand,
        now: datetime,
    ) -> None:
        if not isinstance(approvals, tuple) or len(approvals) != 2:
            raise TaxonomyApplicationError("REVIEW_APPROVAL_REQUIRED")
        domain, safety = approvals
        if (
            not all(isinstance(item, TaxonomyApprovalEvidence) for item in approvals)
            or domain.approval_id != command.domain_approval_id
            or safety.approval_id != command.safety_data_approval_id
            or domain.duty_code != "DOMAIN_STEWARD"
            or safety.duty_code != "SAFETY_DATA_STEWARD"
            or domain.reviewer_id == safety.reviewer_id
            or domain.approval_status != "APPROVED"
            or safety.approval_status != "APPROVED"
            or domain.release_manifest_sha256 != command.release_manifest_sha256
            or safety.release_manifest_sha256 != command.release_manifest_sha256
            or domain.golden_result_sha256 != safety.golden_result_sha256
            or domain.valid_until <= now
            or safety.valid_until <= now
        ):
            raise TaxonomyApplicationError("REVIEW_APPROVAL_REQUIRED")

    def _publish_transaction(
        self,
        *,
        actor: TaxonomyActorContext,
        command: PublishTaxonomyBundleCommand,
        receipt: Mapping[str, Any],
        outside: Mapping[str, Any],
        now: datetime,
    ) -> TaxonomyCommandResult:
        keyring = self._required("receipt_keyring")
        identity = keyring.keyed_digest(
            receipt["active_identity_key_id"], receipt["identity_bytes"]
        )
        payload_hash = keyring.keyed_digest(
            receipt["active_payload_key_id"], receipt["payload_bytes"]
        )
        validated: ValidatedTaxonomyRelease = outside["validated"]
        candidate = validated.candidate
        try:
            with self._required("uow_factory").begin() as uow:
                uow.lock(
                    "taxonomy.publish",
                    (identity, validated.selector_digest, candidate.manifest.bundle_id),
                )
                current = uow.get("current", "selector")
                if current != command.expected_current_bundle_id:
                    raise TaxonomyApplicationError("PRECONDITION_FAILED")
                if uow.get("receipts", identity) is not None:
                    raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
                if uow.get("bundles", candidate.manifest.bundle_id) is not None:
                    raise TaxonomyApplicationError("PRECONDITION_FAILED")
                self._required("locked_evidence").recheck(
                    signature=outside["signature"],
                    approvals=outside["approvals"],
                    server_now=now,
                )
                pending = self._pending_receipt(
                    identity_key_id=receipt["active_identity_key_id"],
                    payload_key_id=receipt["active_payload_key_id"],
                    payload_hash=payload_hash,
                )
                uow.put("receipts", identity, pending)
                uow.checkpoint("receipt.pending")

                created = TaxonomyBundle(
                    bundle_id=candidate.manifest.bundle_id,
                    family_code=candidate.manifest.family_code,
                    semantic_version=candidate.manifest.semantic_version,
                    selector_digest=validated.selector_digest,
                    release_manifest_sha256=validated.release_manifest_sha256,
                    status=TaxonomyBundleStatus.ACTIVE,
                    aggregate_version=1,
                    predecessor_bundle_id=candidate.manifest.predecessor_bundle_id,
                    successor_bundle_id=None,
                    effective_at=candidate.manifest.effective_at,
                    effective_until=candidate.manifest.effective_until,
                    retired_reason_code=None,
                    updated_at=now,
                )
                uow.put("bundles", created.bundle_id, created)
                uow.put("releases", created.bundle_id, candidate)
                uow.checkpoint("bundle.insert")
                uow.put("release_artifacts", created.bundle_id, tuple(command.artifacts))
                uow.checkpoint("artifacts.insert")
                uow.put("nodes", created.bundle_id, candidate.nodes.nodes)
                for node in candidate.nodes.nodes:
                    uow.put(
                        "code_registry",
                        node.code,
                        TaxonomyCodeMeaning(
                            created.family_code,
                            node.code,
                            node.kind,
                            node.definition_code,
                            node.attributes,
                        ),
                    )
                uow.checkpoint("nodes.insert")
                uow.put("edges", created.bundle_id, candidate.edges.edges)
                uow.checkpoint("edges.insert")
                uow.put("labels", created.bundle_id, candidate.labels)
                uow.checkpoint("labels.insert")
                if candidate.crosswalk is not None:
                    uow.put("crosswalks", candidate.crosswalk.crosswalk_id, candidate.crosswalk)
                uow.checkpoint("crosswalk.insert_optional")

                predecessor = None
                if command.expected_current_bundle_id is not None:
                    predecessor = uow.get("bundles", command.expected_current_bundle_id)
                    if not isinstance(predecessor, TaxonomyBundle):
                        raise TaxonomyApplicationError("PRECONDITION_FAILED")
                    predecessor = predecessor.supersede(
                        successor_bundle_id=created.bundle_id, server_now=now
                    )
                    uow.put("bundles", predecessor.bundle_id, predecessor)
                uow.checkpoint("predecessor.supersede_optional")
                uow.put("current", "selector", created.bundle_id)
                uow.checkpoint("current.advance")

                events = self._publish_events(
                    actor=actor,
                    created=created,
                    predecessor=predecessor,
                    candidate=candidate,
                    now=now,
                )
                audit_id = self._required("id_source").next_id("audit")
                uow.put(
                    "audits",
                    audit_id,
                    _audit(
                        actor=actor,
                        operation=self.operation,
                        target_id=created.bundle_id,
                        result="ACTIVE",
                        now=now,
                        evidence_sha256=hashlib.sha256(
                            _canonical_bytes(
                                {
                                    "manifest": validated.release_manifest_sha256,
                                    "golden": outside["approvals"][0].golden_result_sha256,
                                    "artifact_hashes": [item.sha256 for item in command.artifacts],
                                }
                            )
                        ).hexdigest(),
                    ),
                )
                uow.checkpoint("audit.append")
                for event in events:
                    self._required("event_validator").validate(event)
                    uow.put("outbox", event["event_id"], event)
                uow.checkpoint("outbox.append")

                event_types = tuple(event["event_type"] for event in events)
                safe = self._safe_response(
                    target_id=created.bundle_id,
                    target_status=created.status.value,
                    aggregate_version=created.aggregate_version,
                    http_status=201,
                    event_types=event_types,
                    now=now,
                )
                uow.put(
                    "receipts",
                    identity,
                    {**pending, "status": "COMPLETED", "safe_response": safe},
                )
                uow.checkpoint("receipt.complete")
                uow.checkpoint("commit")
                uow.commit()
            return self._result_from_safe(safe, replayed=False)
        except TaxonomyCommitOutcomeUnknownError as error:
            return self._recover_commit(
                identity=identity,
                identity_bytes=receipt["identity_bytes"],
                payload_bytes=receipt["payload_bytes"],
                target_collection="bundles",
                error=error,
            )

    def _publish_events(
        self,
        *,
        actor: TaxonomyActorContext,
        created: TaxonomyBundle,
        predecessor: Optional[TaxonomyBundle],
        candidate: TaxonomyReleaseCandidate,
        now: datetime,
    ) -> tuple[dict[str, Any], ...]:
        events = [
            _event(
                id_source=self._required("id_source"),
                actor=actor,
                event_type="TaxonomyBundlePublished",
                aggregate_type="TaxonomyBundle",
                aggregate_id=created.bundle_id,
                aggregate_version=created.aggregate_version,
                now=now,
                payload={
                    "bundle_id": created.bundle_id,
                    "family_code": created.family_code,
                    "semantic_version": created.semantic_version,
                    "selector_digest": created.selector_digest,
                    "release_manifest_sha256": created.release_manifest_sha256,
                    "effective_at": _timestamp(created.effective_at),
                    "status": "ACTIVE",
                },
            )
        ]
        if predecessor is not None:
            events.append(
                _event(
                    id_source=self._required("id_source"),
                    actor=actor,
                    event_type="TaxonomyBundleSuperseded",
                    aggregate_type="TaxonomyBundle",
                    aggregate_id=predecessor.bundle_id,
                    aggregate_version=predecessor.aggregate_version,
                    now=now,
                    payload={
                        "bundle_id": predecessor.bundle_id,
                        "successor_bundle_id": created.bundle_id,
                        "status": "SUPERSEDED",
                    },
                )
            )
        if candidate.crosswalk is not None:
            events.append(
                _event(
                    id_source=self._required("id_source"),
                    actor=actor,
                    event_type="TaxonomyCrosswalkPublished",
                    aggregate_type="TaxonomyCrosswalk",
                    aggregate_id=candidate.crosswalk.crosswalk_id,
                    aggregate_version=1,
                    now=now,
                    payload={
                        "crosswalk_id": candidate.crosswalk.crosswalk_id,
                        "source_bundle_id": candidate.crosswalk.source_bundle_id,
                        "target_bundle_id": candidate.crosswalk.target_bundle_id,
                        "manifest_sha256": taxonomy_artifact_sha256(candidate.crosswalk),
                    },
                )
            )
        return tuple(events)

    def _retire_transaction(
        self,
        *,
        actor: TaxonomyActorContext,
        command: RetireTaxonomyBundleCommand,
        receipt: Mapping[str, Any],
        now: datetime,
    ) -> TaxonomyCommandResult:
        keyring = self._required("receipt_keyring")
        identity = keyring.keyed_digest(receipt["active_identity_key_id"], receipt["identity_bytes"])
        payload_hash = keyring.keyed_digest(receipt["active_payload_key_id"], receipt["payload_bytes"])
        try:
            with self._required("uow_factory").begin() as uow:
                uow.lock("taxonomy.retire", (identity, command.bundle_id))
                current = uow.get("bundles", command.bundle_id)
                if not isinstance(current, TaxonomyBundle):
                    raise TaxonomyApplicationError("RESOURCE_NOT_FOUND")
                if current.status not in (TaxonomyBundleStatus.ACTIVE, TaxonomyBundleStatus.SUPERSEDED):
                    raise TaxonomyApplicationError("INVALID_STATE_TRANSITION")
                if current.aggregate_version != command.expected_bundle_version:
                    raise TaxonomyApplicationError("PRECONDITION_FAILED")
                pending = self._pending_receipt(
                    identity_key_id=receipt["active_identity_key_id"],
                    payload_key_id=receipt["active_payload_key_id"],
                    payload_hash=payload_hash,
                )
                uow.put("receipts", identity, pending)
                uow.checkpoint("receipt.pending")
                retired = current.retire(reason_code=command.reason_code, server_now=now)
                uow.put("bundles", retired.bundle_id, retired)
                uow.checkpoint("bundle.retire")
                if uow.get("current", "selector") == retired.bundle_id:
                    uow.put("current", "selector", None)
                uow.checkpoint("current.clear_if_current")
                audit_id = self._required("id_source").next_id("audit")
                uow.put(
                    "audits",
                    audit_id,
                    _audit(
                        actor=actor,
                        operation=self.operation,
                        target_id=retired.bundle_id,
                        result="RETIRED",
                        now=now,
                        evidence_sha256=hashlib.sha256(command.reason_code.encode()).hexdigest(),
                    ),
                )
                uow.checkpoint("audit.append")
                event = _event(
                    id_source=self._required("id_source"),
                    actor=actor,
                    event_type="TaxonomyBundleRetired",
                    aggregate_type="TaxonomyBundle",
                    aggregate_id=retired.bundle_id,
                    aggregate_version=retired.aggregate_version,
                    now=now,
                    payload={
                        "bundle_id": retired.bundle_id,
                        "status": "RETIRED",
                        "reason_code": command.reason_code,
                    },
                )
                self._required("event_validator").validate(event)
                uow.put("outbox", event["event_id"], event)
                uow.checkpoint("outbox.append")
                safe = self._safe_response(
                    target_id=retired.bundle_id,
                    target_status=retired.status.value,
                    aggregate_version=retired.aggregate_version,
                    http_status=200,
                    event_types=(event["event_type"],),
                    now=now,
                )
                uow.put("receipts", identity, {**pending, "status": "COMPLETED", "safe_response": safe})
                uow.checkpoint("receipt.complete")
                uow.checkpoint("commit")
                uow.commit()
            return self._result_from_safe(safe, replayed=False)
        except TaxonomyCommitOutcomeUnknownError as error:
            return self._recover_commit(
                identity=identity,
                identity_bytes=receipt["identity_bytes"],
                payload_bytes=receipt["payload_bytes"],
                target_collection="bundles",
                error=error,
            )

    def _recover_commit(
        self,
        *,
        identity: str,
        identity_bytes: bytes,
        payload_bytes: bytes,
        target_collection: str,
        error: Exception,
    ) -> TaxonomyCommandResult:
        reader = self._required("recovery_reader")
        row = reader.read_receipt(identity)
        if row is None:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error
        result = self._validate_receipt(
            identity=identity,
            row=row,
            identity_bytes=identity_bytes,
            payload_bytes=payload_bytes,
            replayed=True,
        )
        target = reader.read_fact(target_collection, result.target_id)
        if target is None:
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error
        if isinstance(target, TaxonomyBundle) and (
            target.status.value != result.target_status
            or target.aggregate_version != result.aggregate_version
        ):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE") from error
        return result

    def _apply_consumer(
        self,
        *,
        actor: TaxonomyActorContext,
        command: ApplyTaxonomyBundleToConsumerCommand,
        now: datetime,
    ) -> TaxonomyCommandResult:
        event = command.source_event
        self._required("source_event_validator").validate(actor=actor, event=event)
        event_digest = taxonomy_artifact_sha256(event)
        snapshot = self._required("uow_factory").store.snapshot()
        prior = snapshot.get("consumer_inbox", {}).get(event.event_id)
        if prior is not None:
            if not isinstance(prior, Mapping) or prior.get("event_sha256") != event_digest or prior.get("status") != "COMPLETED":
                raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
            return self._result_from_safe(prior.get("safe_response"), replayed=True)
        self._validate_source_event(command)
        release = self._required("consumer_catalog").read_exact_release(
            bundle_id=event.bundle_id,
            release_manifest_sha256=event.release_manifest_sha256,
        )
        self._validate_consumer_release(command, release)
        marker_key = f"{command.consumer_code}:{event.family_code}"
        with self._required("uow_factory").begin() as uow:
            uow.lock("taxonomy.consumer", (event.event_id, marker_key))
            if uow.get("consumer_inbox", event.event_id) is not None:
                raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
            uow.put(
                "consumer_inbox",
                event.event_id,
                {"event_sha256": event_digest, "status": "PENDING", "safe_response": None},
            )
            marker = {
                "consumer_code": command.consumer_code,
                "taxonomy_bundle_id": event.bundle_id,
                "release_manifest_sha256": event.release_manifest_sha256,
                "compatibility_level": release.validated.candidate.manifest.compatibility_level.value,
                "activated_at": _timestamp(now),
                "source_event_id": event.event_id,
                "aggregate_version": release.aggregate_version,
                "status": "ACTIVE",
            }
            uow.put("consumer_markers", marker_key, marker)
            safe = self._safe_response(
                target_id=event.bundle_id,
                target_status="ACTIVE",
                aggregate_version=release.aggregate_version,
                http_status=200,
                event_types=(),
                now=now,
            )
            uow.put(
                "consumer_inbox",
                event.event_id,
                {"event_sha256": event_digest, "status": "COMPLETED", "safe_response": safe},
            )
            uow.commit()
        return self._result_from_safe(safe, replayed=False)

    @staticmethod
    def _validate_source_event(command: ApplyTaxonomyBundleToConsumerCommand) -> None:
        event = command.source_event
        if (
            event.event_type != "TaxonomyBundlePublished"
            or event.schema_version != 1
            or event.aggregate_type != "TaxonomyBundle"
            or event.aggregate_id != event.bundle_id
            or event.status != "ACTIVE"
            or event.family_code != command.supported_family_code
        ):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")

    @staticmethod
    def _validate_consumer_release(
        command: ApplyTaxonomyBundleToConsumerCommand,
        release: Any,
    ) -> None:
        event = command.source_event
        if not isinstance(release, TaxonomyConsumerRelease) or release.status != "ACTIVE":
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        validated = release.validated
        if not isinstance(validated, ValidatedTaxonomyRelease):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        candidate = validated.candidate
        manifest = candidate.manifest
        try:
            major = int(manifest.semantic_version.split(".")[0])
        except (ValueError, IndexError):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        if (
            manifest.family_code != command.supported_family_code
            or manifest.schema_version != command.supported_schema_version
            or major not in command.supported_semantic_majors
        ):
            raise TaxonomyApplicationError("TAXONOMY_COMPATIBILITY_REJECTED")
        if (
            manifest.bundle_id != event.bundle_id
            or manifest.family_code != event.family_code
            or manifest.semantic_version != event.semantic_version
            or manifest.selector.selector_digest != event.selector_digest
            or taxonomy_artifact_sha256(manifest) != event.release_manifest_sha256
            or validated.release_manifest_sha256 != event.release_manifest_sha256
            or validated.node_manifest_sha256 != taxonomy_artifact_sha256(candidate.nodes)
            or validated.edge_manifest_sha256 != taxonomy_artifact_sha256(candidate.edges)
            or validated.label_manifest_sha256
            != tuple((item.locale, taxonomy_artifact_sha256(item)) for item in candidate.labels)
            or validated.crosswalk_manifest_sha256
            != (taxonomy_artifact_sha256(candidate.crosswalk) if candidate.crosswalk else None)
        ):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        values = {
            ("NODES", None): candidate.nodes,
            ("EDGES", None): candidate.edges,
            **{("LABELS", item.locale): item for item in candidate.labels},
        }
        if candidate.crosswalk is not None:
            values[("CROSSWALK", None)] = candidate.crosswalk
        if {(item.artifact_kind, item.locale) for item in manifest.artifacts} != set(values):
            raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")
        for descriptor in manifest.artifacts:
            artifact = values[(descriptor.artifact_kind, descriptor.locale)]
            if descriptor.sha256 != taxonomy_artifact_sha256(artifact):
                raise TaxonomyApplicationError("SERVICE_UNAVAILABLE")


class PublishTaxonomyBundleHandler(_TaxonomyHandler):
    operation = "PUBLISH_TAXONOMY_BUNDLE"


class RetireTaxonomyBundleHandler(_TaxonomyHandler):
    operation = "RETIRE_TAXONOMY_BUNDLE"


class ApplyTaxonomyBundleToConsumerHandler(_TaxonomyHandler):
    operation = "APPLY_TAXONOMY_BUNDLE_TO_CONSUMER"


def _public_value(value: Any, *, excluded: set[str] | None = None) -> Any:
    excluded = excluded or set()
    if is_dataclass(value):
        return {
            item.name: _public_value(getattr(value, item.name))
            for item in fields(value)
            if item.name not in excluded
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _timestamp(value)
    if isinstance(value, tuple):
        return [_public_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _public_value(item) for key, item in value.items()}
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _public_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _event(
    *,
    id_source: Any,
    actor: TaxonomyActorContext,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_version: int,
    now: datetime,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": id_source.next_id("event"),
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(now),
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "aggregate_version": aggregate_version,
        "actor_kind": actor.actor_kind.value,
        "actor_id": actor.actor_id,
        "original_actor_id": actor.original_actor_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": None,
        "payload": dict(payload),
    }


def _audit(
    *,
    actor: TaxonomyActorContext,
    operation: str,
    target_id: str,
    result: str,
    now: datetime,
    evidence_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operation": operation,
        "actor_kind": actor.actor_kind.value,
        "actor_id": actor.actor_id,
        "original_actor_id": actor.original_actor_id,
        "target_id": target_id,
        "result": result,
        "occurred_at": _timestamp(now),
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "evidence_sha256": evidence_sha256,
    }
