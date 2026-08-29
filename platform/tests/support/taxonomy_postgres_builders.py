"""Strict Taxonomy PostgreSQL requests and future real-database support."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any, Mapping, Optional

import psycopg

from desire_platform.taxonomy.adapters.postgres import (
    NoTaxonomyPostgresFaults,
    PsycopgTaxonomyUnitOfWorkFactory,
    TaxonomyPostgresApprovalEvidence,
    TaxonomyPostgresArtifactSet,
    TaxonomyPostgresConsumerCaptureRequest,
    TaxonomyPostgresExactReadRequest,
    TaxonomyPostgresExecutionScope,
    TaxonomyPostgresInboxRequest,
    TaxonomyPostgresOperation,
    TaxonomyPostgresPublishRequest,
    TaxonomyPostgresReceiptMaterial,
    TaxonomyPostgresRetireRequest,
    TaxonomyPostgresSignatureEvidence,
    TaxonomyPostgresTrustEvidence,
    TaxonomyPostgresWriteCheckpoint,
)
from desire_platform.taxonomy.domain import canonical_taxonomy_artifact_bytes
from tests.support.taxonomy_builders import (
    BUNDLE_ID,
    FAMILY,
    release_candidate,
    validated_release,
)


UTC_NOW = datetime.now(timezone.utc)
RAW_IDEMPOTENCY_KEY = "raw-taxonomy-postgres-key-sentinel-001"
WORKLOAD_CREDENTIAL = "taxonomy-workload-credential-secret-001"
SIGNING_SECRET = "taxonomy-signing-material-secret-001"
APPROVAL_COMMENT = "taxonomy-private-review-comment-sentinel"
ARTIFACT_LOCATOR = "s3://taxonomy-private-artifact-locator/sentinel"
RAW_SECRET_SENTINELS = (
    RAW_IDEMPOTENCY_KEY,
    WORKLOAD_CREDENTIAL,
    SIGNING_SECRET,
    APPROVAL_COMMENT,
    ARTIFACT_LOCATOR,
)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def execution_scope(
    operation: TaxonomyPostgresOperation,
    *,
    bundle_id: str = BUNDLE_ID,
    consumer_code: Optional[str] = None,
) -> TaxonomyPostgresExecutionScope:
    consumer = operation in (
        TaxonomyPostgresOperation.CAPTURE_CONSUMER,
        TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX,
    )
    return TaxonomyPostgresExecutionScope(
        operation=operation,
        workload_principal_id="taxonomy_workload_principal_0001",
        workload_credential_id=WORKLOAD_CREDENTIAL,
        workload_attestation_sha256=_digest("taxonomy-attestation-v1"),
        correlation_id="taxonomy_correlation_00000001",
        causation_id="taxonomy_causation_000000001",
        trace_id="taxonomy_trace_000000000001",
        selector_digest=_digest("taxonomy-selector-scope-v1"),
        bundle_id=bundle_id,
        consumer_code=(consumer_code or "MATCHING") if consumer else None,
        consumer_job_id="taxonomy_consumer_job_000001" if consumer else None,
        consumer_authorization_digest=(
            _digest("taxonomy-consumer-authorization-v1") if consumer else None
        ),
    )


def receipt_material(
    *, raw_key: str = RAW_IDEMPOTENCY_KEY
) -> TaxonomyPostgresReceiptMaterial:
    return TaxonomyPostgresReceiptMaterial(
        identity_key_id="taxonomy_identity_key_v2",
        payload_hash_key_id="taxonomy_payload_key_v2",
        identity_digest=_digest(f"identity:{raw_key}"),
        payload_digest=_digest("taxonomy-publish-payload-v1"),
        retained_until=UTC_NOW + timedelta(days=30),
    )


def artifact_set() -> TaxonomyPostgresArtifactSet:
    candidate = release_candidate()
    candidate = replace(
        candidate,
        manifest=replace(
            candidate.manifest,
            effective_at=UTC_NOW - timedelta(minutes=1),
        ),
    )
    validated = validated_release(candidate)
    artifacts = [
        ("RELEASE", None, canonical_taxonomy_artifact_bytes(candidate.manifest)),
        ("NODES", None, canonical_taxonomy_artifact_bytes(candidate.nodes)),
        ("EDGES", None, canonical_taxonomy_artifact_bytes(candidate.edges)),
    ]
    artifacts.extend(
        ("LABELS", labels.locale, canonical_taxonomy_artifact_bytes(labels))
        for labels in candidate.labels
    )
    return TaxonomyPostgresArtifactSet(validated, tuple(artifacts))


def publish_request(
    *, raw_key: str = RAW_IDEMPOTENCY_KEY
) -> TaxonomyPostgresPublishRequest:
    artifacts = artifact_set()
    manifest_digest = bytes.fromhex(
        artifacts.validated_release.release_manifest_sha256
    )
    signature = TaxonomyPostgresSignatureEvidence(
        signature_receipt_id="taxonomy_signature_receipt_001",
        trust_record_id="taxonomy_trust_record_000001",
        signing_key_id="taxonomy_signing_key_0000001",
        algorithm="ED25519",
        release_manifest_sha256=manifest_digest,
        verified_at=UTC_NOW - timedelta(minutes=1),
        valid_until=UTC_NOW + timedelta(minutes=10),
    )
    trust = TaxonomyPostgresTrustEvidence(
        trust_record_id=signature.trust_record_id,
        signing_key_id=signature.signing_key_id,
        trust_status="ACTIVE",
        allowed_algorithm="ED25519",
        release_manifest_sha256=manifest_digest,
        valid_until=UTC_NOW + timedelta(minutes=10),
    )
    approvals = (
        TaxonomyPostgresApprovalEvidence(
            approval_id="taxonomy_domain_approval_0001",
            duty_code="DOMAIN_STEWARD",
            reviewer_id="taxonomy_domain_reviewer_0001",
            approval_status="APPROVED",
            release_manifest_sha256=manifest_digest,
            golden_result_sha256=_digest("taxonomy-golden-result-v1"),
            approved_at=UTC_NOW - timedelta(minutes=2),
            valid_until=UTC_NOW + timedelta(minutes=10),
        ),
        TaxonomyPostgresApprovalEvidence(
            approval_id="taxonomy_safety_approval_0001",
            duty_code="SAFETY_DATA_STEWARD",
            reviewer_id="taxonomy_safety_reviewer_0001",
            approval_status="APPROVED",
            release_manifest_sha256=manifest_digest,
            golden_result_sha256=_digest("taxonomy-golden-result-v1"),
            approved_at=UTC_NOW - timedelta(minutes=2),
            valid_until=UTC_NOW + timedelta(minutes=10),
        ),
    )
    return TaxonomyPostgresPublishRequest(
        scope=execution_scope(TaxonomyPostgresOperation.PUBLISH),
        receipt=receipt_material(raw_key=raw_key),
        artifacts=artifacts,
        signature=signature,
        trust=trust,
        approvals=approvals,
        expected_current_bundle_id=None,
    )


def retire_request(
    *, raw_key: str = "raw-taxonomy-retire-postgres-key-001"
) -> TaxonomyPostgresRetireRequest:
    return TaxonomyPostgresRetireRequest(
        scope=execution_scope(TaxonomyPostgresOperation.RETIRE),
        receipt=receipt_material(raw_key=raw_key),
        bundle_id=BUNDLE_ID,
        expected_bundle_version=1,
        reason_code="SECURITY_REVIEW",
    )


def exact_read_request(
    operation: TaxonomyPostgresOperation,
) -> TaxonomyPostgresExactReadRequest:
    return TaxonomyPostgresExactReadRequest(
        scope=execution_scope(operation),
        bundle_id=BUNDLE_ID,
        code=(
            "DOMAIN.ENERGY"
            if operation
            in (
                TaxonomyPostgresOperation.READ_NODE,
                TaxonomyPostgresOperation.READ_EDGE_PAIR,
            )
            else None
        ),
        to_code=(
            "PROBLEM.EFFICIENCY"
            if operation is TaxonomyPostgresOperation.READ_EDGE_PAIR
            else None
        ),
        locale=(
            "en" if operation is TaxonomyPostgresOperation.READ_NODE else None
        ),
    )


def consumer_capture_request(
    *, supported_majors: tuple[int, ...] = (1,), consumer_code: str = "MATCHING"
) -> TaxonomyPostgresConsumerCaptureRequest:
    validated = artifact_set().validated_release
    return TaxonomyPostgresConsumerCaptureRequest(
        scope=execution_scope(
            TaxonomyPostgresOperation.CAPTURE_CONSUMER,
            consumer_code=consumer_code,
        ),
        bundle_id=BUNDLE_ID,
        release_manifest_sha256=bytes.fromhex(
            validated.release_manifest_sha256
        ),
        supported_family_code=FAMILY,
        supported_schema_version=1,
        supported_semantic_majors=supported_majors,
    )


def inbox_request() -> TaxonomyPostgresInboxRequest:
    return TaxonomyPostgresInboxRequest(
        scope=execution_scope(
            TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX,
            consumer_code="MATCHING",
        ),
        event_id="taxonomy_source_event_000001",
        event_sha256=_digest("taxonomy-source-event-envelope-v1"),
        source_schema_version=1,
    )


class RecordingSchemaValidator:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, Optional[str]]] = []

    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None:
        self.calls.append((deepcopy(value), schema_name))


class TrackingTaxonomyConnectionSource:
    """Real pool boundary with an explicit one-shot COMMIT-ack loss."""

    def __init__(
        self,
        conninfo: str,
        *,
        lose_first_commit_ack: bool = False,
        server_processed_commit: bool = True,
    ) -> None:
        self.conninfo = conninfo
        self.checkout_count = 0
        self.release_count = 0
        self.discard_count = 0
        self.connections: list[Any] = []
        self.available: list[Any] = []
        self.lose_first_commit_ack = lose_first_commit_ack
        self.server_processed_commit = server_processed_commit
        self.commit_ack_lost = False
        self.durable_commit_observed = False

    def checkout(self) -> Any:
        self.checkout_count += 1
        if self.available:
            return self.available.pop()
        connection = psycopg.connect(
            self.conninfo,
            autocommit=True,
            prepare_threshold=None,
        )
        wrapped = _CommitAckConnection(connection, self)
        self.connections.append(wrapped)
        return wrapped

    def release(self, connection: Any) -> None:
        self.release_count += 1
        self.available.append(connection)

    def discard(self, connection: Any) -> None:
        self.discard_count += 1
        connection.close()

    def close(self) -> None:
        for connection in self.connections:
            if not connection.closed:
                connection.close()


class _CommitAckConnection:
    def __init__(
        self, connection: Any, source: TrackingTaxonomyConnectionSource
    ) -> None:
        self._connection = connection
        self._source = source

    @property
    def closed(self) -> bool:
        return bool(self._connection.closed)

    def close(self) -> None:
        self._connection.close()

    def execute(self, query: Any, *args: Any, **kwargs: Any) -> Any:
        normalized = str(query).strip().upper()
        if (
            normalized == "COMMIT"
            and self._source.lose_first_commit_ack
            and not self._source.commit_ack_lost
        ):
            self._source.commit_ack_lost = True
            if self._source.server_processed_commit:
                self._connection.execute(query, *args, **kwargs)
                self._source.durable_commit_observed = True
            else:
                self._connection.execute("ROLLBACK")
            raise psycopg.OperationalError("simulated lost COMMIT acknowledgement")
        return self._connection.execute(query, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class RaiseAtTaxonomyCheckpoint(NoTaxonomyPostgresFaults):
    def __init__(self, target: TaxonomyPostgresWriteCheckpoint) -> None:
        self.target = target
        self.calls: list[tuple[TaxonomyPostgresWriteCheckpoint, int]] = []

    def before_write(
        self,
        checkpoint: TaxonomyPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        self.calls.append((checkpoint, ordinal))
        if checkpoint is self.target:
            from desire_platform.taxonomy.adapters.postgres import (
                TaxonomyPostgresDatabaseError,
            )

            raise TaxonomyPostgresDatabaseError("SERVICE_UNAVAILABLE")


def factory(
    source: TrackingTaxonomyConnectionSource,
    *, fault: Any = None,
) -> PsycopgTaxonomyUnitOfWorkFactory:
    return PsycopgTaxonomyUnitOfWorkFactory(
        connections=source,
        event_validator=RecordingSchemaValidator(),
        response_validator=RecordingSchemaValidator(),
        fault_injector=fault or NoTaxonomyPostgresFaults(),
    )


def taxonomy_database_snapshot(connection: Any) -> dict[str, Any]:
    schema_present = connection.execute(
        "SELECT pg_catalog.to_regnamespace('taxonomy') IS NOT NULL"
    ).fetchone()[0]
    if not schema_present:
        return {"schema_present": False}
    relations = (
        "bundles",
        "current_bundles",
        "release_artifacts",
        "nodes",
        "edges",
        "labels",
        "crosswalks",
        "signature_evidence",
        "trust_evidence",
        "review_approvals",
        "command_receipts",
        "audit_log",
        "outbox_events",
        "consumer_inbox",
    )
    result: dict[str, Any] = {"schema_present": True}
    for relation in relations:
        registered = connection.execute(
            "SELECT pg_catalog.to_regclass(%s)::text",
            (f"taxonomy.{relation}",),
        ).fetchone()[0]
        result[relation] = (
            connection.execute(
                f'SELECT count(*) FROM taxonomy."{relation}"'
            ).fetchone()[0]
            if registered is not None
            else None
        )
    return result


def reset_taxonomy_database(connection: Any) -> None:
    """Admin-only deterministic arrange reset; migration facts are retained."""

    connection.execute(
        "TRUNCATE TABLE "
        "taxonomy.consumer_inbox,taxonomy.consumer_authorizations,"
        "taxonomy.workload_authorizations,"
        "taxonomy.outbox_events,taxonomy.audit_log,taxonomy.command_receipts,"
        "taxonomy.review_approvals,taxonomy.trust_evidence,"
        "taxonomy.signature_evidence,taxonomy.crosswalks,taxonomy.labels,"
        "taxonomy.edges,taxonomy.code_registry,taxonomy.nodes,"
        "taxonomy.release_artifacts,taxonomy.current_bundles,taxonomy.bundles,"
        "taxonomy.selectors,taxonomy.families CASCADE"
    )


def seed_consumer_authorization(
    connection: Any,
    *,
    consumer_code: str = "MATCHING",
) -> None:
    request = consumer_capture_request(consumer_code=consumer_code)
    connection.execute(
        "INSERT INTO taxonomy.consumer_authorizations("
        "authorization_digest,consumer_code,consumer_job_id,"
        "workload_principal_id,bundle_id,release_manifest_sha256,"
        "credential_sha256,attestation_sha256,valid_until) "
        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            request.scope.consumer_authorization_digest,
            request.scope.consumer_code,
            request.scope.consumer_job_id,
            request.scope.workload_principal_id,
            request.bundle_id,
            request.release_manifest_sha256,
            _digest(request.scope.workload_credential_id),
            request.scope.workload_attestation_sha256,
            UTC_NOW + timedelta(hours=1),
        ),
    )


def seed_workload_authorizations(connection: Any) -> None:
    for request in (publish_request(), retire_request()):
        scope = request.scope
        connection.execute(
            "INSERT INTO taxonomy.workload_authorizations("
            "workload_principal_id,operation,credential_sha256,"
            "attestation_sha256,status,valid_until) "
            "VALUES(%s,%s,%s,%s,'ACTIVE',%s)",
            (
                scope.workload_principal_id,
                scope.operation.value,
                _digest(scope.workload_credential_id),
                scope.workload_attestation_sha256,
                UTC_NOW + timedelta(hours=1),
            ),
        )


@dataclass(frozen=True)
class ExpectedTaxonomyPublishFacts:
    status: str = "ACTIVE"
    aggregate_version: int = 1
    receipts: int = 1
    audits: int = 1
    outbox: int = 1
