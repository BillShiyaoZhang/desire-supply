"""Fixed PostgreSQL orchestration for the reviewed synthetic Taxonomy seed.

This is an offline seed program.  It uses the migration identities only for
the two narrowly granted provisioning/projection functions, while the actual
release publication, consumer capture, and inbox apply remain on the existing
Taxonomy fixed programs and their online roles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import re
from typing import Any, Mapping, Optional, Protocol
from uuid import UUID

from psycopg.pq import TransactionStatus

from ..creator_profile.adapters.postgres import PROFILE_POSTGRES_SCHEMA_HEAD_VERSION
from ..taxonomy.adapters.postgres import (
    PsycopgTaxonomyUnitOfWorkFactory,
    TaxonomyPostgresApprovalEvidence,
    TaxonomyPostgresArtifactSet,
    TaxonomyPostgresConsumerCaptureRequest,
    TaxonomyPostgresConsumerRelease,
    TaxonomyPostgresExecutionScope,
    TaxonomyPostgresInboxRequest,
    TaxonomyPostgresOperation,
    TaxonomyPostgresPublishRequest,
    TaxonomyPostgresReceiptMaterial,
    TaxonomyPostgresSignatureEvidence,
    TaxonomyPostgresTrustEvidence,
)
from ..taxonomy.application import TaxonomyBundlePublishedSourceEvent
from ..taxonomy.domain import taxonomy_artifact_sha256
from .synthetic_seed import (
    INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
    InternalSandboxSyntheticSeedPlan,
)
from .synthetic_taxonomy import internal_sandbox_taxonomy_artifact_bytes


_SEED_SHA256_HEX = INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256.hex()
_RELEASE_SHA256_HEX = (
    "edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af"
)
_GOLDEN_RESULT_SHA256 = bytes.fromhex(
    "803a8a5f800325491d8ccf946793573780307b0e1aeadd23ca6f6a03b97a98f3"
)
_EVIDENCE_VALID_FROM = datetime(2020, 1, 1, tzinfo=timezone.utc)
_TAXONOMY_PREFLIGHT = (
    "taxonomy_migration_runner",
    "taxonomy_migration_runner",
    18,
    "taxonomy",
    2,
    2,
    2,
    2,
)
_PROFILE_PREFLIGHT = (
    "profile_migration_runner",
    "profile_migration_runner",
    18,
    "profile",
    PROFILE_POSTGRES_SCHEMA_HEAD_VERSION,
    PROFILE_POSTGRES_SCHEMA_HEAD_VERSION,
    PROFILE_POSTGRES_SCHEMA_HEAD_VERSION,
    PROFILE_POSTGRES_SCHEMA_HEAD_VERSION,
)
_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,127}\Z")
_SHA256_TEXT = re.compile(r"[0-9a-f]{64}\Z")


class InternalSandboxSyntheticSeedPostgresError(RuntimeError):
    """Closed offline seed failure without database or secret detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class InternalSandboxSeedFaultInjector(Protocol):
    def before_commit(self, stage: str) -> None: ...


class NoInternalSandboxSeedFaults:
    def before_commit(self, stage: str) -> None:
        del stage


class InternalSandboxTaxonomyPostgresSchemaValidator:
    """Closed validator for the one publish response/event this seed emits."""

    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None:
        try:
            if not isinstance(value, Mapping):
                raise ValueError
            if schema_name == "TaxonomyCommandResponse":
                if (
                    set(value)
                    != {
                        "target_id",
                        "target_status",
                        "aggregate_version",
                        "entity_tag",
                    }
                    or value["target_id"]
                    != "50000000-0000-4000-8000-000000000001"
                    or value["target_status"] != "ACTIVE"
                    or value["aggregate_version"] != 1
                    or value["entity_tag"] != '"v1"'
                ):
                    raise ValueError
                return None
            if schema_name != "TaxonomyBundlePublishedEvent":
                raise ValueError
            envelope_keys = {
                "event_id",
                "event_type",
                "schema_version",
                "occurred_at",
                "aggregate_type",
                "aggregate_id",
                "aggregate_version",
                "actor_kind",
                "actor_id",
                "original_actor_id",
                "correlation_id",
                "causation_id",
                "trace_id",
                "organization_id",
                "payload",
            }
            payload = value.get("payload")
            if (
                set(value) != envelope_keys
                or _OPAQUE_ID.fullmatch(value.get("event_id", "")) is None
                or value.get("event_type") != "TaxonomyBundlePublished"
                or value.get("schema_version") != 1
                or not _utc_timestamp(value.get("occurred_at"))
                or value.get("aggregate_type") != "TaxonomyBundle"
                or value.get("aggregate_id")
                != "50000000-0000-4000-8000-000000000001"
                or value.get("aggregate_version") != 1
                or value.get("actor_kind") != "SYSTEM"
                or value.get("actor_id")
                != "internal_sandbox_taxonomy_seed_v1"
                or value.get("original_actor_id") is not None
                or _OPAQUE_ID.fullmatch(value.get("correlation_id", ""))
                is None
                or _OPAQUE_ID.fullmatch(value.get("causation_id", "")) is None
                or _OPAQUE_ID.fullmatch(value.get("trace_id", "")) is None
                or value.get("organization_id") is not None
                or not isinstance(payload, Mapping)
                or set(payload)
                != {
                    "bundle_id",
                    "family_code",
                    "semantic_version",
                    "selector_digest",
                    "release_manifest_sha256",
                    "effective_at",
                    "status",
                }
                or payload.get("bundle_id") != value.get("aggregate_id")
                or payload.get("family_code") != "PLATFORM_WORK_V1"
                or payload.get("semantic_version") != "1.0.0"
                or _SHA256_TEXT.fullmatch(payload.get("selector_digest", ""))
                is None
                or payload.get("selector_digest")
                != "5d98033bf58eb10d03ebc301c1be971e53e23810d7ab77f644b7ff916a610931"
                or payload.get("release_manifest_sha256")
                != _RELEASE_SHA256_HEX
                or not _utc_timestamp(payload.get("effective_at"))
                or payload.get("status") != "ACTIVE"
            ):
                raise ValueError
        except (AttributeError, TypeError, ValueError):
            raise InternalSandboxSyntheticSeedPostgresError(
                "INTERNAL_SANDBOX_SYNTHETIC_SEED_SCHEMA_INVALID"
            ) from None
        return None

    def __repr__(self) -> str:
        return "InternalSandboxTaxonomyPostgresSchemaValidator()"


@dataclass(frozen=True)
class InternalSandboxSeedRuntimeMaterial:
    deployment_mode: str
    workload_credential_id: str = field(repr=False)
    receipt_hmac_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.deployment_mode != "INTERNAL_SANDBOX":
            raise ValueError("synthetic seed deployment mode is invalid")
        if (
            not isinstance(self.workload_credential_id, str)
            or not 32 <= len(self.workload_credential_id) <= 256
            or self.workload_credential_id != self.workload_credential_id.strip()
            or any(ord(value) < 0x21 or ord(value) > 0x7E for value in self.workload_credential_id)
        ):
            raise ValueError("synthetic seed workload credential is invalid")
        if (
            type(self.receipt_hmac_key) is not bytes
            or len(self.receipt_hmac_key) != 32
            or not any(self.receipt_hmac_key)
        ):
            raise ValueError("synthetic seed receipt key is invalid")


@dataclass(frozen=True)
class InternalSandboxTaxonomySeedResult:
    taxonomy_bundle_id: str
    workload_authority_created: bool
    publication_replayed: bool
    consumer_authority_created: bool
    consumer_inbox_replayed: bool
    profile_marker_created: bool


class PsycopgInternalSandboxTaxonomyProvisioner:
    """Provision only the two exact seed authorization rows."""

    def __init__(
        self,
        *,
        connections: Any,
        fault_injector: InternalSandboxSeedFaultInjector = NoInternalSandboxSeedFaults(),
    ) -> None:
        _connection_source(connections)
        if not callable(getattr(fault_injector, "before_commit", None)):
            raise TypeError("synthetic seed fault injector is invalid")
        self._connections = connections
        self._fault_injector = fault_injector

    def provision_workload(
        self,
        *,
        plan: InternalSandboxSyntheticSeedPlan,
        runtime: InternalSandboxSeedRuntimeMaterial,
    ) -> bool:
        _exact_plan_and_runtime(plan, runtime)
        credential = _credential_sha256(runtime)
        return self._call(
            stage="PROVISION_WORKLOAD",
            sql=(
                "SELECT taxonomy_api.provision_internal_sandbox_workload_v1("
                "%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                runtime.deployment_mode,
                INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
                plan.taxonomy_workload_principal_id,
                "PublishTaxonomyBundle",
                credential,
                bytes.fromhex(plan.taxonomy_workload_attestation_sha256),
                plan.taxonomy_authority_valid_until,
            ),
        )

    def provision_profile_consumer(
        self,
        *,
        plan: InternalSandboxSyntheticSeedPlan,
        runtime: InternalSandboxSeedRuntimeMaterial,
    ) -> bool:
        _exact_plan_and_runtime(plan, runtime)
        credential = _credential_sha256(runtime)
        return self._call(
            stage="PROVISION_PROFILE_CONSUMER",
            sql=(
                "SELECT taxonomy_api."
                "provision_internal_sandbox_profile_consumer_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                runtime.deployment_mode,
                INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
                bytes.fromhex(plan.taxonomy_consumer_authorization_digest),
                plan.taxonomy_profile_consumer_code,
                plan.taxonomy_profile_consumer_job_id,
                plan.taxonomy_workload_principal_id,
                plan.taxonomy_bundle_id,
                bytes.fromhex(plan.taxonomy_release.release_manifest_sha256),
                credential,
                bytes.fromhex(plan.taxonomy_workload_attestation_sha256),
                plan.taxonomy_authority_valid_until,
            ),
        )

    def _call(self, *, stage: str, sql: str, parameters: tuple[Any, ...]) -> bool:
        return _fixed_write(
            connections=self._connections,
            preflight=_TAXONOMY_PREFLIGHT,
            compatibility_sql=(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000,"
                "component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version "
                "FROM taxonomy.schema_compatibility"
            ),
            stage=stage,
            sql=sql,
            parameters=parameters,
            fault_injector=self._fault_injector,
        )

    def __repr__(self) -> str:
        return "PsycopgInternalSandboxTaxonomyProvisioner(connections=<managed>)"


class PsycopgInternalSandboxProfileTaxonomyProjector:
    """Apply one captured release to the Profile marker projection."""

    def __init__(
        self,
        *,
        connections: Any,
        fault_injector: InternalSandboxSeedFaultInjector = NoInternalSandboxSeedFaults(),
    ) -> None:
        _connection_source(connections)
        if not callable(getattr(fault_injector, "before_commit", None)):
            raise TypeError("synthetic seed fault injector is invalid")
        self._connections = connections
        self._fault_injector = fault_injector

    def apply(
        self,
        *,
        plan: InternalSandboxSyntheticSeedPlan,
        runtime: InternalSandboxSeedRuntimeMaterial,
        event: TaxonomyBundlePublishedSourceEvent,
        release: TaxonomyPostgresConsumerRelease,
    ) -> bool:
        _exact_plan_and_runtime(plan, runtime)
        _exact_release(plan, release)
        _exact_event(plan, event, release)
        event_sha256 = bytes.fromhex(taxonomy_artifact_sha256(event))
        return _fixed_write(
            connections=self._connections,
            preflight=_PROFILE_PREFLIGHT,
            compatibility_sql=(
                "SELECT session_user,current_user,"
                "current_setting('server_version_num')::integer/10000,"
                "component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version "
                "FROM profile.schema_compatibility"
            ),
            stage="PROJECT_PROFILE_TAXONOMY",
            sql=(
                "SELECT profile_api."
                "project_internal_sandbox_taxonomy_marker_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s)"
            ),
            parameters=(
                runtime.deployment_mode,
                INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
                event.event_id,
                event_sha256,
                UUID(plan.taxonomy_bundle_id),
                bytes.fromhex(plan.taxonomy_release.release_manifest_sha256),
                release.aggregate_version,
                release.captured_at,
            ),
            fault_injector=self._fault_injector,
        )

    def __repr__(self) -> str:
        return (
            "PsycopgInternalSandboxProfileTaxonomyProjector("
            "connections=<managed>)"
        )


class PostgresInternalSandboxTaxonomySeedOrchestrator:
    """Run provision -> publish -> capture -> inbox -> Profile apply."""

    def __init__(
        self,
        *,
        provisioner: PsycopgInternalSandboxTaxonomyProvisioner,
        publisher: PsycopgTaxonomyUnitOfWorkFactory,
        consumer: PsycopgTaxonomyUnitOfWorkFactory,
        profile_projector: PsycopgInternalSandboxProfileTaxonomyProjector,
    ) -> None:
        if not isinstance(
            provisioner, PsycopgInternalSandboxTaxonomyProvisioner
        ) or not isinstance(
            profile_projector, PsycopgInternalSandboxProfileTaxonomyProjector
        ):
            raise TypeError("synthetic seed PostgreSQL ports are unavailable")
        if not isinstance(publisher, PsycopgTaxonomyUnitOfWorkFactory) or not isinstance(
            consumer, PsycopgTaxonomyUnitOfWorkFactory
        ):
            raise TypeError("synthetic seed Taxonomy programs are unavailable")
        if publisher is consumer:
            raise ValueError("publisher and consumer programs cannot be aliased")
        self._provisioner = provisioner
        self._publisher = publisher
        self._consumer = consumer
        self._profile_projector = profile_projector

    def run(
        self,
        *,
        plan: InternalSandboxSyntheticSeedPlan,
        runtime: InternalSandboxSeedRuntimeMaterial,
    ) -> InternalSandboxTaxonomySeedResult:
        try:
            _exact_plan_and_runtime(plan, runtime)
            plan.require_executable()
            workload_created = self._provisioner.provision_workload(
                plan=plan, runtime=runtime
            )
            publish_request = _publish_request(plan, runtime)
            published = self._publisher.publish(publish_request)
            if (
                published.target_id != plan.taxonomy_bundle_id
                or published.target_status != "ACTIVE"
                or published.aggregate_version != 1
                or tuple(published.event_types)
                not in (("TaxonomyBundlePublished",), ())
            ):
                _blocked()

            consumer_created = self._provisioner.provision_profile_consumer(
                plan=plan,
                runtime=runtime,
            )
            capture_request = _capture_request(plan, runtime)
            release = self._consumer.capture_consumer_release(capture_request)
            _exact_release(plan, release)
            event = _source_event(plan, publish_request, published.completed_at)
            inbox = self._consumer.claim_consumer_inbox(
                TaxonomyPostgresInboxRequest(
                    scope=capture_request.scope.__class__(
                        operation=TaxonomyPostgresOperation.CLAIM_CONSUMER_INBOX,
                        workload_principal_id=(
                            capture_request.scope.workload_principal_id
                        ),
                        workload_credential_id=(
                            capture_request.scope.workload_credential_id
                        ),
                        workload_attestation_sha256=(
                            capture_request.scope.workload_attestation_sha256
                        ),
                        correlation_id=capture_request.scope.correlation_id,
                        causation_id=capture_request.scope.causation_id,
                        trace_id=capture_request.scope.trace_id,
                        selector_digest=capture_request.scope.selector_digest,
                        bundle_id=capture_request.scope.bundle_id,
                        consumer_code=capture_request.scope.consumer_code,
                        consumer_job_id=capture_request.scope.consumer_job_id,
                        consumer_authorization_digest=(
                            capture_request.scope.consumer_authorization_digest
                        ),
                    ),
                    event_id=event.event_id,
                    event_sha256=bytes.fromhex(taxonomy_artifact_sha256(event)),
                    source_schema_version=1,
                )
            )
            if (
                inbox.target_id != event.event_id
                or inbox.target_status != "COMPLETED"
                or inbox.aggregate_version != 1
            ):
                _blocked()
            marker_created = self._profile_projector.apply(
                plan=plan,
                runtime=runtime,
                event=event,
                release=release,
            )
            return InternalSandboxTaxonomySeedResult(
                taxonomy_bundle_id=plan.taxonomy_bundle_id,
                workload_authority_created=workload_created,
                publication_replayed=published.replayed,
                consumer_authority_created=consumer_created,
                consumer_inbox_replayed=inbox.replayed,
                profile_marker_created=marker_created,
            )
        except InternalSandboxSyntheticSeedPostgresError:
            raise
        except BaseException:
            _blocked()
        raise AssertionError("unreachable")

    def __repr__(self) -> str:
        return "PostgresInternalSandboxTaxonomySeedOrchestrator(ports=<managed>)"


def _publish_request(
    plan: InternalSandboxSyntheticSeedPlan,
    runtime: InternalSandboxSeedRuntimeMaterial,
) -> TaxonomyPostgresPublishRequest:
    release = plan.taxonomy_release
    manifest_digest = bytes.fromhex(release.release_manifest_sha256)
    receipt = TaxonomyPostgresReceiptMaterial(
        identity_key_id="internal_sandbox_seed_identity_v1",
        payload_hash_key_id="internal_sandbox_seed_payload_v1",
        identity_digest=_receipt_digest(
            runtime, b"taxonomy-publish-identity-v1"
        ),
        payload_digest=_receipt_digest(
            runtime,
            b"taxonomy-publish-payload-v1:" + manifest_digest,
        ),
        retained_until=plan.taxonomy_authority_valid_until,
    )
    scope = _scope(
        plan,
        runtime,
        operation=TaxonomyPostgresOperation.PUBLISH,
        consumer=False,
    )
    signature = TaxonomyPostgresSignatureEvidence(
        signature_receipt_id="internal_sandbox_signature_receipt_v1",
        trust_record_id="internal_sandbox_trust_record_v1",
        signing_key_id="internal_sandbox_signing_key_v1",
        algorithm="ED25519",
        release_manifest_sha256=manifest_digest,
        verified_at=_EVIDENCE_VALID_FROM,
        valid_until=plan.taxonomy_authority_valid_until,
    )
    trust = TaxonomyPostgresTrustEvidence(
        trust_record_id=signature.trust_record_id,
        signing_key_id=signature.signing_key_id,
        trust_status="ACTIVE",
        allowed_algorithm="ED25519",
        release_manifest_sha256=manifest_digest,
        valid_until=plan.taxonomy_authority_valid_until,
    )
    approvals = (
        TaxonomyPostgresApprovalEvidence(
            approval_id="internal_sandbox_domain_approval_v1",
            duty_code="DOMAIN_STEWARD",
            reviewer_id="internal_sandbox_domain_reviewer_v1",
            approval_status="APPROVED",
            release_manifest_sha256=manifest_digest,
            golden_result_sha256=_GOLDEN_RESULT_SHA256,
            approved_at=_EVIDENCE_VALID_FROM,
            valid_until=plan.taxonomy_authority_valid_until,
        ),
        TaxonomyPostgresApprovalEvidence(
            approval_id="internal_sandbox_safety_approval_v1",
            duty_code="SAFETY_DATA_STEWARD",
            reviewer_id="internal_sandbox_safety_reviewer_v1",
            approval_status="APPROVED",
            release_manifest_sha256=manifest_digest,
            golden_result_sha256=_GOLDEN_RESULT_SHA256,
            approved_at=_EVIDENCE_VALID_FROM,
            valid_until=plan.taxonomy_authority_valid_until,
        ),
    )
    return TaxonomyPostgresPublishRequest(
        scope=scope,
        receipt=receipt,
        artifacts=TaxonomyPostgresArtifactSet(
            validated_release=release,
            canonical_bytes_by_kind=(
                internal_sandbox_taxonomy_artifact_bytes(release)
            ),
        ),
        signature=signature,
        trust=trust,
        approvals=approvals,
        expected_current_bundle_id=None,
    )


def _capture_request(
    plan: InternalSandboxSyntheticSeedPlan,
    runtime: InternalSandboxSeedRuntimeMaterial,
) -> TaxonomyPostgresConsumerCaptureRequest:
    return TaxonomyPostgresConsumerCaptureRequest(
        scope=_scope(
            plan,
            runtime,
            operation=TaxonomyPostgresOperation.CAPTURE_CONSUMER,
            consumer=True,
        ),
        bundle_id=plan.taxonomy_bundle_id,
        release_manifest_sha256=bytes.fromhex(
            plan.taxonomy_release.release_manifest_sha256
        ),
        supported_family_code=plan.taxonomy_family_code,
        supported_schema_version=1,
        supported_semantic_majors=(1,),
    )


def _scope(
    plan: InternalSandboxSyntheticSeedPlan,
    runtime: InternalSandboxSeedRuntimeMaterial,
    *,
    operation: TaxonomyPostgresOperation,
    consumer: bool,
) -> TaxonomyPostgresExecutionScope:
    return TaxonomyPostgresExecutionScope(
        operation=operation,
        workload_principal_id=plan.taxonomy_workload_principal_id,
        workload_credential_id=runtime.workload_credential_id,
        workload_attestation_sha256=bytes.fromhex(
            plan.taxonomy_workload_attestation_sha256
        ),
        correlation_id="internal_sandbox_seed_correlation_v1",
        causation_id="internal_sandbox_seed_causation_v1",
        trace_id="internal_sandbox_seed_trace_v1",
        selector_digest=bytes.fromhex(plan.taxonomy_release.selector_digest),
        bundle_id=plan.taxonomy_bundle_id,
        consumer_code=plan.taxonomy_profile_consumer_code if consumer else None,
        consumer_job_id=plan.taxonomy_profile_consumer_job_id if consumer else None,
        consumer_authorization_digest=(
            bytes.fromhex(plan.taxonomy_consumer_authorization_digest)
            if consumer
            else None
        ),
    )


def _source_event(
    plan: InternalSandboxSyntheticSeedPlan,
    request: TaxonomyPostgresPublishRequest,
    completed_at: datetime,
) -> TaxonomyBundlePublishedSourceEvent:
    event_type = "TaxonomyBundlePublished"
    first_digest = hashlib.sha256(
        request.receipt.identity_digest
        + event_type.encode("ascii")
        + plan.taxonomy_bundle_id.encode("utf-8")
    ).digest()
    event_id = "taxonomy_event_" + hashlib.sha256(
        b"taxonomy_event" + first_digest
    ).hexdigest()[:32]
    manifest = plan.taxonomy_release.candidate.manifest
    return TaxonomyBundlePublishedSourceEvent(
        event_id=event_id,
        event_type=event_type,
        schema_version=1,
        aggregate_type="TaxonomyBundle",
        aggregate_id=plan.taxonomy_bundle_id,
        aggregate_version=1,
        occurred_at=completed_at,
        bundle_id=plan.taxonomy_bundle_id,
        family_code=plan.taxonomy_family_code,
        semantic_version=plan.taxonomy_semantic_version,
        selector_digest=manifest.selector.selector_digest,
        release_manifest_sha256=plan.taxonomy_release.release_manifest_sha256,
        effective_at=manifest.effective_at,
        status="ACTIVE",
    )


def _exact_event(
    plan: InternalSandboxSyntheticSeedPlan,
    event: Any,
    release: TaxonomyPostgresConsumerRelease,
) -> None:
    if (
        not isinstance(event, TaxonomyBundlePublishedSourceEvent)
        or event.event_type != "TaxonomyBundlePublished"
        or event.schema_version != 1
        or event.aggregate_type != "TaxonomyBundle"
        or event.aggregate_id != plan.taxonomy_bundle_id
        or event.aggregate_version != release.aggregate_version
        or event.bundle_id != plan.taxonomy_bundle_id
        or event.family_code != plan.taxonomy_family_code
        or event.semantic_version != plan.taxonomy_semantic_version
        or event.selector_digest != plan.taxonomy_release.selector_digest
        or event.release_manifest_sha256
        != plan.taxonomy_release.release_manifest_sha256
        or event.effective_at
        != plan.taxonomy_release.candidate.manifest.effective_at
        or event.status != "ACTIVE"
    ):
        _blocked()


def _exact_release(
    plan: InternalSandboxSyntheticSeedPlan,
    release: Any,
) -> None:
    if (
        not isinstance(release, TaxonomyPostgresConsumerRelease)
        or release.bundle_id != plan.taxonomy_bundle_id
        or release.semantic_version != plan.taxonomy_semantic_version
        or release.status != "ACTIVE"
        or release.aggregate_version != 1
        or release.selector_digest
        != bytes.fromhex(plan.taxonomy_release.selector_digest)
        or release.release_manifest_sha256
        != bytes.fromhex(plan.taxonomy_release.release_manifest_sha256)
        or release.release != plan.taxonomy_release.candidate
        or not isinstance(release.captured_at, datetime)
        or release.captured_at.tzinfo is None
    ):
        _blocked()


def _exact_plan_and_runtime(plan: Any, runtime: Any) -> None:
    if (
        not isinstance(plan, InternalSandboxSyntheticSeedPlan)
        or plan.manifest_sha256 != _SEED_SHA256_HEX
        or plan.taxonomy_release.release_manifest_sha256 != _RELEASE_SHA256_HEX
        or not isinstance(runtime, InternalSandboxSeedRuntimeMaterial)
        or runtime.deployment_mode != "INTERNAL_SANDBOX"
    ):
        _blocked()


def _credential_sha256(runtime: InternalSandboxSeedRuntimeMaterial) -> bytes:
    return hashlib.sha256(runtime.workload_credential_id.encode("ascii")).digest()


def _receipt_digest(
    runtime: InternalSandboxSeedRuntimeMaterial,
    value: bytes,
) -> bytes:
    return hmac.new(
        runtime.receipt_hmac_key,
        INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256 + b":" + value,
        hashlib.sha256,
    ).digest()


def _connection_source(value: Any) -> None:
    if not all(
        callable(getattr(value, name, None))
        for name in ("checkout", "release", "discard")
    ):
        raise TypeError("synthetic seed connection source is unavailable")


def _fixed_write(
    *,
    connections: Any,
    preflight: tuple[Any, ...],
    compatibility_sql: str,
    stage: str,
    sql: str,
    parameters: tuple[Any, ...],
    fault_injector: InternalSandboxSeedFaultInjector,
) -> bool:
    connection: Any = None
    transaction = False
    released = False
    try:
        connection = connections.checkout()
        _reset(connection)
        if connection.execute(compatibility_sql).fetchone() != preflight:
            raise RuntimeError("synthetic seed database preflight drifted")
        connection.execute("BEGIN ISOLATION LEVEL SERIALIZABLE")
        transaction = True
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute("SET LOCAL lock_timeout = '5000ms'")
        connection.execute("SET LOCAL statement_timeout = '30000ms'")
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '15000ms'"
        )
        for name, value in (
            ("app.deployment_mode", "INTERNAL_SANDBOX"),
            ("app.seed_manifest_sha256", _SEED_SHA256_HEX),
            ("app.seed_operation", stage),
        ):
            if connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            ).fetchone() != (value,):
                raise RuntimeError("synthetic seed database scope drifted")
        row = connection.execute(sql, parameters).fetchone()
        if not isinstance(row, tuple) or len(row) != 1 or type(row[0]) is not bool:
            raise RuntimeError("synthetic seed fixed program drifted")
        fault_injector.before_commit(stage)
        connection.execute("COMMIT")
        transaction = False
        _reset(connection)
        connections.release(connection)
        released = True
        return row[0]
    except BaseException:
        if connection is not None:
            if transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            try:
                _reset(connection)
            except BaseException:
                pass
            if not released:
                try:
                    connections.discard(connection)
                except BaseException:
                    pass
        raise InternalSandboxSyntheticSeedPostgresError(
            "INTERNAL_SANDBOX_SYNTHETIC_SEED_POSTGRES_UNAVAILABLE"
        ) from None


def _reset(connection: Any) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or getattr(getattr(connection, "info", None), "transaction_status", None)
        != TransactionStatus.IDLE
    ):
        raise RuntimeError("synthetic seed database connection is not idle")
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(
        parsed
    )


def _blocked() -> None:
    raise InternalSandboxSyntheticSeedPostgresError(
        "INTERNAL_SANDBOX_SYNTHETIC_SEED_POSTGRES_UNAVAILABLE"
    ) from None


__all__ = [
    "InternalSandboxSeedRuntimeMaterial",
    "InternalSandboxSyntheticSeedPostgresError",
    "InternalSandboxTaxonomyPostgresSchemaValidator",
    "InternalSandboxTaxonomySeedResult",
    "NoInternalSandboxSeedFaults",
    "PostgresInternalSandboxTaxonomySeedOrchestrator",
    "PsycopgInternalSandboxProfileTaxonomyProjector",
    "PsycopgInternalSandboxTaxonomyProvisioner",
]
