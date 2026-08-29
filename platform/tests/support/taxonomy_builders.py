"""Strict secret-safe Taxonomy fixtures with a real copy-on-write Memory UoW."""

from __future__ import annotations

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import asdict, dataclass, is_dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional

from desire_platform.taxonomy.application import (
    ApplyTaxonomyBundleToConsumerCommand,
    PublishTaxonomyBundleCommand,
    RetireTaxonomyBundleCommand,
    TaxonomyActorContext,
    TaxonomyActorKind,
    TaxonomyArtifactReference,
    TaxonomyBundlePublishedSourceEvent,
)
from desire_platform.taxonomy.domain import (
    TaxonomyArtifactDescriptor,
    TaxonomyAttribute,
    TaxonomyBundle,
    TaxonomyBundleStatus,
    TaxonomyCodeMeaning,
    TaxonomyCompatibilityLevel,
    TaxonomyCrosswalkArtifact,
    TaxonomyCrosswalkMapping,
    TaxonomyEdge,
    TaxonomyEdgeKind,
    TaxonomyEdgesArtifact,
    TaxonomyLabel,
    TaxonomyLabelsArtifact,
    TaxonomyMappingKind,
    TaxonomyNode,
    TaxonomyNodeKind,
    TaxonomyNodeStatus,
    TaxonomyNodesArtifact,
    TaxonomyReleaseCandidate,
    TaxonomyReleaseManifest,
    TaxonomySelector,
    ValidatedTaxonomyRelease,
    validate_taxonomy_release,
)
from desire_platform.taxonomy.ports import (
    TaxonomyApprovalEvidence,
    TaxonomyArtifactSet,
    TaxonomyArtifactUnavailableError,
    TaxonomyCommitOutcomeUnknownError,
    TaxonomyConsumerRelease,
    TaxonomySignatureEvidence,
    TaxonomyStorageUnavailableError,
    TaxonomyTrustEvidence,
    TaxonomyWorkloadAuthority,
)


NOW = datetime(2035, 1, 1, tzinfo=timezone.utc)
BUNDLE_ID = "taxonomy_bundle_0000001"
SUCCESSOR_ID = "taxonomy_bundle_0000002"
FAMILY = "PLATFORM_WORK_V1"

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


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return {
            key: _json_value(child)
            for key, child in asdict(value).items()
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, tuple):
        return [_json_value(child) for child in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    return value


def fixture_canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def fixture_sha256(value: Any) -> str:
    return hashlib.sha256(fixture_canonical_bytes(value)).hexdigest()


def _selector(
    *, semantic_major: int = 1, locales: tuple[str, ...] = ("en", "zh-CN")
) -> TaxonomySelector:
    locale_digest = fixture_sha256(locales)
    consumer_digest = fixture_sha256(("DEMAND", "MATCHING", "PROFILE"))
    surface = {
        "canonicalization_version": "taxonomy-selector-json-v1",
        "jurisdiction_code": "JURISDICTION.CN",
        "locale_set_digest": locale_digest,
        "semantic_major": semantic_major,
        "intended_consumer_set_digest": consumer_digest,
    }
    return TaxonomySelector(
        jurisdiction_code="JURISDICTION.CN",
        locale_set_digest=locale_digest,
        semantic_major=semantic_major,
        intended_consumer_set_digest=consumer_digest,
        selector_digest=fixture_sha256(surface),
    )


def _nodes(
    bundle_id: str = BUNDLE_ID, *, include_task: bool = False
) -> TaxonomyNodesArtifact:
    values = [
        TaxonomyNode(
            code="DATA_SENSITIVITY.INTERNAL",
            kind=TaxonomyNodeKind.DATA_SENSITIVITY,
            definition_code="DEFINITION.DATA_SENSITIVITY.INTERNAL",
            status=TaxonomyNodeStatus.ACTIVE,
            introduced_in_bundle_id=BUNDLE_ID,
            deprecated_reason_code=None,
            replacement_codes=(),
            attributes=(
                TaxonomyAttribute(
                    "classification_rank", "INTEGER", None, 2
                ),
            ),
        ),
        TaxonomyNode(
            code="DOMAIN.ENERGY",
            kind=TaxonomyNodeKind.DOMAIN,
            definition_code="DEFINITION.DOMAIN.ENERGY",
            status=TaxonomyNodeStatus.ACTIVE,
            introduced_in_bundle_id=BUNDLE_ID,
            deprecated_reason_code=None,
            replacement_codes=(),
            attributes=(),
        ),
        TaxonomyNode(
            code="PROBLEM.EFFICIENCY",
            kind=TaxonomyNodeKind.PROBLEM_TYPE,
            definition_code="DEFINITION.PROBLEM.EFFICIENCY",
            status=TaxonomyNodeStatus.ACTIVE,
            introduced_in_bundle_id=BUNDLE_ID,
            deprecated_reason_code=None,
            replacement_codes=(),
            attributes=(),
        ),
    ]
    if include_task:
        values.append(
            TaxonomyNode(
                code="TASK.AUDIT",
                kind=TaxonomyNodeKind.TASK,
                definition_code="DEFINITION.TASK.AUDIT",
                status=TaxonomyNodeStatus.ACTIVE,
                introduced_in_bundle_id=bundle_id,
                deprecated_reason_code=None,
                replacement_codes=(),
                attributes=(),
            )
        )
    values.sort(key=lambda item: (item.kind.value.encode(), item.code.encode()))
    return TaxonomyNodesArtifact(
        1, "taxonomy-nodes-json-v1", bundle_id, FAMILY, tuple(values)
    )


def _edges(bundle_id: str = BUNDLE_ID) -> TaxonomyEdgesArtifact:
    return TaxonomyEdgesArtifact(
        1,
        "taxonomy-edges-json-v1",
        bundle_id,
        FAMILY,
        (
            TaxonomyEdge(
                TaxonomyEdgeKind.RELATED_TO,
                "DOMAIN.ENERGY",
                "PROBLEM.EFFICIENCY",
                1,
            ),
        ),
    )


def _labels(
    bundle_id: str = BUNDLE_ID,
    *,
    locale: str,
    include_task: bool = False,
) -> TaxonomyLabelsArtifact:
    translations = {
        "en": ("Internal", "Energy", "Efficiency", "Audit"),
        "zh-CN": ("内部", "能源", "效率", "审计"),
    }[locale]
    values = [
        TaxonomyLabel(
            "DATA_SENSITIVITY.INTERNAL", translations[0], None, translations[0]
        ),
        TaxonomyLabel("DOMAIN.ENERGY", translations[1], None, translations[1]),
        TaxonomyLabel(
            "PROBLEM.EFFICIENCY", translations[2], None, translations[2]
        ),
    ]
    if include_task:
        values.append(TaxonomyLabel("TASK.AUDIT", translations[3], None, translations[3]))
    values.sort(key=lambda item: item.code.encode())
    return TaxonomyLabelsArtifact(
        1,
        "taxonomy-labels-json-v1",
        bundle_id,
        FAMILY,
        locale,
        tuple(values),
    )


def release_candidate(*, successor: bool = False) -> TaxonomyReleaseCandidate:
    bundle_id = SUCCESSOR_ID if successor else BUNDLE_ID
    nodes_value = _nodes(bundle_id, include_task=successor)
    edges_value = _edges(bundle_id)
    labels_values = tuple(
        _labels(bundle_id, locale=locale, include_task=successor)
        for locale in ("en", "zh-CN")
    )
    crosswalk_value = None
    if successor:
        crosswalk_value = TaxonomyCrosswalkArtifact(
            1,
            "taxonomy-crosswalk-json-v1",
            "taxonomy_crosswalk_00001",
            BUNDLE_ID,
            SUCCESSOR_ID,
            TaxonomyCompatibilityLevel.MINOR_COMPATIBLE,
            (
                TaxonomyCrosswalkMapping(
                    "DOMAIN.ENERGY",
                    ("DOMAIN.ENERGY",),
                    TaxonomyMappingKind.EXACT,
                    "REVIEWED_HIGH",
                    "UNCHANGED_DEFINITION",
                ),
            ),
        )
    descriptors = [
        TaxonomyArtifactDescriptor(
            "CROSSWALK",
            "taxonomy-crosswalk-v1",
            None,
            fixture_sha256(crosswalk_value),
            len(crosswalk_value.mappings),
        )
    ] if crosswalk_value is not None else []
    descriptors.extend(
        (
            TaxonomyArtifactDescriptor(
                "EDGES",
                "taxonomy-edges-v1",
                None,
                fixture_sha256(edges_value),
                len(edges_value.edges),
            ),
            *(
                TaxonomyArtifactDescriptor(
                    "LABELS",
                    "taxonomy-labels-v1",
                    value.locale,
                    fixture_sha256(value),
                    len(value.labels),
                )
                for value in labels_values
            ),
            TaxonomyArtifactDescriptor(
                "NODES",
                "taxonomy-nodes-v1",
                None,
                fixture_sha256(nodes_value),
                len(nodes_value.nodes),
            ),
        )
    )
    descriptors.sort(key=lambda item: (item.artifact_kind.encode(), (item.locale or "").encode()))
    manifest = TaxonomyReleaseManifest(
        schema_version=1,
        canonicalization_version="taxonomy-release-json-v1",
        bundle_id=bundle_id,
        family_code=FAMILY,
        semantic_version="1.1.0" if successor else "1.0.0",
        selector=_selector(),
        compatibility_level=(
            TaxonomyCompatibilityLevel.MINOR_COMPATIBLE
            if successor
            else TaxonomyCompatibilityLevel.INITIAL
        ),
        predecessor_bundle_id=BUNDLE_ID if successor else None,
        effective_at=NOW,
        effective_until=None,
        artifacts=tuple(descriptors),
    )
    return TaxonomyReleaseCandidate(
        manifest, nodes_value, edges_value, labels_values, crosswalk_value
    )


def validated_release(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
) -> ValidatedTaxonomyRelease:
    value = candidate or release_candidate()
    labels_hash = tuple(
        (artifact.locale, fixture_sha256(artifact)) for artifact in value.labels
    )
    return ValidatedTaxonomyRelease(
        candidate=value,
        release_manifest_sha256=fixture_sha256(value.manifest),
        selector_digest=value.manifest.selector.selector_digest,
        node_manifest_sha256=fixture_sha256(value.nodes),
        edge_manifest_sha256=fixture_sha256(value.edges),
        label_manifest_sha256=labels_hash,
        crosswalk_manifest_sha256=(
            fixture_sha256(value.crosswalk) if value.crosswalk else None
        ),
        canonical_release_bytes=fixture_canonical_bytes(value.manifest),
    )


def rebind_artifact_descriptors(
    candidate: TaxonomyReleaseCandidate,
) -> TaxonomyReleaseCandidate:
    values: dict[tuple[str, Optional[str]], Any] = {
        ("NODES", None): candidate.nodes,
        ("EDGES", None): candidate.edges,
    }
    values.update({("LABELS", item.locale): item for item in candidate.labels})
    if candidate.crosswalk is not None:
        values[("CROSSWALK", None)] = candidate.crosswalk
    descriptors = []
    for descriptor in candidate.manifest.artifacts:
        value = values[(descriptor.artifact_kind, descriptor.locale)]
        if descriptor.artifact_kind == "NODES":
            count = len(value.nodes)
        elif descriptor.artifact_kind == "EDGES":
            count = len(value.edges)
        elif descriptor.artifact_kind == "LABELS":
            count = len(value.labels)
        else:
            count = len(value.mappings)
        descriptors.append(
            replace(
                descriptor,
                sha256=fixture_sha256(value),
                item_count=count,
            )
        )
    return replace(
        candidate,
        manifest=replace(candidate.manifest, artifacts=tuple(descriptors)),
    )


def permanent_registry(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
) -> tuple[TaxonomyCodeMeaning, ...]:
    value = candidate or release_candidate()
    return tuple(
        TaxonomyCodeMeaning(
            value.manifest.family_code,
            node.code,
            node.kind,
            node.definition_code,
            node.attributes,
        )
        for node in value.nodes.nodes
    )


def bundle(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
    *,
    status: TaxonomyBundleStatus = TaxonomyBundleStatus.ACTIVE,
    aggregate_version: int = 1,
) -> TaxonomyBundle:
    value = candidate or release_candidate()
    return TaxonomyBundle(
        value.manifest.bundle_id,
        value.manifest.family_code,
        value.manifest.semantic_version,
        value.manifest.selector.selector_digest,
        fixture_sha256(value.manifest),
        status,
        aggregate_version,
        value.manifest.predecessor_bundle_id,
        None,
        value.manifest.effective_at,
        value.manifest.effective_until,
        None,
        NOW,
    )


def actor() -> TaxonomyActorContext:
    return TaxonomyActorContext(
        TaxonomyActorKind.SYSTEM,
        "taxonomy_publisher_0001",
        "workload_secret_taxonomy_001",
        None,
        "taxonomy_correlation_001",
        "taxonomy_causation_00001",
        "taxonomy_trace_00000001",
    )


def artifact_references(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
) -> tuple[TaxonomyArtifactReference, ...]:
    value = candidate or release_candidate()
    result = [
        TaxonomyArtifactReference(
            "taxonomy_artifact_release_001",
            "RELEASE",
            "taxonomy-release-v1",
            None,
            fixture_sha256(value.manifest),
        )
    ]
    artifact_values: list[tuple[str, str, Optional[str], Any]] = [
        ("NODES", "taxonomy-nodes-v1", None, value.nodes),
        ("EDGES", "taxonomy-edges-v1", None, value.edges),
    ]
    artifact_values.extend(
        ("LABELS", "taxonomy-labels-v1", item.locale, item)
        for item in value.labels
    )
    if value.crosswalk:
        artifact_values.append(
            ("CROSSWALK", "taxonomy-crosswalk-v1", None, value.crosswalk)
        )
    for index, (kind, schema, locale, artifact) in enumerate(
        artifact_values, 1
    ):
        result.append(
            TaxonomyArtifactReference(
                f"taxonomy_artifact_{index:08d}",
                kind,
                schema,
                locale,
                fixture_sha256(artifact),
            )
        )
    return tuple(result)


def publish_command(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
    *,
    raw_key: str = "raw-taxonomy-publish-key-001",
) -> PublishTaxonomyBundleCommand:
    value = candidate or release_candidate()
    return PublishTaxonomyBundleCommand(
        fixture_sha256(value.manifest),
        "signature_envelope_0001",
        "taxonomy_trust_record_001",
        "taxonomy_domain_approval_01",
        "taxonomy_safety_approval_01",
        artifact_references(value),
        value.manifest.predecessor_bundle_id,
        raw_key,
    )


def retire_command() -> RetireTaxonomyBundleCommand:
    return RetireTaxonomyBundleCommand(
        BUNDLE_ID, "SECURITY_REVIEW", 1, "raw-taxonomy-retire-key-001"
    )


def source_event(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
) -> TaxonomyBundlePublishedSourceEvent:
    value = candidate or release_candidate()
    return TaxonomyBundlePublishedSourceEvent(
        "taxonomy_source_event_001",
        "TaxonomyBundlePublished",
        1,
        "TaxonomyBundle",
        value.manifest.bundle_id,
        1,
        NOW,
        value.manifest.bundle_id,
        value.manifest.family_code,
        value.manifest.semantic_version,
        value.manifest.selector.selector_digest,
        fixture_sha256(value.manifest),
        value.manifest.effective_at,
        "ACTIVE",
    )


def consumer_command(
    candidate: Optional[TaxonomyReleaseCandidate] = None,
) -> ApplyTaxonomyBundleToConsumerCommand:
    return ApplyTaxonomyBundleToConsumerCommand(
        "PROFILE",
        FAMILY,
        1,
        (1,),
        source_event(candidate),
    )


class FixedClock:
    def now(self) -> datetime:
        return NOW


class IdSource:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    def next_id(self, kind: str) -> str:
        self.counters[kind] = self.counters.get(kind, 0) + 1
        return f"taxonomy_{kind}_{self.counters[kind]:08d}"


class ReceiptKeyring:
    active_identity_key_id = "taxonomy-identity-key-v2"
    active_payload_key_id = "taxonomy-payload-key-v2"
    retained_identity_key_ids = ("taxonomy-identity-key-v1",)
    retained_payload_key_ids = ("taxonomy-payload-key-v1",)

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        return hmac.new(
            f"test-only:{key_id}".encode(), value, hashlib.sha256
        ).hexdigest()


class WorkloadAuthorityPort:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def authorize(self, **query: Any) -> TaxonomyWorkloadAuthority:
        self.calls.append(deepcopy(query))
        call_actor = query["actor"]
        return TaxonomyWorkloadAuthority(
            call_actor.actor_id,
            call_actor.workload_credential_id,
            "ACTIVE",
            query["operation"],
            "taxonomy_attestation_0001",
            "1" * 64,
            NOW + timedelta(minutes=5),
        )


class ArtifactReaderPort:
    def __init__(self, candidate: TaxonomyReleaseCandidate) -> None:
        self.candidate = candidate
        self.references = artifact_references(candidate)
        self.calls: list[Any] = []

    def read_exact(self, *, references: Any) -> TaxonomyArtifactSet:
        self.calls.append(deepcopy(references))
        if tuple(references) != self.references:
            raise TaxonomyArtifactUnavailableError("artifact reference drift")
        values: dict[tuple[str, Optional[str]], Any] = {
            ("RELEASE", None): self.candidate.manifest,
            ("NODES", None): self.candidate.nodes,
            ("EDGES", None): self.candidate.edges,
        }
        values.update(
            {("LABELS", item.locale): item for item in self.candidate.labels}
        )
        if self.candidate.crosswalk is not None:
            values[("CROSSWALK", None)] = self.candidate.crosswalk
        raw = tuple(
            (
                reference.artifact_reference_id,
                fixture_canonical_bytes(
                    values[(reference.artifact_kind, reference.locale)]
                ),
            )
            for reference in self.references
        )
        return TaxonomyArtifactSet(self.candidate, self.references, raw)


class SignatureVerifierPort:
    def __init__(self, manifest_sha256: str) -> None:
        self.manifest_sha256 = manifest_sha256
        self.calls: list[Any] = []

    def verify(self, **query: Any) -> TaxonomySignatureEvidence:
        self.calls.append(deepcopy(query))
        return TaxonomySignatureEvidence(
            query["signature_envelope_id"],
            query["trust_record_id"],
            self.manifest_sha256,
            "taxonomy_signing_key_001",
            "ED25519",
            NOW - timedelta(seconds=1),
            NOW + timedelta(minutes=5),
        )


class TrustVerifierPort:
    def __init__(self, manifest_sha256: str) -> None:
        self.manifest_sha256 = manifest_sha256
        self.calls: list[Any] = []

    def verify(self, **query: Any) -> TaxonomyTrustEvidence:
        self.calls.append(deepcopy(query))
        return TaxonomyTrustEvidence(
            query["trust_record_id"],
            query["signing_key_id"],
            "ACTIVE",
            query["algorithm"],
            self.manifest_sha256,
            NOW + timedelta(minutes=5),
        )


class ApprovalReaderPort:
    def __init__(self, manifest_sha256: str) -> None:
        self.manifest_sha256 = manifest_sha256
        self.calls: list[Any] = []

    def read_exact(self, **query: Any):
        self.calls.append(deepcopy(query))
        return (
            TaxonomyApprovalEvidence(
                query["domain_approval_id"],
                "DOMAIN_STEWARD",
                "taxonomy_reviewer_domain_1",
                "APPROVED",
                self.manifest_sha256,
                "2" * 64,
                NOW + timedelta(minutes=5),
            ),
            TaxonomyApprovalEvidence(
                query["safety_data_approval_id"],
                "SAFETY_DATA_STEWARD",
                "taxonomy_reviewer_safety_1",
                "APPROVED",
                self.manifest_sha256,
                "2" * 64,
                NOW + timedelta(minutes=5),
            ),
        )


class LockedEvidencePort:
    def __init__(self) -> None:
        self.calls: list[Any] = []
        self.revoked = False

    def recheck(self, **query: Any) -> None:
        self.calls.append(deepcopy(query))
        if self.revoked:
            raise TaxonomyArtifactUnavailableError("locked evidence revoked")


class DomainValidatorPort:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def validate(self, **query: Any) -> ValidatedTaxonomyRelease:
        self.calls.append(deepcopy(query))
        return validate_taxonomy_release(
            candidate=query["artifact_set"].candidate,
            predecessor=query["predecessor"],
            permanent_code_registry=tuple(query["permanent_code_registry"]),
            server_now=query["server_now"],
        )


class SourceEventValidatorPort:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def validate(self, **query: Any) -> None:
        self.calls.append(deepcopy(query))


class ConsumerCatalogPort:
    def __init__(self, candidate: TaxonomyReleaseCandidate) -> None:
        self.candidate = candidate
        self.calls: list[Any] = []
        self.override: Optional[TaxonomyConsumerRelease] = None

    def read_exact_release(self, **query: Any) -> TaxonomyConsumerRelease:
        self.calls.append(deepcopy(query))
        if self.override is not None:
            return deepcopy(self.override)
        if (
            query["bundle_id"] != self.candidate.manifest.bundle_id
            or query["release_manifest_sha256"]
            != fixture_sha256(self.candidate.manifest)
        ):
            raise TaxonomyArtifactUnavailableError("consumer exact read drift")
        return TaxonomyConsumerRelease(validated_release(self.candidate), 1, "ACTIVE")


class FormalEventValidator:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def validate(self, event: Mapping[str, Any]) -> None:
        self.calls.append(deepcopy(event))
        from pathlib import Path
        from tests.contract.test_demand_contracts import _load, _validate

        path = (
            Path(__file__).resolve().parents[2]
            / "contracts/events/taxonomy-v1.schema.json"
        )
        document = _load(path)
        _validate(document, path, document, event)


class SafeResponseValidator:
    def validate(self, *, operation: str, response: Mapping[str, Any]) -> None:
        expected = {
            "schema_version",
            "response_schema",
            "http_status",
            "etag",
            "body",
        }
        if set(response) != expected:
            raise AssertionError("Taxonomy safe response is not closed")


class SnapshotStore:
    def __init__(self, seed: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.data = deepcopy(dict(seed or {}))

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self.data)


class MemoryUnitOfWork(AbstractContextManager["MemoryUnitOfWork"]):
    def __init__(self, factory: "MemoryUnitOfWorkFactory") -> None:
        self.factory = factory
        self.working = deepcopy(factory.store.data)
        self.calls: list[Any] = []

    def __enter__(self) -> "MemoryUnitOfWork":
        self.factory.instances.append(self)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def lock(self, resource: str, keys: Any) -> None:
        self.calls.append(("lock", resource, tuple(keys)))
        if self.factory.current_race:
            self.working.setdefault("current", {})["selector"] = SUCCESSOR_ID

    def get(self, collection: str, key: str) -> Any:
        return deepcopy(self.working.get(collection, {}).get(key))

    def values(self, collection: str) -> tuple[Any, ...]:
        return tuple(deepcopy(tuple(self.working.get(collection, {}).values())))

    def put(self, collection: str, key: str, value: Any) -> None:
        self.working.setdefault(collection, {})[key] = deepcopy(value)

    def checkpoint(self, name: str) -> None:
        self.calls.append(("checkpoint", name))
        if self.factory.fail_checkpoint == name:
            raise TaxonomyStorageUnavailableError(name)

    def commit(self) -> None:
        if self.factory.commit_unknown:
            if self.factory.commit_unknown_durable:
                self.factory.store.data = deepcopy(self.working)
            raise TaxonomyCommitOutcomeUnknownError("taxonomy commit ack lost")
        self.factory.store.data = deepcopy(self.working)


class MemoryUnitOfWorkFactory:
    def __init__(self, seed: Mapping[str, Mapping[str, Any]]) -> None:
        self.store = SnapshotStore(seed)
        self.instances: list[MemoryUnitOfWork] = []
        self.fail_checkpoint: Optional[str] = None
        self.commit_unknown = False
        self.commit_unknown_durable = False
        self.current_race = False

    def begin(self) -> MemoryUnitOfWork:
        return MemoryUnitOfWork(self)


class RecoveryReader:
    def __init__(self, factory: MemoryUnitOfWorkFactory) -> None:
        self.factory = factory

    def read_receipt(self, identity: str) -> Any:
        return deepcopy(self.factory.store.data.get("receipts", {}).get(identity))

    def read_fact(self, collection: str, identifier: str) -> Any:
        return deepcopy(self.factory.store.data.get(collection, {}).get(identifier))


@dataclass
class TaxonomyHarness:
    dependencies: dict[str, Any]
    uow_factory: MemoryUnitOfWorkFactory
    authority: WorkloadAuthorityPort
    artifacts: ArtifactReaderPort
    signature: SignatureVerifierPort
    trust: TrustVerifierPort
    approvals: ApprovalReaderPort
    locked_evidence: LockedEvidencePort
    source_validator: SourceEventValidatorPort
    consumer_catalog: ConsumerCatalogPort
    candidate: TaxonomyReleaseCandidate

    def assert_ready(self, handler_type: type, command: Any) -> None:
        snapshot = self.uow_factory.store.snapshot()
        name = handler_type.__name__
        if name == "PublishTaxonomyBundleHandler":
            assert tuple(command.artifacts) == self.artifacts.references
            assert self.artifacts.candidate == self.candidate
            predecessor_id = self.candidate.manifest.predecessor_bundle_id
            if predecessor_id is not None:
                assert predecessor_id in snapshot.get("bundles", {})
                assert snapshot.get("current", {}).get("selector") == predecessor_id
        elif name == "RetireTaxonomyBundleHandler":
            current = snapshot.get("bundles", {}).get(command.bundle_id)
            assert isinstance(current, TaxonomyBundle)
            selector = snapshot.get("current", {}).get("selector")
            if current.status is TaxonomyBundleStatus.ACTIVE:
                assert current.aggregate_version == command.expected_bundle_version
                assert selector == command.bundle_id
            else:
                assert current.status is TaxonomyBundleStatus.RETIRED
                assert current.aggregate_version == command.expected_bundle_version
                assert current.retired_reason_code == command.reason_code
                assert selector is None
        elif name == "ApplyTaxonomyBundleToConsumerHandler":
            assert command.source_event.bundle_id == self.candidate.manifest.bundle_id
            inbox = snapshot.get("consumer_inbox", {})
            markers = snapshot.get("consumer_markers", {})
            if inbox or markers:
                assert set(inbox) == {command.source_event.event_id}
                row = inbox[command.source_event.event_id]
                assert row["status"] == "COMPLETED"
                assert row["event_sha256"] == fixture_sha256(command.source_event)
                assert row["safe_response"] is not None
                assert len(markers) == 1
                marker = next(iter(markers.values()))
                assert marker["consumer_code"] == command.consumer_code
                assert marker["taxonomy_bundle_id"] == command.source_event.bundle_id
                assert marker["release_manifest_sha256"] == command.source_event.release_manifest_sha256
                assert marker["source_event_id"] == command.source_event.event_id
                assert marker["status"] == "ACTIVE"
        else:
            raise AssertionError(name)


def build_harness(handler_type: type, command: Any) -> TaxonomyHarness:
    name = handler_type.__name__
    if name == "PublishTaxonomyBundleHandler":
        candidate = (
            release_candidate(successor=True)
            if command.expected_current_bundle_id is not None
            else release_candidate()
        )
        seed: dict[str, dict[str, Any]] = {}
        if candidate.manifest.predecessor_bundle_id:
            predecessor = release_candidate()
            seed = {
                "bundles": {BUNDLE_ID: bundle(predecessor)},
                "releases": {BUNDLE_ID: predecessor},
                "current": {"selector": BUNDLE_ID},
                "code_registry": {
                    item.code: item for item in permanent_registry(predecessor)
                },
            }
    elif name == "RetireTaxonomyBundleHandler":
        candidate = release_candidate()
        seed = {
            "bundles": {BUNDLE_ID: bundle(candidate)},
            "releases": {BUNDLE_ID: candidate},
            "current": {"selector": BUNDLE_ID},
        }
    elif name == "ApplyTaxonomyBundleToConsumerHandler":
        candidate = release_candidate()
        seed = {"consumer_inbox": {}, "consumer_markers": {}}
    else:
        raise AssertionError(name)
    factory = MemoryUnitOfWorkFactory(seed)
    authority_port = WorkloadAuthorityPort()
    artifact_port = ArtifactReaderPort(candidate)
    manifest_hash = fixture_sha256(candidate.manifest)
    signature_port = SignatureVerifierPort(manifest_hash)
    trust_port = TrustVerifierPort(manifest_hash)
    approval_port = ApprovalReaderPort(manifest_hash)
    locked_port = LockedEvidencePort()
    source_validator = SourceEventValidatorPort()
    catalog_port = ConsumerCatalogPort(candidate)
    dependencies = {
        "clock": FixedClock(),
        "id_source": IdSource(),
        "workload_authority": authority_port,
        "artifact_reader": artifact_port,
        "signature_verifier": signature_port,
        "trust_verifier": trust_port,
        "approval_reader": approval_port,
        "locked_evidence": locked_port,
        "domain_validator": DomainValidatorPort(),
        "receipt_keyring": ReceiptKeyring(),
        "source_event_validator": source_validator,
        "consumer_catalog": catalog_port,
        "event_validator": FormalEventValidator(),
        "safe_response_validator": SafeResponseValidator(),
        "uow_factory": factory,
        "recovery_reader": RecoveryReader(factory),
    }
    harness = TaxonomyHarness(
        dependencies,
        factory,
        authority_port,
        artifact_port,
        signature_port,
        trust_port,
        approval_port,
        locked_port,
        source_validator,
        catalog_port,
        candidate,
    )
    harness.assert_ready(handler_type, command)
    return harness
