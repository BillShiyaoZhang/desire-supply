"""Immutable Taxonomy application commands and safe results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple


class TaxonomyActorKind(str, Enum):
    SYSTEM = "SYSTEM"


@dataclass(frozen=True)
class TaxonomyActorContext:
    actor_kind: TaxonomyActorKind
    actor_id: str
    workload_credential_id: str = field(repr=False)
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str


@dataclass(frozen=True)
class TaxonomyArtifactReference:
    artifact_reference_id: str
    artifact_kind: str
    schema_name: str
    locale: Optional[str]
    sha256: str


@dataclass(frozen=True)
class PublishTaxonomyBundleCommand:
    release_manifest_sha256: str
    signature_envelope_id: str
    trust_record_id: str
    domain_approval_id: str
    safety_data_approval_id: str
    artifacts: Tuple[TaxonomyArtifactReference, ...]
    expected_current_bundle_id: Optional[str]
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class RetireTaxonomyBundleCommand:
    bundle_id: str
    reason_code: str
    expected_bundle_version: int
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class TaxonomyBundlePublishedSourceEvent:
    event_id: str
    event_type: str
    schema_version: int
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int
    occurred_at: datetime
    bundle_id: str
    family_code: str
    semantic_version: str
    selector_digest: str
    release_manifest_sha256: str
    effective_at: datetime
    status: str


@dataclass(frozen=True)
class ApplyTaxonomyBundleToConsumerCommand:
    consumer_code: str
    supported_family_code: str
    supported_schema_version: int
    supported_semantic_majors: Tuple[int, ...]
    source_event: TaxonomyBundlePublishedSourceEvent = field(repr=False)


@dataclass(frozen=True)
class TaxonomyCommandResult:
    target_id: str
    target_status: str
    aggregate_version: int
    entity_tag: str
    http_status: int
    event_types: Tuple[str, ...]
    replayed: bool
    completed_at: datetime
