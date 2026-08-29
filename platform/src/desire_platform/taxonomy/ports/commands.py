"""Closed dependency ports for Taxonomy application orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ContextManager, Mapping, Optional, Protocol, Sequence, Tuple

from ..application.commands import TaxonomyActorContext, TaxonomyArtifactReference
from ..domain.model import TaxonomyReleaseCandidate, ValidatedTaxonomyRelease


class TaxonomyStorageUnavailableError(Exception):
    pass


class TaxonomyCommitOutcomeUnknownError(Exception):
    pass


class TaxonomyAuthorityUnavailableError(Exception):
    pass


class TaxonomyArtifactUnavailableError(Exception):
    pass


class TaxonomyTrustUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class TaxonomyWorkloadAuthority:
    workload_principal_id: str
    workload_credential_id: str = field(repr=False)
    credential_status: str
    operation: str
    attestation_id: str
    attestation_sha256: str
    valid_until: datetime


@dataclass(frozen=True)
class TaxonomySignatureEvidence:
    signature_envelope_id: str
    trust_record_id: str
    release_manifest_sha256: str
    signing_key_id: str
    algorithm: str
    verified_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class TaxonomyTrustEvidence:
    trust_record_id: str
    signing_key_id: str
    trust_status: str
    allowed_algorithm: str
    release_manifest_sha256: str
    valid_until: datetime


@dataclass(frozen=True)
class TaxonomyApprovalEvidence:
    approval_id: str
    duty_code: str
    reviewer_id: str
    approval_status: str
    release_manifest_sha256: str
    golden_result_sha256: str
    valid_until: datetime


@dataclass(frozen=True)
class TaxonomyArtifactSet:
    candidate: TaxonomyReleaseCandidate = field(repr=False)
    references: Tuple[TaxonomyArtifactReference, ...]
    canonical_bytes_by_reference: Tuple[Tuple[str, bytes], ...] = field(
        repr=False
    )


@dataclass(frozen=True)
class TaxonomyConsumerRelease:
    validated: ValidatedTaxonomyRelease = field(repr=False)
    aggregate_version: int
    status: str


class TaxonomyWorkloadAuthorityPort(Protocol):
    def authorize(self, *, actor: TaxonomyActorContext, operation: str) -> TaxonomyWorkloadAuthority: ...


class TaxonomyArtifactReaderPort(Protocol):
    def read_exact(self, *, references: Sequence[TaxonomyArtifactReference]) -> TaxonomyArtifactSet: ...


class TaxonomySignatureVerifierPort(Protocol):
    def verify(self, *, signature_envelope_id: str, trust_record_id: str, release_manifest_sha256: str) -> TaxonomySignatureEvidence: ...


class TaxonomyTrustVerifierPort(Protocol):
    def verify(self, *, trust_record_id: str, signing_key_id: str, algorithm: str, release_manifest_sha256: str) -> TaxonomyTrustEvidence: ...


class TaxonomyApprovalReaderPort(Protocol):
    def read_exact(self, *, domain_approval_id: str, safety_data_approval_id: str, release_manifest_sha256: str) -> Tuple[TaxonomyApprovalEvidence, TaxonomyApprovalEvidence]: ...


class TaxonomyLockedEvidencePort(Protocol):
    def recheck(self, *, signature: TaxonomySignatureEvidence, approvals: Sequence[TaxonomyApprovalEvidence], server_now: datetime) -> None: ...


class TaxonomyDomainValidatorPort(Protocol):
    def validate(self, *, artifact_set: TaxonomyArtifactSet, predecessor: Optional[TaxonomyReleaseCandidate], permanent_code_registry: Sequence[Any], server_now: datetime) -> ValidatedTaxonomyRelease: ...


class TaxonomyReceiptKeyringPort(Protocol):
    active_identity_key_id: str
    active_payload_key_id: str
    retained_identity_key_ids: Tuple[str, ...]
    retained_payload_key_ids: Tuple[str, ...]
    def keyed_digest(self, key_id: str, value: bytes) -> str: ...


class TaxonomyClockPort(Protocol):
    def now(self) -> datetime: ...


class TaxonomyIdSourcePort(Protocol):
    def next_id(self, kind: str) -> str: ...


class TaxonomyEventValidatorPort(Protocol):
    def validate(self, event: Mapping[str, Any]) -> None: ...


class TaxonomySafeResponseValidatorPort(Protocol):
    def validate(self, *, operation: str, response: Mapping[str, Any]) -> None: ...


class TaxonomyUnitOfWorkPort(Protocol):
    def lock(self, resource: str, keys: Sequence[str]) -> None: ...
    def get(self, collection: str, key: str) -> Any: ...
    def values(self, collection: str) -> Tuple[Any, ...]: ...
    def put(self, collection: str, key: str, value: Any) -> None: ...
    def checkpoint(self, name: str) -> None: ...
    def commit(self) -> None: ...


class TaxonomyUnitOfWorkFactoryPort(Protocol):
    store: Any
    def begin(self) -> ContextManager[TaxonomyUnitOfWorkPort]: ...


class TaxonomyRecoveryReaderPort(Protocol):
    def read_receipt(self, identity: str) -> Any: ...
    def read_fact(self, collection: str, identifier: str) -> Any: ...


class TaxonomyConsumerCatalogPort(Protocol):
    def read_exact_release(self, *, bundle_id: str, release_manifest_sha256: str) -> TaxonomyConsumerRelease: ...


class TaxonomySourceEventValidatorPort(Protocol):
    def validate(self, *, actor: TaxonomyActorContext, event: Any) -> None: ...
