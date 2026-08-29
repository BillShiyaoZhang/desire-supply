"""Policy acknowledgement and immutable ConsentOffer domain contracts."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
from typing import Optional, Tuple
import unicodedata

from .errors import IamError


class PolicyLegalEffect(str, Enum):
    NOTICE_ACKNOWLEDGEMENT = "NOTICE_ACKNOWLEDGEMENT"
    CONTRACT_ACCEPTANCE = "CONTRACT_ACCEPTANCE"
    CONSENT_TEXT = "CONSENT_TEXT"


class PolicyBundleStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class PolicyDocumentStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class ConsentPurpose(str, Enum):
    PILOT_RESEARCH = "PILOT_RESEARCH"


class ConsentScopeType(str, Enum):
    PLATFORM_PARTICIPATION = "PLATFORM_PARTICIPATION"


class ConsentScopeDerivation(str, Enum):
    PLATFORM_PARTICIPATION_NULL_SCOPE = "PLATFORM_PARTICIPATION_NULL_SCOPE"


class ConsentExpiryRule(str, Enum):
    EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER = (
        "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
    )


class DataCategory(str, Enum):
    PROFILE = "PROFILE"
    MATCHING = "MATCHING"
    RESEARCH = "RESEARCH"


@dataclass(frozen=True)
class PolicyDocument:
    document_id: str
    content_sha256: str
    legal_effect: PolicyLegalEffect
    kind: Optional[str] = None
    semantic_version: Optional[str] = None
    locale: Optional[str] = None
    jurisdiction: Optional[str] = None
    canonical_body: Optional[str] = field(default=None, repr=False)
    status: PolicyDocumentStatus = PolicyDocumentStatus.ACTIVE
    effective_at: Optional[datetime] = None
    superseded_by_document_id: Optional[str] = None
    publication_command_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        _require_sha256(self.content_sha256)
        try:
            status = PolicyDocumentStatus(self.status)
        except (TypeError, ValueError) as error:
            raise IamError("INVALID_POLICY_DOCUMENT") from error
        object.__setattr__(self, "status", status)
        for timestamp in (self.effective_at, self.created_at, self.updated_at):
            if timestamp is not None:
                _require_aware_utc(timestamp)
        if self.canonical_body is not None and hashlib.sha256(
            self.canonical_body.encode("utf-8")
        ).hexdigest() != self.content_sha256:
            raise IamError("INVALID_CONTENT_HASH")
        if self.publication_command_id is not None:
            if any(
                not isinstance(value, str) or not value
                for value in (
                    self.kind,
                    self.semantic_version,
                    self.locale,
                    self.jurisdiction,
                    self.canonical_body,
                    self.publication_command_id,
                )
            ):
                raise IamError("INVALID_POLICY_DOCUMENT")
            if status == PolicyDocumentStatus.ACTIVE and (
                self.effective_at is None
                or self.superseded_by_document_id is not None
            ):
                raise IamError("INVALID_POLICY_DOCUMENT")


@dataclass(frozen=True)
class PolicyAcceptance:
    document_id: str
    content_sha256: str
    affirmed: bool


@dataclass(frozen=True)
class ConsentOfferChoice:
    consent_offer_id: str
    document_id: str
    content_sha256: str
    affirmed: bool


@dataclass(frozen=True)
class ConsentOffer:
    consent_offer_id: str
    aggregate_version: int
    purpose: ConsentPurpose
    scope_type: ConsentScopeType
    data_categories: Tuple[DataCategory, ...]
    supporting_document_id: str
    supporting_document_sha256: str
    recipient_reference: str
    pilot_ends_at: datetime
    canonicalization_version: str = "consent-offer-json-v1"
    policy_bundle_id: Optional[str] = None
    scope_derivation: ConsentScopeDerivation = (
        ConsentScopeDerivation.PLATFORM_PARTICIPATION_NULL_SCOPE
    )
    recipient_label: Optional[str] = None
    expiry_rule: ConsentExpiryRule = (
        ConsentExpiryRule.EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER
    )
    expiry_days: Optional[int] = 365
    optional: bool = True
    canonical_offer_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        if self.aggregate_version < 1:
            raise IamError("INVALID_AGGREGATE_VERSION")
        _require_sha256(self.supporting_document_sha256)
        _require_aware_utc(self.pilot_ends_at)
        try:
            scope_derivation = ConsentScopeDerivation(self.scope_derivation)
            expiry_rule = ConsentExpiryRule(self.expiry_rule)
        except (TypeError, ValueError) as error:
            raise IamError("INVALID_CONSENT_OFFER") from error
        object.__setattr__(self, "scope_derivation", scope_derivation)
        object.__setattr__(self, "expiry_rule", expiry_rule)
        if (
            self.canonicalization_version != "consent-offer-json-v1"
            or self.purpose != ConsentPurpose.PILOT_RESEARCH
            or self.scope_type != ConsentScopeType.PLATFORM_PARTICIPATION
            or scope_derivation
            != ConsentScopeDerivation.PLATFORM_PARTICIPATION_NULL_SCOPE
            or self.data_categories
            != (
                DataCategory.PROFILE,
                DataCategory.MATCHING,
                DataCategory.RESEARCH,
            )
            or not isinstance(self.recipient_reference, str)
            or not self.recipient_reference
            or self.recipient_reference
            != unicodedata.normalize("NFC", self.recipient_reference)
            or expiry_rule
            != ConsentExpiryRule.EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER
            or self.expiry_days != 365
            or self.optional is not True
        ):
            raise IamError("INVALID_CONSENT_OFFER")
        release_fields = (
            self.policy_bundle_id,
            self.recipient_label,
            self.canonical_offer_sha256,
        )
        if any(value is not None for value in release_fields):
            if (
                not all(isinstance(value, str) and value for value in release_fields)
                or self.recipient_label
                != unicodedata.normalize("NFC", self.recipient_label)
                or len(self.recipient_label) > 160
            ):
                raise IamError("INVALID_CONSENT_OFFER")
            _require_sha256(self.canonical_offer_sha256)

    @property
    def not_after(self) -> datetime:
        return self.pilot_ends_at

    @classmethod
    def pilot_research(
        cls,
        *,
        consent_offer_id: str,
        aggregate_version: int,
        supporting_document_id: str,
        supporting_document_sha256: str,
        recipient_reference: str,
        pilot_ends_at: datetime,
        policy_bundle_id: Optional[str] = None,
        recipient_label: Optional[str] = None,
        canonical_offer_sha256: Optional[str] = None,
    ) -> "ConsentOffer":
        return cls(
            consent_offer_id=consent_offer_id,
            aggregate_version=aggregate_version,
            purpose=ConsentPurpose.PILOT_RESEARCH,
            scope_type=ConsentScopeType.PLATFORM_PARTICIPATION,
            data_categories=(
                DataCategory.PROFILE,
                DataCategory.MATCHING,
                DataCategory.RESEARCH,
            ),
            supporting_document_id=supporting_document_id,
            supporting_document_sha256=supporting_document_sha256,
            recipient_reference=recipient_reference,
            pilot_ends_at=pilot_ends_at,
            policy_bundle_id=policy_bundle_id,
            recipient_label=recipient_label,
            canonical_offer_sha256=canonical_offer_sha256,
        )


def canonical_consent_offer_bytes(offer: ConsentOffer) -> bytes:
    """Return the sole ``consent-offer-json-v1`` canonical byte encoding."""

    payload = {
        "canonicalization_version": offer.canonicalization_version,
        "consent_offer_id": offer.consent_offer_id,
        "consent_offer_version": offer.aggregate_version,
        "policy_bundle_id": offer.policy_bundle_id,
        "purpose": _enum_or_raw_value(offer.purpose),
        "scope_type": _enum_or_raw_value(offer.scope_type),
        "scope_derivation": _enum_or_raw_value(offer.scope_derivation),
        "data_categories": [
            _enum_or_raw_value(category) for category in offer.data_categories
        ],
        "recipient_ref": offer.recipient_reference,
        "recipient_label": offer.recipient_label,
        "supporting_document_id": offer.supporting_document_id,
        "supporting_document_sha256": offer.supporting_document_sha256,
        "expiry_rule": _enum_or_raw_value(offer.expiry_rule),
        "expiry_days": offer.expiry_days,
        "not_after": offer.not_after.isoformat().replace("+00:00", "Z"),
        "optional": offer.optional,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _enum_or_raw_value(value: object) -> object:
    """Serialize an untrusted release fact without validating its domain value.

    Publication verifies the signature over the submitted raw artifact before
    applying the strict ConsentOffer domain rules.  Valid Enum instances and
    their raw string representation therefore must produce identical bytes;
    validation remains the caller's responsibility.
    """

    return value.value if isinstance(value, Enum) else value


@dataclass(frozen=True)
class DerivedConsentAuthorization:
    consent_offer_id: str
    consent_offer_version: int
    policy_bundle_id: str
    purpose: ConsentPurpose
    scope_type: ConsentScopeType
    scope_id: Optional[str]
    data_categories: Tuple[DataCategory, ...]
    recipient_reference: str
    supporting_policy_document_id: str
    supporting_document_sha256: str
    expires_at: datetime


@dataclass(frozen=True)
class PolicyEvaluation:
    policy_acceptances: Tuple[PolicyAcceptance, ...]
    consent_authorizations: Tuple[DerivedConsentAuthorization, ...]


@dataclass(frozen=True)
class PolicyBundle:
    policy_bundle_id: str
    selector_digest: str
    status: PolicyBundleStatus
    effective_at: Optional[datetime]
    effective_until: Optional[datetime]
    documents: Tuple[PolicyDocument, ...]
    required_document_ids: Tuple[str, ...]
    consent_offers: Tuple[ConsentOffer, ...]
    superseded_by_bundle_id: Optional[str] = None
    release_manifest_sha256: Optional[str] = None
    release_signature_algorithm: Optional[str] = None
    release_signature_key_id: Optional[str] = None
    release_signature: Optional[str] = field(default=None, repr=False)
    publication_command_id: Optional[str] = None
    aggregate_version: int = 1
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        _require_sha256(self.selector_digest)
        try:
            status = PolicyBundleStatus(self.status)
        except (TypeError, ValueError) as error:
            raise IamError("INVALID_POLICY_BUNDLE") from error
        object.__setattr__(self, "status", status)
        if self.aggregate_version < 1:
            raise IamError("INVALID_AGGREGATE_VERSION")
        if self.effective_at is not None:
            _require_aware_utc(self.effective_at)
        if self.effective_until is not None:
            _require_aware_utc(self.effective_until)
        if self.created_at is not None:
            _require_aware_utc(self.created_at)
        if self.updated_at is not None:
            _require_aware_utc(self.updated_at)
        if self.release_manifest_sha256 is not None:
            _require_sha256(self.release_manifest_sha256)
        if status == PolicyBundleStatus.DRAFT:
            if (
                self.effective_at is not None
                or self.effective_until is not None
                or self.superseded_by_bundle_id is not None
            ):
                raise IamError("INVALID_POLICY_BUNDLE")
        elif self.effective_at is None:
            raise IamError("INVALID_POLICY_BUNDLE")
        if (
            self.effective_at is not None
            and self.effective_until is not None
            and self.effective_until <= self.effective_at
        ):
            raise IamError("INVALID_POLICY_BUNDLE")
        document_ids = [document.document_id for document in self.documents]
        offer_ids = [offer.consent_offer_id for offer in self.consent_offers]
        if len(document_ids) != len(set(document_ids)):
            raise IamError("INVALID_POLICY_BUNDLE")
        if len(offer_ids) != len(set(offer_ids)):
            raise IamError("INVALID_POLICY_BUNDLE")
        if len(self.required_document_ids) != len(set(self.required_document_ids)):
            raise IamError("INVALID_POLICY_BUNDLE")
        documents_by_id = {
            document.document_id: document for document in self.documents
        }
        if any(
            document_id not in documents_by_id
            for document_id in self.required_document_ids
        ):
            raise IamError("INVALID_POLICY_BUNDLE")
        for offer in self.consent_offers:
            document = documents_by_id.get(offer.supporting_document_id)
            if (
                document is None
                or document.content_sha256 != offer.supporting_document_sha256
                or document.legal_effect != PolicyLegalEffect.CONSENT_TEXT
            ):
                raise IamError("INVALID_POLICY_BUNDLE")
        if self.publication_command_id is not None:
            if any(
                not isinstance(value, str) or not value
                for value in (
                    self.release_signature_algorithm,
                    self.release_signature_key_id,
                    self.release_signature,
                    self.publication_command_id,
                )
            ) or self.release_manifest_sha256 is None:
                raise IamError("INVALID_POLICY_BUNDLE")

    def evaluate(
        self,
        *,
        now: datetime,
        presented_bundle_id: str,
        policy_acceptances: Tuple[PolicyAcceptance, ...],
        consent_choices: Tuple[ConsentOfferChoice, ...],
    ) -> PolicyEvaluation:
        _require_aware_utc(now)
        if presented_bundle_id != self.policy_bundle_id:
            raise IamError("POLICY_BUNDLE_CHANGED")

        documents_by_id = {
            document.document_id: document for document in self.documents
        }
        required_ids = set(self.required_document_ids)
        seen_acceptances = set()
        for acceptance in policy_acceptances:
            document = documents_by_id.get(acceptance.document_id)
            if (
                acceptance.document_id not in required_ids
                or document is None
                or acceptance.content_sha256 != document.content_sha256
                or acceptance.document_id in seen_acceptances
            ):
                raise IamError("POLICY_DOCUMENT_MISMATCH")
            seen_acceptances.add(acceptance.document_id)

        accepted_ids = {
            acceptance.document_id
            for acceptance in policy_acceptances
            if acceptance.affirmed
        }
        if accepted_ids != required_ids:
            raise IamError("POLICY_ACCEPTANCE_REQUIRED")

        accepted_by_id = {
            acceptance.document_id: acceptance
            for acceptance in policy_acceptances
        }
        ordered_acceptances = tuple(
            accepted_by_id[document_id]
            for document_id in self.required_document_ids
        )

        offers_by_id = {
            offer.consent_offer_id: offer for offer in self.consent_offers
        }
        seen_choices = set()
        authorizations = []
        for choice in consent_choices:
            if not choice.affirmed:
                continue
            offer = offers_by_id.get(choice.consent_offer_id)
            if (
                offer is None
                or choice.consent_offer_id in seen_choices
                or choice.document_id != offer.supporting_document_id
                or choice.content_sha256 != offer.supporting_document_sha256
            ):
                raise IamError("CONSENT_OFFER_MISMATCH")
            seen_choices.add(choice.consent_offer_id)
            expires_at = min(offer.pilot_ends_at, now + timedelta(days=365))
            if expires_at <= now:
                raise IamError("CONSENT_OFFER_EXPIRED")
            authorizations.append(
                DerivedConsentAuthorization(
                    consent_offer_id=offer.consent_offer_id,
                    consent_offer_version=offer.aggregate_version,
                    policy_bundle_id=self.policy_bundle_id,
                    purpose=offer.purpose,
                    scope_type=offer.scope_type,
                    scope_id=None,
                    data_categories=offer.data_categories,
                    recipient_reference=offer.recipient_reference,
                    supporting_policy_document_id=offer.supporting_document_id,
                    supporting_document_sha256=offer.supporting_document_sha256,
                    expires_at=expires_at,
                )
            )

        return PolicyEvaluation(
            policy_acceptances=ordered_acceptances,
            consent_authorizations=tuple(authorizations),
        )


def _require_sha256(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise IamError("INVALID_CONTENT_HASH")


def _require_aware_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IamError("INVALID_SERVER_TIME")
