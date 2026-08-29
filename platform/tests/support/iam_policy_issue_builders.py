"""Independent strict fixtures for policy publication and invitation issue REDs.

Nothing in this module imports the Accept application builder.  The fake unit
of work owns an isolated copy-on-write store and records locks/writes so a
future GREEN implementation must cross the intended transaction boundary.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import unicodedata
from typing import Any, Mapping, Optional, Sequence

from desire_platform.identity_access.application.issue_access_invitations import (
    InvitationIssuerContext,
    IssueAccessInvitationCommand,
    IssueAccessInvitationHandler,
    IssuerKind,
    RecipientContactType,
    RecipientInput,
)
from desire_platform.identity_access.application.policy_publication import (
    ConcurrentPolicyPublishError,
    PolicyDocumentKind,
    PolicyDocumentRelease,
    PolicyPublisherContext,
    PolicyReleaseManifest,
    PolicySelectorFacts,
    PolicySelectorScopeType,
    PublishPolicyBundleCommand,
    PublishPolicyBundleHandler,
    SignedPolicyRelease,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import (
    InvitationPurpose,
    TargetRole,
)
from desire_platform.identity_access.domain.policies import (
    ConsentPurpose,
    ConsentScopeType,
    DataCategory,
    PolicyBundle,
    PolicyBundleStatus,
    PolicyDocument,
    PolicyLegalEffect,
)
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    StrictFakeSafetyHold,
)


UTC_NOW = datetime(2026, 8, 8, 9, 0, tzinfo=timezone.utc)
POLICY_RELEASE_KEY_ID = "iam-policy-release-ed25519-2026-01"
POLICY_RELEASE_KEY = hashlib.sha256(b"test-policy-release-key-v1").digest()
RECEIPT_KEY_ID = "iam-issue-receipt-hmac-2026-01"
RECEIPT_KEY = hashlib.sha256(b"test-issue-receipt-key-v1").digest()
SAFETY_HOLD_POLICY_VERSION = "safety-hold-v1"


@dataclass(frozen=True)
class PolicyConsentOfferRelease:
    """Closed release artifact while the production offer model catches up.

    The current domain object already owns the authorization facts consumed by
    Accept.  The signed release additionally needs the publication-only facts
    fixed by ADR-0004: bundle binding, public label, derivation/expiry rules,
    hard deadline, optional marker, and the independent canonical digest.
    """

    canonicalization_version: str
    consent_offer_id: str
    aggregate_version: int
    policy_bundle_id: str
    purpose: ConsentPurpose
    scope_type: ConsentScopeType
    scope_derivation: str
    data_categories: tuple[DataCategory, ...]
    recipient_reference: str
    recipient_label: str
    supporting_document_id: str
    supporting_document_sha256: str
    expiry_rule: str
    expiry_days: Optional[int]
    not_after: datetime
    optional: bool
    canonical_offer_sha256: str

    @property
    def pilot_ends_at(self) -> datetime:
        """Compatibility name used by the current authorization evaluator."""

        return self.not_after


def policy_selector_digest(facts: PolicySelectorFacts) -> str:
    """Independent oracle for policy-selector-json-v1 canonical bytes."""

    payload = {
        "access_purpose": facts.access_purpose.value,
        "scope_type": facts.scope_type.value,
        "target_role": facts.target_role.value,
        "jurisdiction": unicodedata.normalize("NFC", facts.jurisdiction),
        "locale": unicodedata.normalize("NFC", facts.locale),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def canonical_consent_offer_bytes(offer: PolicyConsentOfferRelease) -> bytes:
    """Independent oracle for the closed consent-offer-json-v1 object."""

    payload = {
        "canonicalization_version": offer.canonicalization_version,
        "consent_offer_id": offer.consent_offer_id,
        "consent_offer_version": offer.aggregate_version,
        "policy_bundle_id": offer.policy_bundle_id,
        "purpose": offer.purpose.value,
        "scope_type": offer.scope_type.value,
        "scope_derivation": offer.scope_derivation,
        "data_categories": [
            category.value for category in offer.data_categories
        ],
        "recipient_ref": offer.recipient_reference,
        "recipient_label": offer.recipient_label,
        "supporting_document_id": offer.supporting_document_id,
        "supporting_document_sha256": offer.supporting_document_sha256,
        "expiry_rule": offer.expiry_rule,
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


def canonical_consent_offer_sha256(
    offer: PolicyConsentOfferRelease,
) -> str:
    return hashlib.sha256(canonical_consent_offer_bytes(offer)).hexdigest()


def canonical_release_manifest_bytes(manifest: PolicyReleaseManifest) -> bytes:
    """Test oracle for the signed, closed release manifest representation."""

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
        "effective_at": manifest.effective_at.isoformat().replace(
            "+00:00", "Z"
        ),
        "effective_until": (
            None
            if manifest.effective_until is None
            else manifest.effective_until.isoformat().replace("+00:00", "Z")
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


def sign_policy_release(
    manifest: PolicyReleaseManifest,
    *,
    manifest_sha256: Optional[str] = None,
    signature: Optional[str] = None,
) -> SignedPolicyRelease:
    manifest_digest = manifest_sha256 or hashlib.sha256(
        canonical_release_manifest_bytes(manifest)
    ).hexdigest()
    release_signature = signature or hmac.new(
        POLICY_RELEASE_KEY,
        bytes.fromhex(manifest_digest),
        hashlib.sha256,
    ).hexdigest()
    return SignedPolicyRelease(
        manifest=manifest,
        manifest_sha256=manifest_digest,
        signature_algorithm="TEST-HMAC-SHA-256",
        signature_key_id=POLICY_RELEASE_KEY_ID,
        signature=release_signature,
    )


class FixedUtcClock:
    def __init__(self, current: datetime = UTC_NOW) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


class FixedIdSource:
    def __init__(self, values: Mapping[str, Sequence[str]]) -> None:
        self.remaining = {
            name: list(identifiers) for name, identifiers in values.items()
        }
        self.calls: list[str] = []

    def new_id(self, kind: str) -> str:
        self.calls.append(kind)
        try:
            return self.remaining[kind].pop(0)
        except (KeyError, IndexError) as error:
            raise AssertionError("unexpected ID allocation: %s" % kind) from error


class FixedSecretSource:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def token_bytes(self, *, purpose: str, length: int) -> bytes:
        self.calls.append((purpose, length))
        material = hashlib.sha256(
            ("strict-policy-issue-secret:" + purpose).encode("utf-8")
        ).digest()
        while len(material) < length:
            material += hashlib.sha256(material).digest()
        return material[:length]


class IsolatedPolicyIssueStore:
    def __init__(self) -> None:
        self._tables: dict[str, dict[Any, Any]] = {}

    def seed(self, **tables: Mapping[Any, Any]) -> None:
        for table, rows in tables.items():
            self._tables.setdefault(table, {}).update(deepcopy(dict(rows)))

    def snapshot(self) -> dict[str, dict[Any, Any]]:
        return deepcopy(self._tables)


class StrictPolicyIssueUowFactory:
    def __init__(
        self,
        *,
        store: IsolatedPolicyIssueStore,
        conflict_on_commit: bool = False,
    ) -> None:
        self.store = store
        self.conflict_on_commit = conflict_on_commit
        self.begin_count = 0
        self.commit_count = 0
        self.lock_calls: list[tuple[str, Any]] = []
        self.write_calls: list[tuple[str, Any, str]] = []

    def begin(self) -> "StrictPolicyIssueUow":
        self.begin_count += 1
        return StrictPolicyIssueUow(self)


class StrictPolicyIssueUow:
    def __init__(self, factory: StrictPolicyIssueUowFactory) -> None:
        self.factory = factory
        self.tables = factory.store.snapshot()
        self.committed = False

    def __enter__(self) -> "StrictPolicyIssueUow":
        return self

    def __exit__(self, exception_type, exception, traceback) -> bool:
        if exception_type is None and self.committed:
            self.factory.store._tables = self.tables
        return False

    def lock(self, table: str, key: Any) -> Any:
        self.factory.lock_calls.append((table, key))
        return self.tables.get(table, {}).get(key)

    def put(
        self,
        table: str,
        key: Any,
        value: Any,
        *,
        checkpoint: str,
    ) -> None:
        self.factory.write_calls.append((table, key, checkpoint))
        self.tables.setdefault(table, {})[key] = deepcopy(value)

    def commit(self) -> None:
        if self.factory.conflict_on_commit:
            raise ConcurrentPolicyPublishError("simulated stale selector write")
        self.factory.commit_count += 1
        self.committed = True


class StrictReleaseVerifier:
    """Verifies exact bytes, checksum, document content and retained key ID."""

    def __init__(self) -> None:
        self.calls: list[SignedPolicyRelease] = []

    def verify(self, release: SignedPolicyRelease) -> bytes:
        self.calls.append(release)
        raw_manifest = canonical_release_manifest_bytes(release.manifest)
        actual_digest = hashlib.sha256(raw_manifest).hexdigest()
        expected_signature = hmac.new(
            POLICY_RELEASE_KEY,
            bytes.fromhex(actual_digest),
            hashlib.sha256,
        ).hexdigest()
        if (
            release.manifest_sha256 != actual_digest
            or release.signature_key_id != POLICY_RELEASE_KEY_ID
            or release.signature_algorithm != "TEST-HMAC-SHA-256"
            or not hmac.compare_digest(release.signature, expected_signature)
        ):
            raise IamError("POLICY_RELEASE_INVALID")
        for document in release.manifest.documents:
            if hashlib.sha256(
                document.canonical_body.encode("utf-8")
            ).hexdigest() != document.content_sha256:
                raise IamError("POLICY_RELEASE_INVALID")
        return raw_manifest


@dataclass(frozen=True)
class CreatorEnrollmentPolicy:
    policy_version: str
    jurisdiction: str
    locale: str
    aggregate_version: int


class StrictPlatformEnrollmentPolicy:
    def __init__(self) -> None:
        self.value = CreatorEnrollmentPolicy(
            policy_version="creator-enrollment-defaults-v1",
            jurisdiction="GLOBAL",
            locale="en",
            aggregate_version=4,
        )
        self.calls = 0

    def current(self) -> CreatorEnrollmentPolicy:
        self.calls += 1
        return self.value


class StrictLocaleResolver:
    policy_version = "organization-locale-fallback-v1"

    def __init__(self, *, locale: str = "zh-CN", unavailable: bool = False) -> None:
        self.locale = locale
        self.unavailable = unavailable
        self.calls: list[dict[str, str]] = []

    def resolve(
        self,
        *,
        jurisdiction: str,
        access_purpose: str,
        target_role: str,
    ) -> str:
        self.calls.append(
            {
                "jurisdiction": jurisdiction,
                "access_purpose": access_purpose,
                "target_role": target_role,
                "policy_version": self.policy_version,
            }
        )
        if self.unavailable:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        return self.locale


class StrictRecipientBinding:
    digest_key_id = "iam-recipient-binding-hmac-2026-01"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def bind(self, *, contact_type: str, locator: str) -> dict[str, str]:
        self.calls.append((contact_type, locator))
        normalized = unicodedata.normalize("NFC", locator.strip().casefold())
        return {
            "type": contact_type,
            "locator_ciphertext": "ciphertext:test-only",
            "binding_digest": hmac.new(
                RECEIPT_KEY,
                normalized.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest(),
            "digest_key_id": self.digest_key_id,
            "masked_recipient_label": "a***@example.test",
        }


class StrictReceiptCodec:
    key_id = RECEIPT_KEY_ID

    def __init__(self) -> None:
        self.identity_calls: list[str] = []
        self.payload_calls: list[tuple[IssueAccessInvitationCommand, str]] = []

    def identity_digest(self, raw_key: str) -> str:
        self.identity_calls.append(raw_key)
        return hmac.new(
            RECEIPT_KEY,
            raw_key.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def payload_hash(
        self,
        *,
        command: IssueAccessInvitationCommand,
        recipient_binding_digest: str,
    ) -> str:
        self.payload_calls.append((command, recipient_binding_digest))
        payload = {
            "organization_id": command.organization_id,
            "expected_organization_version": (
                command.expected_organization_version
            ),
            "recipient_binding_digest": recipient_binding_digest,
            "target_role": command.target_role.value,
            "expires_at": command.expires_at.isoformat(),
        }
        return hmac.new(
            RECEIPT_KEY,
            json.dumps(payload, sort_keys=True).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


class StrictInvitationTokenCodec:
    key_id = "iam-access-invitation-token-v1"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def issue(
        self,
        *,
        invitation_id: str,
        nonce: str,
        expires_at: datetime,
    ) -> str:
        self.calls.append(
            {
                "invitation_id": invitation_id,
                "nonce": nonce,
                "expires_at": expires_at,
                "key_id": self.key_id,
            }
        )
        return "test-capability.%s.%s" % (invitation_id, nonce)


@dataclass
class PublicationFixture:
    store: IsolatedPolicyIssueStore
    uow_factory: StrictPolicyIssueUowFactory
    verifier: StrictReleaseVerifier
    actor: PolicyPublisherContext
    command: PublishPolicyBundleCommand
    handler: PublishPolicyBundleHandler
    selector_facts: PolicySelectorFacts
    selector_digest: str


@dataclass
class IssueFixture:
    store: IsolatedPolicyIssueStore
    uow_factory: StrictPolicyIssueUowFactory
    clock: FixedUtcClock
    platform_policy: StrictPlatformEnrollmentPolicy
    locale_resolver: StrictLocaleResolver
    hold: StrictFakeSafetyHold
    token_codec: StrictInvitationTokenCodec
    recipient_binding: StrictRecipientBinding
    receipt_codec: StrictReceiptCodec
    id_source: FixedIdSource
    secret_source: FixedSecretSource
    actor: InvitationIssuerContext
    command: IssueAccessInvitationCommand
    handler: IssueAccessInvitationHandler
    selector_facts: PolicySelectorFacts
    selector_digest: str
    current_bundle: PolicyBundle


def initial_publication_fixture(
    *,
    conflict_on_commit: bool = False,
) -> PublicationFixture:
    selector = PolicySelectorFacts(
        canonicalization_version="policy-selector-json-v1",
        access_purpose=InvitationPurpose.CREATOR_ENROLLMENT,
        scope_type=PolicySelectorScopeType.USER_ROLE,
        target_role=TargetRole.CREATOR,
        jurisdiction="GLOBAL",
        locale="en",
    )
    selector_digest = policy_selector_digest(selector)
    body = "Synthetic creator terms v1."
    document = PolicyDocumentRelease(
        document_id="policy_document_terms_0001",
        kind=PolicyDocumentKind.TERMS,
        semantic_version="1.0.0",
        locale="en",
        jurisdiction="GLOBAL",
        canonical_body=body,
        content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
    )
    manifest = PolicyReleaseManifest(
        schema_version="iam-policy-release-v1",
        policy_bundle_id="policy_bundle_creator_0001",
        selector_digest=selector_digest,
        selector=selector,
        supersedes_policy_bundle_id=None,
        effective_at=UTC_NOW - timedelta(days=30),
        effective_until=None,
        documents=(document,),
        required_document_ids=(document.document_id,),
        consent_offers=(),
    )
    release = sign_policy_release(manifest)
    store = IsolatedPolicyIssueStore()
    uow_factory = StrictPolicyIssueUowFactory(
        store=store,
        conflict_on_commit=conflict_on_commit,
    )
    verifier = StrictReleaseVerifier()
    actor = PolicyPublisherContext(
        system_id="system_policy_release_001",
        original_actor_id="user_legal_approver_001",
        correlation_id="correlation_policy_release_001",
        causation_id="causation_policy_release_001",
        trace_id="trace_policy_release_001",
    )
    command = PublishPolicyBundleCommand(
        command_id="command_publish_policy_001",
        release=release,
    )
    return PublicationFixture(
        store=store,
        uow_factory=uow_factory,
        verifier=verifier,
        actor=actor,
        command=command,
        handler=PublishPolicyBundleHandler(
            uow_factory=uow_factory,
            release_verifier=verifier,
            clock=FixedUtcClock(),
        ),
        selector_facts=selector,
        selector_digest=selector_digest,
    )


def publication_with_consent_offer_fixture() -> PublicationFixture:
    """A signed non-empty PILOT_RESEARCH release with exact document binding."""

    fixture = initial_publication_fixture()
    manifest = fixture.command.release.manifest
    consent_body = "Synthetic optional research consent v1."
    consent_document = PolicyDocumentRelease(
        document_id="policy_document_research_consent_0001",
        kind=PolicyDocumentKind.CONSENT_TEXT,
        semantic_version="1.0.0",
        locale=manifest.selector.locale,
        jurisdiction=manifest.selector.jurisdiction,
        canonical_body=consent_body,
        content_sha256=hashlib.sha256(
            consent_body.encode("utf-8")
        ).hexdigest(),
        legal_effect=PolicyLegalEffect.CONSENT_TEXT,
    )
    unsigned_offer = PolicyConsentOfferRelease(
        canonicalization_version="consent-offer-json-v1",
        consent_offer_id="consent_offer_pilot_research_0001",
        aggregate_version=1,
        policy_bundle_id=manifest.policy_bundle_id,
        purpose=ConsentPurpose.PILOT_RESEARCH,
        scope_type=ConsentScopeType.PLATFORM_PARTICIPATION,
        scope_derivation="PLATFORM_PARTICIPATION_NULL_SCOPE",
        data_categories=(
            DataCategory.PROFILE,
            DataCategory.MATCHING,
            DataCategory.RESEARCH,
        ),
        recipient_reference="research_controller_desire_supply_v1",
        recipient_label="Desire Supply Research",
        supporting_document_id=consent_document.document_id,
        supporting_document_sha256=consent_document.content_sha256,
        expiry_rule=(
            "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
        ),
        expiry_days=365,
        not_after=UTC_NOW + timedelta(days=180),
        optional=True,
        canonical_offer_sha256="0" * 64,
    )
    offer = replace(
        unsigned_offer,
        canonical_offer_sha256=canonical_consent_offer_sha256(
            unsigned_offer
        ),
    )
    manifest = replace(
        manifest,
        documents=manifest.documents + (consent_document,),
        consent_offers=(offer,),
    )
    fixture.command = replace(
        fixture.command,
        release=sign_policy_release(manifest),
    )
    return fixture


def replacement_publication_fixture() -> PublicationFixture:
    fixture = initial_publication_fixture()
    old_manifest = fixture.command.release.manifest
    old_document_release = old_manifest.documents[0]
    old_document = PolicyDocument(
        document_id=old_document_release.document_id,
        content_sha256=old_document_release.content_sha256,
        legal_effect=old_document_release.legal_effect,
    )
    old_bundle = PolicyBundle(
        policy_bundle_id=old_manifest.policy_bundle_id,
        selector_digest=fixture.selector_digest,
        status=PolicyBundleStatus.ACTIVE,
        effective_at=old_manifest.effective_at,
        effective_until=None,
        documents=(old_document,),
        required_document_ids=(old_document.document_id,),
        consent_offers=(),
    )
    fixture.store.seed(
        policy_selectors={
            fixture.selector_digest: {
                "selector_digest": fixture.selector_digest,
                "canonicalization_version": "policy-selector-json-v1",
                "access_purpose": InvitationPurpose.CREATOR_ENROLLMENT.value,
                "scope_type": PolicySelectorScopeType.USER_ROLE.value,
                "target_role": TargetRole.CREATOR.value,
                "jurisdiction": "GLOBAL",
                "locale": "en",
                "current_bundle_id": old_bundle.policy_bundle_id,
                "aggregate_version": 1,
            }
        },
        policy_bundles={old_bundle.policy_bundle_id: old_bundle},
        policy_documents={old_document.document_id: old_document},
    )
    body = "Synthetic creator terms v2."
    document = replace(
        old_document_release,
        document_id="policy_document_terms_0002",
        semantic_version="2.0.0",
        canonical_body=body,
        content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
    )
    manifest = replace(
        old_manifest,
        policy_bundle_id="policy_bundle_creator_0002",
        supersedes_policy_bundle_id=old_bundle.policy_bundle_id,
        effective_at=UTC_NOW,
        documents=(document,),
        required_document_ids=(document.document_id,),
    )
    fixture.command = PublishPolicyBundleCommand(
        command_id="command_publish_policy_002",
        release=sign_policy_release(manifest),
    )
    return fixture


def creator_issue_fixture() -> IssueFixture:
    selector = PolicySelectorFacts(
        canonicalization_version="policy-selector-json-v1",
        access_purpose=InvitationPurpose.CREATOR_ENROLLMENT,
        scope_type=PolicySelectorScopeType.USER_ROLE,
        target_role=TargetRole.CREATOR,
        jurisdiction="GLOBAL",
        locale="en",
    )
    return _issue_fixture(
        selector=selector,
        organization_id=None,
        expected_organization_version=None,
        actor_kind=IssuerKind.SYSTEM,
        target_role=TargetRole.CREATOR,
    )


def organization_issue_fixture(
    *,
    locale_unavailable: bool = False,
) -> IssueFixture:
    selector = PolicySelectorFacts(
        canonicalization_version="policy-selector-json-v1",
        access_purpose=InvitationPurpose.ORGANIZATION_MEMBERSHIP,
        scope_type=PolicySelectorScopeType.ORGANIZATION_ROLE,
        target_role=TargetRole.DEMAND_OWNER,
        jurisdiction="CN",
        locale="zh-CN",
    )
    return _issue_fixture(
        selector=selector,
        organization_id="organization_issue_target_001",
        expected_organization_version=3,
        actor_kind=IssuerKind.USER,
        target_role=TargetRole.DEMAND_OWNER,
        locale_unavailable=locale_unavailable,
    )


def _issue_fixture(
    *,
    selector: PolicySelectorFacts,
    organization_id: Optional[str],
    expected_organization_version: Optional[int],
    actor_kind: IssuerKind,
    target_role: TargetRole,
    locale_unavailable: bool = False,
) -> IssueFixture:
    selector_digest = policy_selector_digest(selector)
    document = PolicyDocument(
        document_id="policy_document_issue_terms_001",
        content_sha256="a" * 64,
        legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
    )
    bundle = PolicyBundle(
        policy_bundle_id="policy_bundle_issue_current_001",
        selector_digest=selector_digest,
        status=PolicyBundleStatus.ACTIVE,
        effective_at=UTC_NOW - timedelta(days=1),
        effective_until=UTC_NOW + timedelta(days=30),
        documents=(document,),
        required_document_ids=(document.document_id,),
        consent_offers=(),
    )
    store = IsolatedPolicyIssueStore()
    selector_row = {
        "selector_digest": selector_digest,
        "canonicalization_version": selector.canonicalization_version,
        "access_purpose": selector.access_purpose.value,
        "scope_type": selector.scope_type.value,
        "target_role": selector.target_role.value,
        "jurisdiction": selector.jurisdiction,
        "locale": selector.locale,
        "current_bundle_id": bundle.policy_bundle_id,
        "aggregate_version": 2,
    }
    store.seed(
        policy_selectors={selector_digest: selector_row},
        policy_bundles={bundle.policy_bundle_id: bundle},
    )
    if organization_id is not None:
        store.seed(
            organizations={
                organization_id: {
                    "organization_id": organization_id,
                    "status": "ACTIVE",
                    "jurisdiction": "CN",
                    "aggregate_version": 3,
                }
            },
            memberships={
                "membership_issuer_admin_001": {
                    "membership_id": "membership_issuer_admin_001",
                    "organization_id": organization_id,
                    "user_id": "user_issuer_admin_001",
                    "status": "ACTIVE",
                    "aggregate_version": 1,
                }
            },
            membership_role_grants={
                "membership_role_issuer_admin_001": {
                    "membership_role_grant_id": (
                        "membership_role_issuer_admin_001"
                    ),
                    "membership_id": "membership_issuer_admin_001",
                    "organization_id": organization_id,
                    "user_id": "user_issuer_admin_001",
                    "role": "ORG_ADMIN",
                    "revoked_at": None,
                }
            },
        )
    uow_factory = StrictPolicyIssueUowFactory(store=store)
    clock = FixedUtcClock()
    platform_policy = StrictPlatformEnrollmentPolicy()
    locale_resolver = StrictLocaleResolver(
        locale=selector.locale,
        unavailable=locale_unavailable,
    )
    hold = StrictFakeSafetyHold(
        decision=HoldDecision.ALLOW,
        evaluated_at=UTC_NOW,
        valid_until=UTC_NOW + timedelta(seconds=30),
    )
    token_codec = StrictInvitationTokenCodec()
    recipient_binding = StrictRecipientBinding()
    receipt_codec = StrictReceiptCodec()
    id_source = FixedIdSource(
        {
            "contact_point": ["contact_point_issue_001"],
            "access_invitation": ["access_invitation_issue_001"],
            "command_receipt": ["command_receipt_issue_001"],
            "audit_event": ["audit_event_issue_001"],
            "outbox_event": ["outbox_event_issue_001"],
        }
    )
    secret_source = FixedSecretSource()
    actor_id = (
        "system_invitation_issuer_001"
        if actor_kind == IssuerKind.SYSTEM
        else "user_issuer_admin_001"
    )
    actor = InvitationIssuerContext(
        actor_kind=actor_kind,
        actor_id=actor_id,
        session_id=(
            None if actor_kind == IssuerKind.SYSTEM else "session_issuer_001"
        ),
        original_actor_id=None,
        correlation_id="correlation_issue_001",
        causation_id="causation_issue_001",
        trace_id="trace_issue_0001",
        auth_time=UTC_NOW - timedelta(minutes=2),
        acr_code="urn:desire:acr:mfa",
        amr_codes=("pwd", "otp"),
    )
    command = IssueAccessInvitationCommand(
        organization_id=organization_id,
        expected_organization_version=expected_organization_version,
        recipient=RecipientInput(
            type=RecipientContactType.EMAIL,
            value="Applicant@Example.Test ",
        ),
        target_role=target_role,
        expires_at=UTC_NOW + timedelta(days=7),
        idempotency_key="issue-idempotency-key-001",
    )
    handler = IssueAccessInvitationHandler(
        uow_factory=uow_factory,
        clock=clock,
        platform_enrollment_policy=platform_policy,
        locale_resolver=locale_resolver,
        safety_hold=hold,
        safety_hold_policy_version=SAFETY_HOLD_POLICY_VERSION,
        release_token_codec=token_codec,
        recipient_binding=recipient_binding,
        receipt_codec=receipt_codec,
        id_source=id_source,
        secret_source=secret_source,
    )
    return IssueFixture(
        store=store,
        uow_factory=uow_factory,
        clock=clock,
        platform_policy=platform_policy,
        locale_resolver=locale_resolver,
        hold=hold,
        token_codec=token_codec,
        recipient_binding=recipient_binding,
        receipt_codec=receipt_codec,
        id_source=id_source,
        secret_source=secret_source,
        actor=actor,
        command=command,
        handler=handler,
        selector_facts=selector,
        selector_digest=selector_digest,
        current_bundle=bundle,
    )
