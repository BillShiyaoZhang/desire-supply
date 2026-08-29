"""Strict independent fixtures for policy acceptance and consent command REDs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional, Sequence
import unicodedata

from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    AcceptCurrentPoliciesHandler,
    GrantConsentCommand,
    GrantConsentHandler,
    PolicyConsentActor,
    PolicyRequirementReference,
    PolicyRequirementScopeType,
)
from desire_platform.identity_access.domain.policies import (
    ConsentOffer,
    ConsentOfferChoice,
    ConsentPurpose,
    ConsentScopeType,
    DataCategory,
    PolicyAcceptance,
    PolicyBundle,
    PolicyBundleStatus,
    PolicyDocument,
    PolicyDocumentStatus,
    PolicyLegalEffect,
)
from desire_platform.identity_access.ports.policy_consent_commands import (
    PolicyConsentCommitOutcomeUnknownError,
    PolicyConsentKeyUnavailableError,
    PolicyConsentStorageUnavailableError,
    PolicyConsentTelemetryEvent,
)
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)
PILOT_NOT_AFTER = NOW + timedelta(days=180)

ACTOR_USER_ID = "user_policy_consent_0001"
OTHER_USER_ID = "user_policy_consent_other_0002"
SESSION_FAMILY_ID = "session_family_policy_consent_0001"
SESSION_ID = "session_policy_consent_current_0001"
AUTH_TRANSACTION_ID = "auth_transaction_policy_consent_0001"
ORGANIZATION_ALPHA_ID = "organization_policy_alpha_0001"
ORGANIZATION_BETA_ID = "organization_policy_beta_0002"
MEMBERSHIP_ALPHA_ID = "membership_policy_alpha_0001"
MEMBERSHIP_BETA_ID = "membership_policy_beta_0002"
CREATOR_ROLE_GRANT_ID = "user_role_grant_creator_policy_0001"
ALPHA_ROLE_GRANT_ID = "membership_role_grant_alpha_0001"
BETA_ROLE_GRANT_ID = "membership_role_grant_beta_0002"
CREATOR_SOURCE_INVITATION_ID = "invitation_creator_source_0001"
ALPHA_SOURCE_INVITATION_ID = "invitation_alpha_source_0001"
BETA_SOURCE_INVITATION_ID = "invitation_beta_source_0002"

CREATOR_BUNDLE_V1_ID = "policy_bundle_creator_historical_0001"
CREATOR_BUNDLE_ID = "policy_bundle_creator_current_0002"
ALPHA_BUNDLE_ID = "policy_bundle_org_alpha_current_0001"
BETA_BUNDLE_ID = "policy_bundle_org_beta_current_0001"

CREATOR_TERMS_ID = "policy_document_creator_terms_0001"
CREATOR_PRIVACY_ID = "policy_document_creator_privacy_0001"
CREATOR_CONSENT_ID = "policy_document_creator_consent_0001"
ALPHA_TERMS_ID = "policy_document_alpha_terms_0001"
BETA_TERMS_ID = "policy_document_beta_terms_0001"
CONSENT_OFFER_ID = "consent_offer_pilot_research_0001"

EXISTING_TERMS_ACCEPTANCE_ID = "policy_acceptance_creator_terms_0001"
EXISTING_PRIVACY_ACCEPTANCE_ID = "policy_acceptance_creator_privacy_0001"

ACCEPT_IDEMPOTENCY_KEY = "SECRET-idempotency-accept-policy-0001"
GRANT_IDEMPOTENCY_KEY = "SECRET-idempotency-grant-consent-0001"
SESSION_DIGEST_SENTINEL = "SECRET-persisted-session-digest-sentinel"
INTERNAL_RECIPIENT_SENTINEL = "SECRET-internal-research-recipient-reference"
POLICY_BODY_SENTINEL = "SECRET-policy-body-must-not-enter-command-evidence"
TRACE_ID = "trace_policy_consent_0001"

RECEIPT_IDENTITY_KEY_ID = "iam-self-command-identity-key-2026-08"
RECEIPT_PAYLOAD_KEY_ID = "iam-self-command-payload-key-2026-08"
OLD_RECEIPT_IDENTITY_KEY_ID = "iam-self-command-identity-key-2026-01"
OLD_RECEIPT_PAYLOAD_KEY_ID = "iam-self-command-payload-key-2026-01"
SESSION_HANDLE_KEY_ID = "iam-session-handle-key-2026-08"
SESSION_CSRF_KEY_ID = "iam-session-csrf-key-2026-08"


def _selector_digest(
    *, access_purpose: str, scope_type: str, target_role: str
) -> str:
    value = {
        "access_purpose": access_purpose,
        "scope_type": scope_type,
        "target_role": target_role,
        "jurisdiction": "CN",
        "locale": "zh-CN",
    }
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


CREATOR_SELECTOR_DIGEST = _selector_digest(
    access_purpose="CREATOR_ENROLLMENT",
    scope_type="USER_ROLE",
    target_role="CREATOR",
)
ALPHA_SELECTOR_DIGEST = _selector_digest(
    access_purpose="ORGANIZATION_MEMBERSHIP",
    scope_type="ORGANIZATION_ROLE",
    target_role="ORG_ADMIN",
)
BETA_SELECTOR_DIGEST = _selector_digest(
    access_purpose="ORGANIZATION_MEMBERSHIP",
    scope_type="ORGANIZATION_ROLE",
    target_role="DEMAND_OWNER",
)
UNKNOWN_SELECTOR_DIGEST = "f" * 64


class FixedPolicyConsentClock:
    def __init__(self, current: datetime = NOW) -> None:
        self.current = current
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.current


class FixedPolicyConsentIdSource:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.counts: dict[str, int] = {}

    def new_id(self, kind: str) -> str:
        self.calls.append(kind)
        number = self.counts.get(kind, 0) + 1
        self.counts[kind] = number
        return f"{kind}_policy_consent_{number:04d}"


class StrictPolicyConsentKeyring:
    idempotency_key_digest_key_id = RECEIPT_IDENTITY_KEY_ID
    payload_hash_key_id = RECEIPT_PAYLOAD_KEY_ID
    session_handle_digest_key_id = SESSION_HANDLE_KEY_ID
    csrf_key_id = SESSION_CSRF_KEY_ID
    retained_idempotency_key_digest_key_ids = (
        OLD_RECEIPT_IDENTITY_KEY_ID,
        RECEIPT_IDENTITY_KEY_ID,
    )
    retained_payload_hash_key_ids = (
        OLD_RECEIPT_PAYLOAD_KEY_ID,
        RECEIPT_PAYLOAD_KEY_ID,
    )

    def __init__(self) -> None:
        self.keys = {
            RECEIPT_IDENTITY_KEY_ID: hashlib.sha256(b"self-command-identity").digest(),
            RECEIPT_PAYLOAD_KEY_ID: hashlib.sha256(b"self-command-payload").digest(),
            OLD_RECEIPT_IDENTITY_KEY_ID: hashlib.sha256(
                b"self-command-identity-old"
            ).digest(),
            OLD_RECEIPT_PAYLOAD_KEY_ID: hashlib.sha256(
                b"self-command-payload-old"
            ).digest(),
            SESSION_HANDLE_KEY_ID: hashlib.sha256(b"self-session-handle").digest(),
            SESSION_CSRF_KEY_ID: hashlib.sha256(b"self-session-csrf").digest(),
        }
        self.calls: list[tuple[str, bytes]] = []

    def remove_key(self, key_id: str) -> None:
        self.keys.pop(key_id, None)

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        self.calls.append((key_id, bytes(canonical_bytes)))
        try:
            key = self.keys[key_id]
        except KeyError as error:
            raise PolicyConsentKeyUnavailableError("synthetic key unavailable") from error
        return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()


class RecordingPolicyConsentTelemetry:
    def __init__(self) -> None:
        self.events: list[PolicyConsentTelemetryEvent] = []

    def record(self, event: PolicyConsentTelemetryEvent) -> None:
        if not isinstance(event, PolicyConsentTelemetryEvent):
            raise AssertionError("telemetry must use the closed event value")
        self.events.append(event)


class StrictPolicyConsentStore:
    def __init__(self, tables: Mapping[str, Mapping[Any, Any]]) -> None:
        self._tables = deepcopy(dict(tables))

    def snapshot(self) -> dict[str, dict[Any, Any]]:
        return deepcopy(self._tables)

    def replace_fact(self, table: str, key: Any, **changes: Any) -> None:
        current = deepcopy(self._tables[table][key])
        if not isinstance(current, dict):
            raise TypeError("replace_fact only supports mapping facts")
        current.update(changes)
        self._tables[table][key] = current

    def set_fact(self, table: str, key: Any, value: Any) -> None:
        self._tables.setdefault(table, {})[key] = deepcopy(value)

    def remove_fact(self, table: str, key: Any) -> None:
        self._tables.get(table, {}).pop(key, None)


class StrictPolicyConsentUowFactory:
    def __init__(
        self,
        *,
        store: StrictPolicyConsentStore,
        fail_on_checkpoint: Optional[str] = None,
        commit_mode: str = "normal",
    ) -> None:
        self.store = store
        self.fail_on_checkpoint = fail_on_checkpoint
        self.commit_mode = commit_mode
        self.begin_count = 0
        self.lock_calls: list[tuple[str, tuple[Any, ...]]] = []
        self.write_checkpoints: list[str] = []
        self.write_values: list[tuple[str, Any, Any]] = []
        self.commit_count = 0
        self.before_begin = None

    def begin(self) -> "StrictPolicyConsentUow":
        self.begin_count += 1
        if self.before_begin is not None:
            self.before_begin(self.begin_count)
        return StrictPolicyConsentUow(self)


class StrictPolicyConsentUow:
    def __init__(self, factory: StrictPolicyConsentUowFactory) -> None:
        self.factory = factory
        self.tables = factory.store.snapshot()

    def __enter__(self) -> "StrictPolicyConsentUow":
        return self

    def __exit__(self, exception_type, exception, traceback) -> bool:
        return False

    def lock(self, table: str, keys: Sequence[Any]) -> None:
        normalized = tuple(keys)
        if len(normalized) > 1 and normalized != tuple(sorted(normalized)):
            raise AssertionError("same-level policy/consent locks must be stable")
        self.factory.lock_calls.append((table, normalized))

    def get(self, table: str, key: Any) -> Any:
        return self.tables.get(table, {}).get(key)

    def values(self, table: str) -> Sequence[Any]:
        return tuple(self.tables.get(table, {}).values())

    def put(self, table: str, key: Any, value: Any, *, checkpoint: str) -> None:
        if not checkpoint or checkpoint in self.factory.write_checkpoints:
            raise AssertionError("write checkpoints must be non-empty and unique")
        self.factory.write_checkpoints.append(checkpoint)
        self.factory.write_values.append((table, key, deepcopy(value)))
        if checkpoint == self.factory.fail_on_checkpoint:
            raise PolicyConsentStorageUnavailableError("synthetic pre-commit fault")
        self.tables.setdefault(table, {})[key] = deepcopy(value)

    def commit(self) -> None:
        self.factory.commit_count += 1
        if self.factory.commit_mode == "unavailable":
            raise PolicyConsentStorageUnavailableError("synthetic commit not sent")
        if self.factory.commit_mode == "unknown_not_landed":
            raise PolicyConsentCommitOutcomeUnknownError("synthetic unknown outcome")
        self.factory.store._tables = deepcopy(self.tables)
        if self.factory.commit_mode == "unknown_landed":
            raise PolicyConsentCommitOutcomeUnknownError("synthetic landed outcome")


@dataclass
class PolicyConsentCommandFixture:
    store: StrictPolicyConsentStore
    uow_factory: StrictPolicyConsentUowFactory
    clock: FixedPolicyConsentClock
    id_source: FixedPolicyConsentIdSource
    keyring: StrictPolicyConsentKeyring
    event_validator: ClosedSchemaValidator
    response_validator: ClosedSchemaValidator
    telemetry: RecordingPolicyConsentTelemetry
    actor: PolicyConsentActor
    accept_command: AcceptCurrentPoliciesCommand
    grant_command: GrantConsentCommand
    accept_handler: AcceptCurrentPoliciesHandler
    grant_handler: GrantConsentHandler

    def restart_handlers(self) -> None:
        self.accept_handler = _accept_handler(self)
        self.grant_handler = _grant_handler(self)


def _document(
    *,
    document_id: str,
    body: str,
    legal_effect: PolicyLegalEffect,
    kind: str,
    semantic_version: str,
) -> PolicyDocument:
    return PolicyDocument(
        document_id=document_id,
        content_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        legal_effect=legal_effect,
        kind=kind,
        semantic_version=semantic_version,
        locale="zh-CN",
        jurisdiction="CN",
        canonical_body=body,
        status=PolicyDocumentStatus.ACTIVE,
        effective_at=NOW - timedelta(days=30),
        superseded_by_document_id=None,
        publication_command_id=f"publication_{document_id}",
        created_at=NOW - timedelta(days=30),
        updated_at=NOW - timedelta(days=30),
    )


def _offer_digest_payload(
    *,
    policy_bundle_id: str,
    supporting_document: PolicyDocument,
) -> dict[str, Any]:
    return {
        "canonicalization_version": "consent-offer-json-v1",
        "consent_offer_id": CONSENT_OFFER_ID,
        "consent_offer_version": 1,
        "policy_bundle_id": policy_bundle_id,
        "purpose": "PILOT_RESEARCH",
        "scope_type": "PLATFORM_PARTICIPATION",
        "scope_derivation": "PLATFORM_PARTICIPATION_NULL_SCOPE",
        "data_categories": ["PROFILE", "MATCHING", "RESEARCH"],
        "recipient_ref": INTERNAL_RECIPIENT_SENTINEL,
        "recipient_label": "Desire Supply Research",
        "supporting_document_id": supporting_document.document_id,
        "supporting_document_sha256": supporting_document.content_sha256,
        "expiry_rule": "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER",
        "expiry_days": 365,
        "not_after": PILOT_NOT_AFTER.isoformat().replace("+00:00", "Z"),
        "optional": True,
    }


def canonical_offer_sha256(
    *, policy_bundle_id: str, supporting_document: PolicyDocument
) -> str:
    canonical = json.dumps(
        _offer_digest_payload(
            policy_bundle_id=policy_bundle_id,
            supporting_document=supporting_document,
        ),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _creator_bundles() -> tuple[PolicyBundle, PolicyBundle]:
    terms = _document(
        document_id=CREATOR_TERMS_ID,
        body="Creator terms v1. " + POLICY_BODY_SENTINEL,
        legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
        kind="TERMS",
        semantic_version="1.0.0",
    )
    privacy = _document(
        document_id=CREATOR_PRIVACY_ID,
        body="Creator privacy notice v1.",
        legal_effect=PolicyLegalEffect.NOTICE_ACKNOWLEDGEMENT,
        kind="PRIVACY_NOTICE",
        semantic_version="1.0.0",
    )
    consent = _document(
        document_id=CREATOR_CONSENT_ID,
        body="Optional research consent v1.",
        legal_effect=PolicyLegalEffect.CONSENT_TEXT,
        kind="CONSENT_TEXT",
        semantic_version="1.0.0",
    )
    offer = ConsentOffer.pilot_research(
        consent_offer_id=CONSENT_OFFER_ID,
        aggregate_version=1,
        supporting_document_id=consent.document_id,
        supporting_document_sha256=consent.content_sha256,
        recipient_reference=INTERNAL_RECIPIENT_SENTINEL,
        pilot_ends_at=PILOT_NOT_AFTER,
        policy_bundle_id=CREATOR_BUNDLE_ID,
        recipient_label="Desire Supply Research",
        canonical_offer_sha256=canonical_offer_sha256(
            policy_bundle_id=CREATOR_BUNDLE_ID,
            supporting_document=consent,
        ),
    )
    old = PolicyBundle(
        policy_bundle_id=CREATOR_BUNDLE_V1_ID,
        selector_digest=CREATOR_SELECTOR_DIGEST,
        status=PolicyBundleStatus.SUPERSEDED,
        effective_at=NOW - timedelta(days=90),
        effective_until=NOW - timedelta(days=30),
        documents=(terms, privacy),
        required_document_ids=(terms.document_id, privacy.document_id),
        consent_offers=(),
        superseded_by_bundle_id=CREATOR_BUNDLE_ID,
        release_manifest_sha256="1" * 64,
        release_signature_algorithm="ED25519",
        release_signature_key_id="policy_release_key_historical_0001",
        release_signature="synthetic-historical-signature",
        publication_command_id="publication_creator_bundle_historical_0001",
        aggregate_version=2,
        created_at=NOW - timedelta(days=90),
        updated_at=NOW - timedelta(days=30),
    )
    current = PolicyBundle(
        policy_bundle_id=CREATOR_BUNDLE_ID,
        selector_digest=CREATOR_SELECTOR_DIGEST,
        status=PolicyBundleStatus.ACTIVE,
        effective_at=NOW - timedelta(days=30),
        effective_until=None,
        documents=(terms, privacy, consent),
        required_document_ids=(terms.document_id, privacy.document_id),
        consent_offers=(offer,),
        release_manifest_sha256="2" * 64,
        release_signature_algorithm="ED25519",
        release_signature_key_id="policy_release_key_current_0002",
        release_signature="synthetic-current-signature",
        publication_command_id="publication_creator_bundle_current_0002",
        aggregate_version=1,
        created_at=NOW - timedelta(days=30),
        updated_at=NOW - timedelta(days=30),
    )
    return old, current


def _organization_bundle(
    *,
    bundle_id: str,
    selector_digest: str,
    document_id: str,
    label: str,
) -> PolicyBundle:
    document = _document(
        document_id=document_id,
        body=f"{label} organization terms v1.",
        legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
        kind="TERMS",
        semantic_version="1.0.0",
    )
    return PolicyBundle(
        policy_bundle_id=bundle_id,
        selector_digest=selector_digest,
        status=PolicyBundleStatus.ACTIVE,
        effective_at=NOW - timedelta(days=7),
        effective_until=None,
        documents=(document,),
        required_document_ids=(document.document_id,),
        consent_offers=(),
        release_manifest_sha256=("3" if label == "Alpha" else "4") * 64,
        release_signature_algorithm="ED25519",
        release_signature_key_id=f"policy_release_key_{label.lower()}_0001",
        release_signature=f"synthetic-{label.lower()}-signature",
        publication_command_id=f"publication_{label.lower()}_bundle_0001",
        aggregate_version=1,
        created_at=NOW - timedelta(days=7),
        updated_at=NOW - timedelta(days=7),
    )


def _selector(
    *,
    selector_digest: str,
    purpose: str,
    scope_type: str,
    role: str,
    current_bundle_id: str,
) -> dict[str, Any]:
    return {
        "selector_digest": selector_digest,
        "canonicalization_version": "policy-selector-json-v1",
        "access_purpose": purpose,
        "scope_type": scope_type,
        "target_role": role,
        "jurisdiction": "CN",
        "locale": "zh-CN",
        "current_bundle_id": current_bundle_id,
        "aggregate_version": 1,
    }


def _source_invitation(
    *,
    invitation_id: str,
    purpose: str,
    target_scope: str,
    role: str,
    organization_id: Optional[str],
    selector_digest: str,
) -> dict[str, Any]:
    return {
        "invitation_id": invitation_id,
        "purpose": purpose,
        "target_scope": target_scope,
        "target_role": role,
        "organization_id": organization_id,
        "policy_selector_digest": selector_digest,
        "status": "ACCEPTED",
        "accepted_by_user_id": ACTOR_USER_ID,
        "aggregate_version": 2,
    }


def _acceptance(
    *, acceptance_id: str, document: PolicyDocument
) -> dict[str, Any]:
    return {
        "policy_acceptance_id": acceptance_id,
        "user_id": ACTOR_USER_ID,
        "document_id": document.document_id,
        "content_sha256": document.content_sha256,
        # Deliberately historical: immutable evidence remains valid when the
        # exact document is reused by the current bundle.
        "bundle_id": CREATOR_BUNDLE_V1_ID,
        "accepted_at": NOW - timedelta(days=45),
        "session_id": SESSION_ID,
        "auth_transaction_id": AUTH_TRANSACTION_ID,
        "auth_time": NOW - timedelta(days=45, minutes=2),
        "acr_code": "urn:desire:acr:mfa",
        "amr_codes": ("otp", "pwd"),
        "source_action": "POLICY_ACCEPT",
        "command_id": "command_historical_acceptance_0001",
        "correlation_id": "correlation_historical_acceptance_0001",
        "aggregate_version": 1,
        "created_at": NOW - timedelta(days=45),
    }


def policy_consent_command_fixture(
    *,
    fail_on_checkpoint: Optional[str] = None,
    commit_mode: str = "normal",
) -> PolicyConsentCommandFixture:
    old_creator, creator = _creator_bundles()
    alpha = _organization_bundle(
        bundle_id=ALPHA_BUNDLE_ID,
        selector_digest=ALPHA_SELECTOR_DIGEST,
        document_id=ALPHA_TERMS_ID,
        label="Alpha",
    )
    beta = _organization_bundle(
        bundle_id=BETA_BUNDLE_ID,
        selector_digest=BETA_SELECTOR_DIGEST,
        document_id=BETA_TERMS_ID,
        label="Beta",
    )
    creator_documents = {item.document_id: item for item in creator.documents}
    tables: dict[str, dict[Any, Any]] = {
        "users": {
            ACTOR_USER_ID: {
                "user_id": ACTOR_USER_ID,
                "status": "ACTIVE",
                "aggregate_version": 7,
                "stable_handle": "policy-consent-user",
            }
        },
        "auth_transactions": {
            AUTH_TRANSACTION_ID: {
                "auth_transaction_id": AUTH_TRANSACTION_ID,
                "purpose": "LOGIN",
                "status": "SUCCEEDED",
                "resolved_user_id": ACTOR_USER_ID,
                "aggregate_version": 3,
            }
        },
        "session_families": {
            SESSION_FAMILY_ID: {
                "session_family_id": SESSION_FAMILY_ID,
                "user_id": ACTOR_USER_ID,
                "status": "ACTIVE",
                "current_generation": 2,
                "aggregate_version": 2,
            }
        },
        "sessions": {
            SESSION_ID: {
                "session_id": SESSION_ID,
                "session_family_id": SESSION_FAMILY_ID,
                "user_id": ACTOR_USER_ID,
                "generation": 2,
                "status": "ACTIVE",
                "auth_transaction_id": AUTH_TRANSACTION_ID,
                "auth_time": NOW - timedelta(minutes=5),
                "acr_code": "urn:desire:acr:mfa",
                "amr_codes": ("otp", "pwd"),
                "created_at": NOW - timedelta(minutes=5),
                "last_activity_at": NOW - timedelta(minutes=1),
                "idle_expires_at": NOW + timedelta(minutes=29),
                "absolute_expires_at": NOW + timedelta(hours=8),
                "handle_digest": SESSION_DIGEST_SENTINEL,
                "handle_digest_key_id": SESSION_HANDLE_KEY_ID,
                "csrf_key_id": SESSION_CSRF_KEY_ID,
                "aggregate_version": 1,
            }
        },
        "organizations": {
            ORGANIZATION_ALPHA_ID: {
                "organization_id": ORGANIZATION_ALPHA_ID,
                "status": "ACTIVE",
                "aggregate_version": 3,
            },
            ORGANIZATION_BETA_ID: {
                "organization_id": ORGANIZATION_BETA_ID,
                "status": "ACTIVE",
                "aggregate_version": 5,
            },
        },
        "memberships": {
            MEMBERSHIP_ALPHA_ID: {
                "membership_id": MEMBERSHIP_ALPHA_ID,
                "organization_id": ORGANIZATION_ALPHA_ID,
                "user_id": ACTOR_USER_ID,
                "source_invitation_id": ALPHA_SOURCE_INVITATION_ID,
                "status": "ACTIVE",
                "aggregate_version": 2,
            },
            MEMBERSHIP_BETA_ID: {
                "membership_id": MEMBERSHIP_BETA_ID,
                "organization_id": ORGANIZATION_BETA_ID,
                "user_id": ACTOR_USER_ID,
                "source_invitation_id": BETA_SOURCE_INVITATION_ID,
                "status": "ACTIVE",
                "aggregate_version": 4,
            },
        },
        "user_role_grants": {
            CREATOR_ROLE_GRANT_ID: {
                "role_grant_id": CREATOR_ROLE_GRANT_ID,
                "user_id": ACTOR_USER_ID,
                "role_code": "CREATOR",
                "source_invitation_id": CREATOR_SOURCE_INVITATION_ID,
                "policy_selector_digest": CREATOR_SELECTOR_DIGEST,
                "revoked_at": None,
            }
        },
        "membership_role_grants": {
            # Alpha deliberately sorts before the selected Beta grant.
            ALPHA_ROLE_GRANT_ID: {
                "role_grant_id": ALPHA_ROLE_GRANT_ID,
                "membership_id": MEMBERSHIP_ALPHA_ID,
                "organization_id": ORGANIZATION_ALPHA_ID,
                "user_id": ACTOR_USER_ID,
                "role_code": "ORG_ADMIN",
                "source_invitation_id": ALPHA_SOURCE_INVITATION_ID,
                "policy_selector_digest": ALPHA_SELECTOR_DIGEST,
                "revoked_at": None,
            },
            BETA_ROLE_GRANT_ID: {
                "role_grant_id": BETA_ROLE_GRANT_ID,
                "membership_id": MEMBERSHIP_BETA_ID,
                "organization_id": ORGANIZATION_BETA_ID,
                "user_id": ACTOR_USER_ID,
                "role_code": "DEMAND_OWNER",
                "source_invitation_id": BETA_SOURCE_INVITATION_ID,
                "policy_selector_digest": BETA_SELECTOR_DIGEST,
                "revoked_at": None,
            },
        },
        "invitations": {
            CREATOR_SOURCE_INVITATION_ID: _source_invitation(
                invitation_id=CREATOR_SOURCE_INVITATION_ID,
                purpose="CREATOR_ENROLLMENT",
                target_scope="USER",
                role="CREATOR",
                organization_id=None,
                selector_digest=CREATOR_SELECTOR_DIGEST,
            ),
            ALPHA_SOURCE_INVITATION_ID: _source_invitation(
                invitation_id=ALPHA_SOURCE_INVITATION_ID,
                purpose="ORGANIZATION_MEMBERSHIP",
                target_scope="ORGANIZATION",
                role="ORG_ADMIN",
                organization_id=ORGANIZATION_ALPHA_ID,
                selector_digest=ALPHA_SELECTOR_DIGEST,
            ),
            BETA_SOURCE_INVITATION_ID: _source_invitation(
                invitation_id=BETA_SOURCE_INVITATION_ID,
                purpose="ORGANIZATION_MEMBERSHIP",
                target_scope="ORGANIZATION",
                role="DEMAND_OWNER",
                organization_id=ORGANIZATION_BETA_ID,
                selector_digest=BETA_SELECTOR_DIGEST,
            ),
        },
        "policy_selectors": {
            CREATOR_SELECTOR_DIGEST: _selector(
                selector_digest=CREATOR_SELECTOR_DIGEST,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
                current_bundle_id=CREATOR_BUNDLE_ID,
            ),
            ALPHA_SELECTOR_DIGEST: _selector(
                selector_digest=ALPHA_SELECTOR_DIGEST,
                purpose="ORGANIZATION_MEMBERSHIP",
                scope_type="ORGANIZATION_ROLE",
                role="ORG_ADMIN",
                current_bundle_id=ALPHA_BUNDLE_ID,
            ),
            BETA_SELECTOR_DIGEST: _selector(
                selector_digest=BETA_SELECTOR_DIGEST,
                purpose="ORGANIZATION_MEMBERSHIP",
                scope_type="ORGANIZATION_ROLE",
                role="DEMAND_OWNER",
                current_bundle_id=BETA_BUNDLE_ID,
            ),
        },
        "policy_bundles": {
            CREATOR_BUNDLE_V1_ID: old_creator,
            CREATOR_BUNDLE_ID: creator,
            ALPHA_BUNDLE_ID: alpha,
            BETA_BUNDLE_ID: beta,
        },
        "policy_acceptances": {
            EXISTING_TERMS_ACCEPTANCE_ID: _acceptance(
                acceptance_id=EXISTING_TERMS_ACCEPTANCE_ID,
                document=creator_documents[CREATOR_TERMS_ID],
            ),
            EXISTING_PRIVACY_ACCEPTANCE_ID: _acceptance(
                acceptance_id=EXISTING_PRIVACY_ACCEPTANCE_ID,
                document=creator_documents[CREATOR_PRIVACY_ID],
            ),
        },
        "consent_grants": {},
        "command_receipts": {},
        "audit_events": {},
        "outbox_events": {},
    }
    store = StrictPolicyConsentStore(tables)
    uow_factory = StrictPolicyConsentUowFactory(
        store=store,
        fail_on_checkpoint=fail_on_checkpoint,
        commit_mode=commit_mode,
    )
    clock = FixedPolicyConsentClock()
    id_source = FixedPolicyConsentIdSource()
    keyring = StrictPolicyConsentKeyring()
    event_validator = ClosedSchemaValidator.for_events()
    response_validator = ClosedSchemaValidator.for_openapi()
    telemetry = RecordingPolicyConsentTelemetry()
    actor = PolicyConsentActor(
        actor_user_id=ACTOR_USER_ID,
        current_session_id=SESSION_ID,
        original_actor_id=None,
        correlation_id="correlation_policy_consent_0001",
        causation_id="causation_policy_consent_0001",
        trace_id=TRACE_ID,
    )
    accept_command = AcceptCurrentPoliciesCommand(
        policy_requirement=PolicyRequirementReference(
            selector_digest=BETA_SELECTOR_DIGEST,
            scope_type=PolicyRequirementScopeType.ORGANIZATION_ROLE,
            scope_id=ORGANIZATION_BETA_ID,
        ),
        policy_bundle_id=BETA_BUNDLE_ID,
        policy_acceptances=tuple(
            PolicyAcceptance(
                document_id=document_id,
                content_sha256=next(
                    item.content_sha256
                    for item in beta.documents
                    if item.document_id == document_id
                ),
                affirmed=True,
            )
            for document_id in beta.required_document_ids
        ),
        expected_user_version=7,
        idempotency_key=ACCEPT_IDEMPOTENCY_KEY,
    )
    offer = creator.consent_offers[0]
    grant_command = GrantConsentCommand(
        policy_requirement=PolicyRequirementReference(
            selector_digest=CREATOR_SELECTOR_DIGEST,
            scope_type=PolicyRequirementScopeType.USER_ROLE,
            scope_id=None,
        ),
        policy_bundle_id=CREATOR_BUNDLE_ID,
        consent_choice=ConsentOfferChoice(
            consent_offer_id=offer.consent_offer_id,
            document_id=offer.supporting_document_id,
            content_sha256=offer.supporting_document_sha256,
            affirmed=True,
        ),
        expected_user_version=7,
        idempotency_key=GRANT_IDEMPOTENCY_KEY,
    )
    fixture = PolicyConsentCommandFixture(
        store=store,
        uow_factory=uow_factory,
        clock=clock,
        id_source=id_source,
        keyring=keyring,
        event_validator=event_validator,
        response_validator=response_validator,
        telemetry=telemetry,
        actor=actor,
        accept_command=accept_command,
        grant_command=grant_command,
        accept_handler=None,  # type: ignore[arg-type]
        grant_handler=None,  # type: ignore[arg-type]
    )
    fixture.restart_handlers()
    return fixture


def _accept_handler(fixture: PolicyConsentCommandFixture) -> AcceptCurrentPoliciesHandler:
    return AcceptCurrentPoliciesHandler(
        uow_factory=fixture.uow_factory,
        clock=fixture.clock,
        id_source=fixture.id_source,
        keyring=fixture.keyring,
        event_validator=fixture.event_validator,
        safe_response_validator=fixture.response_validator,
        telemetry=fixture.telemetry,
    )


def _grant_handler(fixture: PolicyConsentCommandFixture) -> GrantConsentHandler:
    return GrantConsentHandler(
        uow_factory=fixture.uow_factory,
        clock=fixture.clock,
        id_source=fixture.id_source,
        keyring=fixture.keyring,
        event_validator=fixture.event_validator,
        safe_response_validator=fixture.response_validator,
        telemetry=fixture.telemetry,
    )


def expected_accept_body() -> dict[str, Any]:
    return {
        "selector_digest": BETA_SELECTOR_DIGEST,
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "role": "DEMAND_OWNER",
        "scope_type": "ORGANIZATION_ROLE",
        "scope_id": ORGANIZATION_BETA_ID,
        "satisfied": True,
        "required_policy_bundle_id": BETA_BUNDLE_ID,
        "missing_document_ids": [],
    }


def expected_creator_accept_body() -> dict[str, Any]:
    return {
        "selector_digest": CREATOR_SELECTOR_DIGEST,
        "purpose": "CREATOR_ENROLLMENT",
        "role": "CREATOR",
        "scope_type": "USER_ROLE",
        "scope_id": None,
        "satisfied": True,
        "required_policy_bundle_id": CREATOR_BUNDLE_ID,
        "missing_document_ids": [],
    }


def creator_accept_command(
    fixture: PolicyConsentCommandFixture,
    *,
    idempotency_key: str = "SECRET-idempotency-creator-policy-0002",
) -> AcceptCurrentPoliciesCommand:
    bundle = fixture.store.snapshot()["policy_bundles"][CREATOR_BUNDLE_ID]
    documents = {item.document_id: item for item in bundle.documents}
    return AcceptCurrentPoliciesCommand(
        policy_requirement=PolicyRequirementReference(
            selector_digest=CREATOR_SELECTOR_DIGEST,
            scope_type=PolicyRequirementScopeType.USER_ROLE,
            scope_id=None,
        ),
        policy_bundle_id=CREATOR_BUNDLE_ID,
        policy_acceptances=tuple(
            PolicyAcceptance(
                document_id=document_id,
                content_sha256=documents[document_id].content_sha256,
                affirmed=True,
            )
            for document_id in bundle.required_document_ids
        ),
        expected_user_version=7,
        idempotency_key=idempotency_key,
    )


def expected_grant_body(*, grant_id: str = "consent_grant_policy_consent_0001") -> dict[str, Any]:
    fixture = policy_consent_command_fixture()
    bundle = fixture.store.snapshot()["policy_bundles"][CREATOR_BUNDLE_ID]
    offer = bundle.consent_offers[0]
    return {
        "consent_grant_id": grant_id,
        "consent_offer_id": offer.consent_offer_id,
        "purpose": ConsentPurpose.PILOT_RESEARCH.value,
        "scope_type": ConsentScopeType.PLATFORM_PARTICIPATION.value,
        "scope_id": None,
        "data_categories": [category.value for category in offer.data_categories],
        "recipient_label": offer.recipient_label,
        "document_id": offer.supporting_document_id,
        "content_sha256": offer.supporting_document_sha256,
        "granted_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": PILOT_NOT_AFTER.isoformat().replace("+00:00", "Z"),
        "status": "ACTIVE",
        "aggregate_version": 1,
        "entity_tag": '"v1"',
    }


def seed_exact_active_grant(
    fixture: PolicyConsentCommandFixture,
    *,
    grant_id: str = "consent_grant_existing_exact_0001",
    granted_at: datetime = NOW - timedelta(days=1),
    expires_at: datetime = PILOT_NOT_AFTER,
    **overrides: Any,
) -> dict[str, Any]:
    bundle = fixture.store.snapshot()["policy_bundles"][CREATOR_BUNDLE_ID]
    offer = bundle.consent_offers[0]
    row = {
        "consent_grant_id": grant_id,
        "user_id": ACTOR_USER_ID,
        "consent_offer_id": offer.consent_offer_id,
        "consent_offer_version": offer.aggregate_version,
        "policy_bundle_id": CREATOR_BUNDLE_ID,
        "purpose": offer.purpose.value,
        "scope_type": offer.scope_type.value,
        "scope_id": None,
        "data_categories": tuple(category.value for category in offer.data_categories),
        "recipient_reference": offer.recipient_reference,
        "recipient_label": offer.recipient_label,
        "document_id": offer.supporting_document_id,
        "content_sha256": offer.supporting_document_sha256,
        "granted_at": granted_at,
        "expires_at": expires_at,
        "session_id": SESSION_ID,
        "auth_transaction_id": AUTH_TRANSACTION_ID,
        "auth_time": min(
            NOW - timedelta(minutes=5),
            granted_at - timedelta(minutes=5),
        ),
        "acr_code": "urn:desire:acr:mfa",
        "amr_codes": ("otp", "pwd"),
        "command_id": "command_existing_consent_grant_0001",
        "correlation_id": "correlation_existing_consent_grant_0001",
        "status": "ACTIVE",
        "withdrawn_at": None,
        "aggregate_version": 1,
        "created_at": granted_at,
        "updated_at": granted_at,
    }
    row.update(overrides)
    fixture.store.set_fact("consent_grants", grant_id, row)
    return row


def expected_existing_grant_body(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "consent_grant_id": row["consent_grant_id"],
        "consent_offer_id": row["consent_offer_id"],
        "purpose": row["purpose"],
        "scope_type": row["scope_type"],
        "scope_id": row["scope_id"],
        "data_categories": list(row["data_categories"]),
        "recipient_label": row["recipient_label"],
        "document_id": row["document_id"],
        "content_sha256": row["content_sha256"],
        "granted_at": row["granted_at"].isoformat().replace("+00:00", "Z"),
        "expires_at": row["expires_at"].isoformat().replace("+00:00", "Z"),
        "status": row["status"],
        "aggregate_version": row["aggregate_version"],
        "entity_tag": f'"v{row["aggregate_version"]}"',
    }


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reference_body(reference: PolicyRequirementReference) -> dict[str, Any]:
    return {
        "selector_digest": reference.selector_digest,
        "scope_type": reference.scope_type.value,
        "scope_id": reference.scope_id,
    }


def _command_profile(
    command: object,
) -> tuple[str, str, int, Mapping[str, Any], str, str]:
    if isinstance(command, AcceptCurrentPoliciesCommand):
        body = {
            "policy_requirement": _reference_body(command.policy_requirement),
            "policy_bundle_id": command.policy_bundle_id,
            "policy_acceptances": [
                {
                    "document_id": item.document_id,
                    "content_sha256": item.content_sha256,
                    "affirmed": item.affirmed,
                }
                for item in sorted(
                    command.policy_acceptances,
                    key=lambda item: (item.document_id, item.content_sha256),
                )
            ],
        }
        return (
            "AcceptCurrentPolicies",
            "/v1/me/policy-acceptances",
            200,
            body,
            "PolicyRequirementStatusDto",
            "acceptCurrentPolicies",
        )
    if isinstance(command, GrantConsentCommand):
        choice = command.consent_choice
        body = {
            "policy_requirement": _reference_body(command.policy_requirement),
            "policy_bundle_id": command.policy_bundle_id,
            "consent_offer_id": choice.consent_offer_id,
            "document_id": choice.document_id,
            "content_sha256": choice.content_sha256,
            "affirmed": choice.affirmed,
        }
        return (
            "GrantConsent",
            "/v1/me/consents",
            201,
            body,
            "ConsentGrantDto",
            "grantConsent",
        )
    raise TypeError("unsupported policy/consent command")


def seed_completed_receipt(
    fixture: PolicyConsentCommandFixture,
    *,
    command: object,
    response_body: Mapping[str, Any],
    response_entity_tag: str,
    current_user_entity_tag: str,
    identity_key_id: str = RECEIPT_IDENTITY_KEY_ID,
    payload_key_id: str = RECEIPT_PAYLOAD_KEY_ID,
    receipt_id: str = "command_receipt_policy_consent_existing_0001",
) -> Mapping[str, Any]:
    (
        command_name,
        path,
        http_status,
        body,
        response_schema,
        _operation_id,
    ) = _command_profile(command)
    raw_key = command.idempotency_key
    identity_digest = fixture.keyring.keyed_digest_hex(
        key_id=identity_key_id,
        canonical_bytes=_canonical_json(
            {
                "domain": "iam-self-command-idempotency-key-v1",
                "idempotency_key": raw_key,
            }
        ),
    )
    projection = {
        "body": body,
        "canonicalization_version": "restricted-canonical-json-v1",
        "command_name": command_name,
        "command_version": 1,
        "http_method": "POST",
        "if_match_version": command.expected_user_version,
        "path": path,
        "target_id": ACTOR_USER_ID,
        "target_kind": "User",
    }
    payload_hash = fixture.keyring.keyed_digest_hex(
        key_id=payload_key_id,
        canonical_bytes=_canonical_json(projection),
    )
    row = {
        "command_receipt_id": receipt_id,
        "principal_kind": "USER",
        "principal_id": ACTOR_USER_ID,
        "command_name": command_name,
        "command_version": 1,
        "idempotency_key_digest": identity_digest,
        "idempotency_key_digest_key_id": identity_key_id,
        "payload_hash": payload_hash,
        "payload_hash_key_id": payload_key_id,
        "canonicalization_version": "restricted-canonical-json-v1",
        "target_type": "User",
        "target_id": ACTOR_USER_ID,
        "http_method": "POST",
        "canonical_path": path,
        "if_match_version": command.expected_user_version,
        "status": "COMPLETED",
        "response_schema": response_schema,
        "response_schema_version": 1,
        "response_http_status": http_status,
        "response_body": deepcopy(dict(response_body)),
        "response_entity_tag": response_entity_tag,
        "current_user_entity_tag": current_user_entity_tag,
        "created_at": NOW - timedelta(minutes=1),
        "completed_at": NOW - timedelta(minutes=1),
    }
    fixture.store.set_fact("command_receipts", receipt_id, row)
    return row


def all_secret_sentinels() -> tuple[object, ...]:
    return (
        ACCEPT_IDEMPOTENCY_KEY,
        GRANT_IDEMPOTENCY_KEY,
        SESSION_DIGEST_SENTINEL,
        INTERNAL_RECIPIENT_SENTINEL,
        POLICY_BODY_SENTINEL,
    )


def contains_secret(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(contains_secret(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(contains_secret(item) for item in value)
    rendered = value if isinstance(value, str) else repr(value)
    return any(
        isinstance(sentinel, str) and sentinel in rendered
        for sentinel in all_secret_sentinels()
    )


__all__ = [
    "ACCEPT_IDEMPOTENCY_KEY",
    "ACTOR_USER_ID",
    "ALPHA_BUNDLE_ID",
    "ALPHA_SELECTOR_DIGEST",
    "AUTH_TRANSACTION_ID",
    "BETA_BUNDLE_ID",
    "BETA_SELECTOR_DIGEST",
    "CREATOR_BUNDLE_ID",
    "CREATOR_BUNDLE_V1_ID",
    "CREATOR_SELECTOR_DIGEST",
    "GRANT_IDEMPOTENCY_KEY",
    "INTERNAL_RECIPIENT_SENTINEL",
    "NOW",
    "ORGANIZATION_ALPHA_ID",
    "ORGANIZATION_BETA_ID",
    "OLD_RECEIPT_IDENTITY_KEY_ID",
    "OLD_RECEIPT_PAYLOAD_KEY_ID",
    "OTHER_USER_ID",
    "PILOT_NOT_AFTER",
    "PolicyConsentCommandFixture",
    "SESSION_FAMILY_ID",
    "SESSION_ID",
    "UNKNOWN_SELECTOR_DIGEST",
    "all_secret_sentinels",
    "canonical_offer_sha256",
    "creator_accept_command",
    "contains_secret",
    "expected_accept_body",
    "expected_creator_accept_body",
    "expected_existing_grant_body",
    "expected_grant_body",
    "policy_consent_command_fixture",
    "seed_completed_receipt",
    "seed_exact_active_grant",
]
