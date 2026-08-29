"""Independent deterministic builders for Creator Profile PostgreSQL semantics."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional
import uuid

import psycopg

from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresCommand,
    CreatorProfilePostgresDerivedMatchCaptureRequest,
    CreatorProfilePostgresExecutionScope,
    CreatorProfilePostgresHoldEvidence,
    CreatorProfilePostgresMatchCaptureRequest,
    CreatorProfilePostgresOperation,
    CreatorProfilePostgresReceiptMaterial,
    CreatorProfilePostgresWriteCheckpoint,
)
from desire_platform.creator_profile.domain import (
    ProfileContent,
    canonical_profile_version_bytes,
)


UTC_NOW = datetime.now(timezone.utc)
ACTOR_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")
OTHER_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000002")
SESSION_ID = uuid.UUID("20000000-0000-4000-8000-000000000001")
PROFILE_ID = uuid.UUID("30000000-0000-4000-8000-000000000001")
OTHER_PROFILE_ID = uuid.UUID("30000000-0000-4000-8000-000000000002")
VERSION_ID = uuid.UUID("40000000-0000-4000-8000-000000000001")
SECOND_VERSION_ID = uuid.UUID("40000000-0000-4000-8000-000000000002")
TAXONOMY_ID = uuid.UUID("50000000-0000-4000-8000-000000000001")
MATCH_RUN_ID = uuid.UUID("60000000-0000-4000-8000-000000000001")
WORKLOAD_ID = uuid.UUID("70000000-0000-4000-8000-000000000001")
MATCH_ORGANIZATION_ID = uuid.UUID("80000000-0000-4000-8000-000000000002")
MATCH_DEMAND_ID = uuid.UUID("81000000-0000-4000-8000-000000000001")
MATCH_DEMAND_VERSION_ID = uuid.UUID("82000000-0000-4000-8000-000000000001")

RAW_IDEMPOTENCY_SENTINEL = "PROFILE-PG-RAW-IDEMPOTENCY-DO-NOT-PERSIST-4f11"
RAW_SESSION_SENTINEL = "PROFILE-PG-RAW-SESSION-DO-NOT-PERSIST-c182"
RAW_CSRF_SENTINEL = "PROFILE-PG-RAW-CSRF-DO-NOT-PERSIST-d301"
RAW_COMPENSATION_SENTINEL = "PROFILE-PG-COMPENSATION-DO-NOT-LOG-100000"
RAW_BOUNDARY_SENTINEL = "PROFILE-PG-BOUNDARY-DO-NOT-LOG-SURVEILLANCE"
RAW_EVIDENCE_SENTINEL = "s3://profile-pg-private/evidence/raw-object"
RAW_PROVIDER_SENTINEL = "PROFILE-PG-PROVIDER-TOKEN-DO-NOT-LOG"
RAW_SECRET_SENTINELS = (
    RAW_IDEMPOTENCY_SENTINEL,
    RAW_SESSION_SENTINEL,
    RAW_CSRF_SENTINEL,
    RAW_COMPENSATION_SENTINEL,
    RAW_BOUNDARY_SENTINEL,
    RAW_EVIDENCE_SENTINEL,
    RAW_PROVIDER_SENTINEL,
)


@dataclass(frozen=True)
class SeededCreatorIamAuthority:
    actor_user_id: uuid.UUID
    session_id: uuid.UUID
    session_family_id: uuid.UUID
    auth_transaction_id: uuid.UUID
    creator_grant_id: uuid.UUID
    creator_invitation_id: uuid.UUID
    policy_bundle_id: uuid.UUID
    policy_selector_digest: bytes
    required_document_id: uuid.UUID
    required_document_sha256: bytes
    authority_marker_sha256: bytes


def _new_id(kind: int) -> uuid.UUID:
    return uuid.UUID(f"{kind:08x}-0000-4000-8000-000000000001")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return ProfileContent(
            tuple((str(key), _freeze(child)) for key, child in value.items())
        )
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def content() -> ProfileContent:
    metadata = {
        "visibility": "MATCH_ONLY",
        "source_kind": "SELF_ASSERTED",
        "evidence_ids": [],
    }
    private = {**metadata, "visibility": "PRIVATE"}
    return _freeze(
        {
            "interests": [
                {
                    "problem_code": "PROBLEM.CLIMATE",
                    "domain_code": "DOMAIN.ENERGY",
                    "task_code": "TASK.RESEARCH",
                    "strength": 4,
                    **metadata,
                }
            ],
            "skills": [
                {"skill_code": "SKILL.RESEARCH", "proficiency": 3, **metadata}
            ],
            "availability": {
                "available_from": "2026-08-09",
                "weekly_hours": 20,
                "duration_weeks": 12,
                "timezone": "Asia/Shanghai",
                **metadata,
            },
            "collaboration": {
                "languages": [{"language_code": "zh-CN", **metadata}],
                "work_modes": [{"work_mode": "REMOTE", **metadata}],
                "feedback_cadence": {"feedback_cadence": "WEEKLY", **metadata},
                "team_preference": {"team_preference": "SMALL_TEAM", **metadata},
            },
            "compensation": {
                "minimum_project_amount_minor": 100000,
                "currency": "CNY",
                "direct_cost_amount_minor": 20000,
                **private,
            },
            "boundaries": {
                "prohibited_domains": [{"code": "DOMAIN.GAMBLING", **private}],
                "prohibited_tasks": [{"code": "TASK.SURVEILLANCE", **private}],
                "allowed_data_sensitivity": {
                    "data_sensitivity": "CONFIDENTIAL",
                    **private,
                },
            },
            "location": {
                "region_code": "CN-SH",
                "visibility": "PUBLIC",
                "source_kind": "SELF_ASSERTED",
                "evidence_ids": [],
            },
            "conflicts": [
                {
                    "organization_id": "80000000-0000-4000-8000-000000000001",
                    **private,
                }
            ],
            "ai": {
                "allowed": True,
                "requires_ai": False,
                "human_review_code": "REQUIRED",
                "prohibited_case_codes": ["AI.BIOMETRIC_SURVEILLANCE"],
                **metadata,
            },
        }
    )


def version_material(*, version_no: int) -> tuple[bytes, bytes]:
    canonical = canonical_profile_version_bytes(
        profile_id=str(PROFILE_ID),
        version_no=version_no,
        taxonomy_bundle_id=str(TAXONOMY_ID),
        content=content(),
    )
    return canonical, hashlib.sha256(canonical).digest()


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _keyed(label: str, value: str) -> bytes:
    return hmac.new(
        ("profile-pg-test:" + label).encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def creator_authority_marker_sha256() -> bytes:
    """Mirror the closed marker material frozen by IAM capability v1."""

    selector_bytes = json.dumps(
        {
            "access_purpose": "CREATOR_ENROLLMENT",
            "scope_type": "USER_ROLE",
            "target_role": "CREATOR",
            "jurisdiction": "CN",
            "locale": "zh-CN",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    selector_digest = hashlib.sha256(selector_bytes).digest()
    material = "|".join(
        (
            str(ACTOR_USER_ID),
            str(SESSION_ID),
            str(_new_id(0xA3)),
            selector_digest.hex(),
            str(_new_id(0xA6)),
            "7",
            "1",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def seed_exact_creator_iam_authority(
    connection: Any,
    *,
    now: datetime,
) -> SeededCreatorIamAuthority:
    """Insert one independently valid ACTIVE Session/CREATOR/policy graph."""

    contact_id = _new_id(0xA1)
    creator_invitation_id = _new_id(0xA2)
    creator_grant_id = _new_id(0xA3)
    auth_transaction_id = _new_id(0xA4)
    family_id = _new_id(0xA5)
    policy_bundle_id = _new_id(0xA6)
    required_document_id = _new_id(0xA7)
    publication_command_id = _new_id(0xA8)
    accepted_command_id = _new_id(0xA9)
    created_at = now - timedelta(days=30)
    accepted_at = now - timedelta(days=29)
    auth_time = now - timedelta(days=2)
    session_created_at = now - timedelta(days=1)
    policy_accepted_at = now - timedelta(hours=12)
    selector_bytes = json.dumps(
        {
            "access_purpose": "CREATOR_ENROLLMENT",
            "scope_type": "USER_ROLE",
            "target_role": "CREATOR",
            "jurisdiction": "CN",
            "locale": "zh-CN",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    selector_digest = hashlib.sha256(selector_bytes).digest()
    policy_body = "Reviewed Creator Profile terms v1."
    policy_hash = hashlib.sha256(policy_body.encode("utf-8")).digest()

    connection.execute(
        "INSERT INTO iam.policy_selectors ("
        "selector_digest,canonicalization_version,access_purpose,scope_type,"
        "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,'policy-selector-json-v1','CREATOR_ENROLLMENT','USER_ROLE',"
        "'CREATOR','CN','zh-CN',NULL,1,%s,%s)",
        (selector_digest, created_at, created_at),
    )
    connection.execute(
        "INSERT INTO iam.policy_documents ("
        "id,kind,locale,semantic_version,canonical_body,content_sha256,"
        "legal_effect,jurisdiction,status,effective_at,"
        "superseded_by_document_id,publication_command_id,created_at,updated_at"
        ") VALUES (%s,'TERMS','zh-CN','1.0.0',%s,%s,"
        "'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,NULL,%s,%s,%s)",
        (
            required_document_id,
            policy_body,
            policy_hash,
            accepted_at,
            publication_command_id,
            created_at,
            accepted_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.policy_bundles ("
        "id,selector_digest,status,effective_at,effective_until,"
        "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
        "release_signing_key_id,publication_command_id,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'profile-pg-signing-v1',"
        "%s,1,%s,%s)",
        (
            policy_bundle_id,
            selector_digest,
            _digest("profile-pg-policy-manifest"),
            b"reviewed-profile-pg-signature",
            publication_command_id,
            created_at,
            created_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.policy_bundle_documents "
        "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
        (policy_bundle_id, required_document_id),
    )
    connection.execute(
        "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
        "aggregate_version=2,updated_at=%s WHERE id=%s",
        (accepted_at, accepted_at, policy_bundle_id),
    )
    connection.execute(
        "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
        "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
        (policy_bundle_id, accepted_at, selector_digest),
    )
    connection.execute(
        "INSERT INTO iam.users "
        "(id,status,display_handle,aggregate_version,created_at,updated_at) "
        "VALUES (%s,'ACTIVE','profile_pg_creator',7,%s,%s)",
        (ACTOR_USER_ID, created_at, accepted_at),
    )
    connection.execute(
        "INSERT INTO iam.contact_points ("
        "id,user_id,contact_type,locator_ciphertext,locator_encryption_key_id,"
        "locator_encryption_algorithm,binding_digest,binding_digest_key_id,"
        "verified_at,retention_until,created_at,updated_at) VALUES ("
        "%s,%s,'EMAIL',NULL,NULL,NULL,%s,'contact-hmac-v1',%s,%s,%s,%s)",
        (
            contact_id,
            ACTOR_USER_ID,
            _digest("profile-pg-contact-binding"),
            accepted_at,
            now + timedelta(days=365),
            created_at,
            accepted_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.access_invitations ("
        "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
        "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
        "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
        "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
        "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
        "%s,'CREATOR_ENROLLMENT',NULL,'USER','CREATOR',false,%s,"
        "'p***@example.invalid',%s,%s,'ACCEPTED',%s,'SYSTEM',NULL,%s,"
        "'invitation-token-v1',%s,%s,NULL,2,%s,%s)",
        (
            creator_invitation_id,
            contact_id,
            selector_digest,
            policy_bundle_id,
            now + timedelta(days=300),
            _digest("profile-pg-invitation-nonce"),
            ACTOR_USER_ID,
            accepted_at,
            created_at,
            accepted_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.user_role_grants ("
        "id,user_id,role_code,source_invitation_id,policy_selector_digest,"
        "granted_by_kind,granted_by_id,granted_at,revoked_at,"
        "revocation_reason_code,aggregate_version) VALUES ("
        "%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
        (
            creator_grant_id,
            ACTOR_USER_ID,
            creator_invitation_id,
            selector_digest,
            _new_id(0xAA),
            accepted_at,
        ),
    )
    transaction_created = auth_time - timedelta(minutes=5)
    connection.execute(
        "INSERT INTO iam.auth_transactions ("
        "id,status,purpose,attempt,protocol_version,browser_binding_digest,"
        "browser_binding_key_id,initiating_session_id,initiating_user_id,"
        "expected_user_id,invitation_id,invitation_version,"
        "expected_contact_point_id,state_digest,state_digest_key_id,"
        "nonce_digest,nonce_digest_key_id,pkce_verifier_ciphertext,"
        "pkce_encryption_key_id,pkce_encryption_algorithm,redirect_uri,"
        "provider_error_class,deadline,succeeded_at,created_at,updated_at) "
        "VALUES (%s,'SUCCEEDED','LOGIN',1,1,%s,'browser-hmac-v1',"
        "NULL,NULL,NULL,NULL,NULL,NULL,%s,'state-hmac-v1',%s,'nonce-hmac-v1',"
        "%s,'pkce-aead-v1','AES_256_GCM_V1',"
        "'https://app.example.test/v1/auth/oidc/callback',NULL,%s,%s,%s,%s)",
        (
            auth_transaction_id,
            _digest("profile-pg-browser-binding"),
            _digest("profile-pg-state"),
            _digest("profile-pg-nonce"),
            b"reviewed-profile-pg-pkce-ciphertext",
            now + timedelta(days=30),
            auth_time,
            transaction_created,
            auth_time,
        ),
    )
    connection.execute(
        "INSERT INTO iam.session_families ("
        "id,user_id,status,current_generation,revoked_at,"
        "revocation_reason_code,aggregate_version,created_at,updated_at) "
        "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
        (family_id, ACTOR_USER_ID, session_created_at, session_created_at),
    )
    connection.execute(
        "INSERT INTO iam.sessions ("
        "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
        "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
        "verified_contact_point_id,verified_at,verified_for_invitation_id,"
        "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
        "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
        "device_label,status,rotation_reason,revoked_at,"
        "revocation_reason_code,aggregate_version) VALUES ("
        "%s,%s,%s,1,NULL,%s,'session-hmac-v1',%s,'csrf-hmac-v1',%s,"
        "NULL,NULL,NULL,%s,%s,'urn:desire:acr:mfa',ARRAY['otp','pwd']::text[],"
        "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
        (
            SESSION_ID,
            ACTOR_USER_ID,
            family_id,
            _digest(RAW_SESSION_SENTINEL),
            _digest("profile-pg-csrf-salt"),
            _digest(RAW_CSRF_SENTINEL),
            auth_transaction_id,
            auth_time,
            session_created_at,
            now - timedelta(minutes=1),
            now + timedelta(minutes=30),
            now + timedelta(days=30),
            now - timedelta(minutes=1),
        ),
    )
    connection.execute(
        "INSERT INTO iam.policy_acceptances ("
        "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
        "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
        "source_action,command_id,correlation_id,aggregate_version,created_at"
        ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,"
        "'urn:desire:acr:mfa',ARRAY['otp','pwd']::text[],'POLICY_ACCEPT',"
        "%s,%s,1,%s)",
        (
            _new_id(0xAB),
            ACTOR_USER_ID,
            required_document_id,
            policy_hash,
            policy_bundle_id,
            policy_accepted_at,
            SESSION_ID,
            auth_transaction_id,
            auth_time,
            accepted_command_id,
            _new_id(0xAC),
            policy_accepted_at,
        ),
    )
    return SeededCreatorIamAuthority(
        actor_user_id=ACTOR_USER_ID,
        session_id=SESSION_ID,
        session_family_id=family_id,
        auth_transaction_id=auth_transaction_id,
        creator_grant_id=creator_grant_id,
        creator_invitation_id=creator_invitation_id,
        policy_bundle_id=policy_bundle_id,
        policy_selector_digest=selector_digest,
        required_document_id=required_document_id,
        required_document_sha256=policy_hash,
        authority_marker_sha256=creator_authority_marker_sha256(),
    )


def postgres_command(
    operation: CreatorProfilePostgresOperation,
    *,
    actor_user_id: uuid.UUID = ACTOR_USER_ID,
    profile_id: uuid.UUID = PROFILE_ID,
    expected_version: int = 2,
    idempotency_material: str = RAW_IDEMPOTENCY_SENTINEL,
) -> CreatorProfilePostgresCommand:
    request_now = datetime.now(timezone.utc)
    command_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "urn:desire:profile-pg-command:"
        + operation.value
        + ":"
        + idempotency_material,
    )
    def scoped_id(label: str) -> uuid.UUID:
        return uuid.uuid5(command_id, label)

    event_required = operation is not CreatorProfilePostgresOperation.SAVE_DRAFT
    scope = CreatorProfilePostgresExecutionScope(
        actor_user_id=actor_user_id,
        session_id=SESSION_ID,
        profile_id=profile_id,
        command_id=command_id,
        audit_event_id=scoped_id("audit"),
        outbox_event_id=scoped_id("outbox") if event_required else None,
        correlation_id=scoped_id("correlation"),
        causation_id=scoped_id("causation"),
        trace_id=scoped_id("trace"),
        original_actor_id=None,
        expected_authority_marker_sha256=creator_authority_marker_sha256(),
    )
    receipt = CreatorProfilePostgresReceiptMaterial(
        receipt_id=command_id,
        principal_id=actor_user_id,
        idempotency_key_digest_key_id="profile-idempotency-2026-01",
        idempotency_key_digest=_keyed("identity", idempotency_material),
        payload_hash_key_id="profile-payload-2026-01",
        canonicalization_version="profile-command-json-v1",
        payload_hash=_keyed(
            "payload",
            operation.value + ":" + str(profile_id) + ":" + str(expected_version),
        ),
        retain_until=request_now + timedelta(days=7),
    )
    hold = None
    if operation in {
        CreatorProfilePostgresOperation.PUBLISH,
        CreatorProfilePostgresOperation.RESUME,
    }:
        _canonical, published_hash = version_material(version_no=1)
        hold = CreatorProfilePostgresHoldEvidence(
            profile_id=profile_id,
            prospective_aggregate_version=expected_version + 1,
            content_sha256=published_hash,
            actor_user_id=actor_user_id,
            policy_version="creator-profile-hold-v1",
            evaluated_at=request_now,
            valid_until=request_now + timedelta(minutes=5),
        )
    if operation is CreatorProfilePostgresOperation.CREATE:
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=None,
            profile_version_id=None,
            based_on_profile_version_id=None,
            taxonomy_bundle_id=None,
        )
    if operation is CreatorProfilePostgresOperation.SAVE_DRAFT:
        canonical, digest = version_material(version_no=2)
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            profile_version_id=SECOND_VERSION_ID,
            based_on_profile_version_id=VERSION_ID,
            taxonomy_bundle_id=TAXONOMY_ID,
            canonical_profile_version_bytes=canonical,
            content_sha256=digest,
        )
    if operation is CreatorProfilePostgresOperation.PUBLISH:
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            profile_version_id=VERSION_ID,
            based_on_profile_version_id=None,
            taxonomy_bundle_id=None,
            confirmed=True,
            hold=hold,
        )
    if operation is CreatorProfilePostgresOperation.PAUSE:
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            profile_version_id=None,
            based_on_profile_version_id=None,
            taxonomy_bundle_id=None,
            reason_code="OWNER_REQUEST",
        )
    if operation is CreatorProfilePostgresOperation.RESUME:
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            profile_version_id=None,
            based_on_profile_version_id=None,
            taxonomy_bundle_id=None,
            hold=hold,
        )
    if operation is CreatorProfilePostgresOperation.ARCHIVE:
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            profile_version_id=None,
            based_on_profile_version_id=None,
            taxonomy_bundle_id=None,
            reason_code="OWNER_REQUEST",
        )
    raise ValueError("writer builder received a matcher operation")


def match_capture_request() -> CreatorProfilePostgresMatchCaptureRequest:
    return CreatorProfilePostgresMatchCaptureRequest(
        match_run_id=MATCH_RUN_ID,
        workload_id=WORKLOAD_ID,
        authorization_digest=_digest("exact-match-candidate-allowlist"),
    )


def demand_match_context(**overrides: Any) -> tuple[Mapping[str, Any], bytes, bytes]:
    value = {
        "schema_version": 1,
        "canonicalization_version": "profile-match-demand-context-json-v1",
        "organization_id": str(MATCH_ORGANIZATION_ID),
        "demand_id": str(MATCH_DEMAND_ID),
        "demand_version_id": str(MATCH_DEMAND_VERSION_ID),
        "taxonomy_bundle_id": str(TAXONOMY_ID),
        "currency": "CNY",
        "minimum_amount_minor": 50000,
        "maximum_amount_minor": 150000,
        "allowed_region_codes": ["REGION.CN"],
        "required_language_codes": ["LANGUAGE.ZH"],
        "required_work_mode_code": "WORK_MODE.REMOTE",
        "data_sensitivity_code": "HIGH",
        "ai_use_code": "OPTIONAL",
    }
    value.update(overrides)
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return value, canonical, hashlib.sha256(canonical).digest()


def derived_match_capture_request(
    **context_overrides: Any,
) -> CreatorProfilePostgresDerivedMatchCaptureRequest:
    _, canonical, digest = demand_match_context(**context_overrides)
    return CreatorProfilePostgresDerivedMatchCaptureRequest(
        match_run_id=MATCH_RUN_ID,
        workload_id=WORKLOAD_ID,
        authorization_digest=_digest("exact-derived-match-authorization"),
        demand_match_context_bytes=canonical,
        demand_match_context_sha256=digest,
    )


def reset_creator_profile_database(connection: Any) -> None:
    """Reset only Profile-owned facts and Profile audit/outbox test facts."""

    connection.execute(
        "TRUNCATE TABLE "
        "profile.derived_match_input_snapshots,"
        "profile.derived_match_raw_snapshots,"
        "profile.derived_match_capture_receipts,"
        "profile.match_input_snapshots,"
        "profile.match_capture_authorizations,"
        "profile.match_capture_batches,"
        "profile.profile_version_evidence,"
        "profile.capability_evidence,"
        "profile.command_receipts,"
        "profile.profile_versions,"
        "profile.creator_profiles,"
        "profile.taxonomy_bundle_markers,"
        "audit.audit_events,"
        "infra.outbox_events"
    )


def seed_creator_profile_prestate(
    connection: Any,
    operation: CreatorProfilePostgresOperation,
    *,
    include_match_authorization: bool = False,
    now: Optional[datetime] = None,
) -> None:
    """Establish one explicit legal pre-state; production never calls this."""

    current_time = now or datetime.now(timezone.utc)
    connection.execute(
        "INSERT INTO profile.taxonomy_bundle_markers ("
        "id,status,bundle_sha256,aggregate_version,updated_at) "
        "VALUES (%s,'ACTIVE',%s,1,%s)",
        (TAXONOMY_ID, _digest("profile-pg-taxonomy-bundle"), current_time),
    )
    if operation is CreatorProfilePostgresOperation.CREATE:
        return

    root_status = "DRAFT"
    version_status = "DRAFT"
    current_draft = VERSION_ID
    current_published = None
    paused_at = None
    pause_reason = None
    published_at = None
    confirmed = False
    if operation in {
        CreatorProfilePostgresOperation.SAVE_DRAFT,
        CreatorProfilePostgresOperation.PAUSE,
        CreatorProfilePostgresOperation.RESUME,
        CreatorProfilePostgresOperation.ARCHIVE,
        CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS,
        CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS,
    }:
        root_status = "ACTIVE"
        version_status = "PUBLISHED"
        current_draft = None
        current_published = VERSION_ID
        published_at = current_time - timedelta(hours=1)
        confirmed = True
    if operation is CreatorProfilePostgresOperation.RESUME:
        root_status = "PAUSED"
        paused_at = current_time - timedelta(minutes=30)
        pause_reason = "OWNER_REQUEST"

    canonical, digest = version_material(version_no=1)
    connection.execute("SET CONSTRAINTS ALL DEFERRED")
    connection.execute(
        "INSERT INTO profile.creator_profiles ("
        "id,owner_user_id,status,aggregate_version,current_draft_version_id,"
        "current_published_version_id,paused_at,pause_reason_code,"
        "archived_at,archive_reason_code,created_at,updated_at) VALUES ("
        "%s,%s,%s,2,%s,%s,%s,%s,NULL,NULL,%s,%s)",
        (
            PROFILE_ID,
            ACTOR_USER_ID,
            root_status,
            current_draft,
            current_published,
            paused_at,
            pause_reason,
            current_time - timedelta(days=1),
            current_time - timedelta(hours=1),
        ),
    )
    connection.execute(
        "INSERT INTO profile.profile_versions ("
        "id,profile_id,version_no,status,based_on_profile_version_id,"
        "schema_version,canonicalization_version,taxonomy_bundle_id,"
        "canonical_content,content,content_sha256,created_by_user_id,created_at,"
        "published_at,confirmed) VALUES ("
        "%s,%s,1,%s,NULL,1,'profile-version-json-v1',%s,%s,%s::jsonb,%s,%s,%s,%s,%s)",
        (
            VERSION_ID,
            PROFILE_ID,
            version_status,
            TAXONOMY_ID,
            canonical,
            canonical.decode("utf-8"),
            digest,
            ACTOR_USER_ID,
            current_time - timedelta(hours=2),
            published_at,
            confirmed,
        ),
    )
    del include_match_authorization


def creator_profile_database_snapshot(connection: Any) -> tuple[Any, ...]:
    """Closed whole-graph snapshot used by publish fault gates."""

    return connection.execute(
        "SELECT "
        "(SELECT count(*) FROM profile.creator_profiles),"
        "(SELECT count(*) FROM profile.profile_versions),"
        "(SELECT count(*) FROM profile.command_receipts),"
        "(SELECT count(*) FROM audit.audit_events WHERE target_kind='CreatorProfile'),"
        "(SELECT count(*) FROM infra.outbox_events "
        " WHERE aggregate_type='CreatorProfile'),"
        "(SELECT COALESCE(string_agg("
        " id::text||':'||status||':'||aggregate_version::text,',' ORDER BY id),'' )"
        " FROM profile.creator_profiles),"
        "(SELECT COALESCE(string_agg("
        " id::text||':'||status||':'||encode(content_sha256,'hex'),',' ORDER BY id),'' )"
        " FROM profile.profile_versions)"
    ).fetchone()


class RecordingSchemaValidator:
    def __init__(self) -> None:
        self.calls: list[tuple[Optional[str], Mapping[str, Any]]] = []

    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None:
        self.calls.append((schema_name, deepcopy(dict(value))))


class _TrackingConnection:
    def __init__(
        self,
        raw: Any,
        trace: list[str],
        *,
        lose_commit_ack: bool = False,
    ) -> None:
        self._raw = raw
        self._trace = trace
        self._lose_commit_ack = lose_commit_ack

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        normalized = " ".join(str(query).strip().split())
        self._trace.append(normalized)
        if self._lose_commit_ack and normalized.upper() == "COMMIT":
            self._lose_commit_ack = False
            result = self._raw.execute(query, parameters, *args, **kwargs)
            self._raw.close()
            del result
            raise psycopg.OperationalError(
                "synthetic Creator Profile COMMIT acknowledgement loss"
            )
        return self._raw.execute(query, parameters, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class TrackingProfileConnectionSource:
    """Role-bound real psycopg source with observable pool disposition."""

    def __init__(
        self,
        conninfo: str,
        *,
        reuse_released: bool = False,
        lose_first_commit_ack: bool = False,
    ) -> None:
        self.conninfo = conninfo
        self.reuse_released = reuse_released
        self.lose_first_commit_ack = lose_first_commit_ack
        self.trace: list[str] = []
        self.backend_pids: list[int] = []
        self.checked_out: list[Any] = []
        self.released: list[Any] = []
        self.discarded: list[Any] = []
        self._reusable_raw: Optional[Any] = None

    def checkout(self) -> Any:
        raw = self._reusable_raw
        if raw is None or raw.closed or not self.reuse_released:
            raw = psycopg.connect(self.conninfo, autocommit=True)
            if self.reuse_released:
                self._reusable_raw = raw
        self.backend_pids.append(raw.info.backend_pid)
        connection = _TrackingConnection(
            raw,
            self.trace,
            lose_commit_ack=self.lose_first_commit_ack,
        )
        self.lose_first_commit_ack = False
        self.checked_out.append(connection)
        return connection

    def release(self, connection: Any) -> None:
        self.released.append(connection)
        if not self.reuse_released:
            connection.close()

    def discard(self, connection: Any) -> None:
        self.discarded.append(connection)
        connection.close()
        if self._reusable_raw is not None and self._reusable_raw.closed:
            self._reusable_raw = None

    def close(self) -> None:
        if self._reusable_raw is not None and not self._reusable_raw.closed:
            self._reusable_raw.close()


class InjectedProfilePostgresWriteFailure(RuntimeError):
    pass


class RaiseAtProfileCheckpoint:
    def __init__(self, target: CreatorProfilePostgresWriteCheckpoint) -> None:
        self.target = target
        self.calls: list[tuple[CreatorProfilePostgresWriteCheckpoint, int]] = []

    def before_write(
        self,
        checkpoint: CreatorProfilePostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        self.calls.append((checkpoint, ordinal))
        if checkpoint is self.target:
            raise InjectedProfilePostgresWriteFailure(checkpoint.value)


def with_actor(
    request: CreatorProfilePostgresCommand,
    actor_user_id: uuid.UUID,
) -> CreatorProfilePostgresCommand:
    scope = replace(request.scope, actor_user_id=actor_user_id)
    receipt = replace(request.receipt, principal_id=actor_user_id)
    hold = (
        replace(request.hold, actor_user_id=actor_user_id)
        if request.hold is not None
        else None
    )
    return replace(request, scope=scope, receipt=receipt, hold=hold)
