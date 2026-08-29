"""Independent deterministic builders for Demand PostgreSQL semantic RED."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional
import uuid

import psycopg

from desire_platform.demand.adapters.postgres import (
    DemandPostgresCommand,
    DemandPostgresContentPolicyEvidence,
    DemandPostgresExecutionScope,
    DemandPostgresHoldEvidence,
    DemandPostgresMatchCaptureRequest,
    DemandPostgresMatchCaptureResult,
    DemandPostgresMatchInputSnapshot,
    DemandPostgresMatchSkillRequirement,
    DemandPostgresOperation,
    DemandPostgresReceiptMaterial,
    DemandPostgresRuleRequirement,
    DemandPostgresSourceEvent,
    DemandPostgresWriteCheckpoint,
)
from desire_platform.demand.domain import canonical_demand_version_bytes
from tests.support.demand_builders import freeze_json, thaw_json, valid_content


# Session/policy/evidence fixtures must remain valid when the suite is run.
# A frozen wall-clock date silently turns every authority happy path into
# RESOURCE_NOT_FOUND once its idle deadline passes.  Round for reproducible
# equality within one test process while keeping PostgreSQL transaction time
# as the independently asserted source of truth.
UTC_NOW = datetime.now(timezone.utc).replace(microsecond=0)
ACTOR_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")
SESSION_ID = uuid.UUID("20000000-0000-4000-8000-000000000001")
REVIEWER_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000002")
REVIEWER_SESSION_ID = uuid.UUID("20000000-0000-4000-8000-000000000002")
REVIEWER_SESSION_FAMILY_ID = uuid.UUID(
    "da000000-0000-4000-8000-000000000002"
)
REVIEWER_AUTH_TRANSACTION_ID = uuid.UUID(
    "d9000000-0000-4000-8000-000000000002"
)
REVIEWER_DUTY_GRANT_ID = uuid.UUID(
    "000000f2-0000-4000-8000-000000000001"
)
ORGANIZATION_ID = uuid.UUID("81000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = uuid.UUID("81000000-0000-4000-8000-000000000002")
MEMBERSHIP_ID = uuid.UUID("82000000-0000-4000-8000-000000000001")
MEMBERSHIP_ROLE_GRANT_ID = uuid.UUID("83000000-0000-4000-8000-000000000001")
DEMAND_ID = uuid.UUID("30000000-0000-4000-8000-000000000001")
OTHER_DEMAND_ID = uuid.UUID("30000000-0000-4000-8000-000000000002")
DEMAND_VERSION_ID = uuid.UUID("40000000-0000-4000-8000-000000000001")
SECOND_DEMAND_VERSION_ID = uuid.UUID("40000000-0000-4000-8000-000000000002")
SUBMISSION_ID = uuid.UUID("41000000-0000-4000-8000-000000000001")
ASSIGNMENT_ID = uuid.UUID("42000000-0000-4000-8000-000000000001")
REVIEW_ID = uuid.UUID("43000000-0000-4000-8000-000000000001")
PRIOR_ASSIGNMENT_ID = uuid.UUID("42000000-0000-4000-8000-000000000002")
PRIOR_REVIEW_ID = uuid.UUID("43000000-0000-4000-8000-000000000002")
FUNDING_ID = uuid.UUID("44000000-0000-4000-8000-000000000001")
FUNDING_MARKER_ID = uuid.UUID("45000000-0000-4000-8000-000000000001")
MATCHING_REQUEST_ID = uuid.UUID("46000000-0000-4000-8000-000000000001")
MATCH_RUN_ID = uuid.UUID("47000000-0000-4000-8000-000000000001")
WORKLOAD_ID = uuid.UUID("48000000-0000-4000-8000-000000000001")
TAXONOMY_ID = uuid.UUID("50000000-0000-4000-8000-000000000001")
BUDGET_RULE_ID = uuid.UUID("51000000-0000-4000-8000-000000000001")
RISK_RULE_ID = uuid.UUID("52000000-0000-4000-8000-000000000001")
MATCHING_RULE_ID = uuid.UUID("53000000-0000-4000-8000-000000000001")
REASON_RULE_ID = uuid.UUID("54000000-0000-4000-8000-000000000001")
COMPOSITE_RULE_ID = uuid.UUID("55000000-0000-4000-8000-000000000001")
FUNDING_EVENT_ID = uuid.UUID("60000000-0000-4000-8000-000000000001")
EXPIRY_EVENT_ID = uuid.UUID("60000000-0000-4000-8000-000000000002")

RAW_IDEMPOTENCY_SENTINEL = "DEMAND-PG-RAW-IDEMPOTENCY-DO-NOT-PERSIST-f37c"
RAW_CLIENT_REFERENCE_SENTINEL = "DEMAND-PG-RAW-CLIENT-REFERENCE-PRIVATE-b297"
RAW_SESSION_SENTINEL = "DEMAND-PG-RAW-SESSION-DO-NOT-LOG-413a"
RAW_CSRF_SENTINEL = "DEMAND-PG-RAW-CSRF-DO-NOT-LOG-c75d"
RAW_CONTENT_SENTINEL = "DEMAND-PG-RAW-CONTENT-DO-NOT-LOG-926a"
RAW_REVIEW_SENTINEL = "DEMAND-PG-RAW-REVIEW-NOTE-DO-NOT-LOG-a27b"
RAW_PROVIDER_SENTINEL = "DEMAND-PG-PROVIDER-REFERENCE-DO-NOT-LOG-c9d1"
RAW_WORKLOAD_SENTINEL = "DEMAND-PG-WORKLOAD-CREDENTIAL-DO-NOT-LOG-1cc4"
RAW_SECRET_SENTINELS = (
    RAW_IDEMPOTENCY_SENTINEL,
    RAW_CLIENT_REFERENCE_SENTINEL,
    RAW_SESSION_SENTINEL,
    RAW_CSRF_SENTINEL,
    RAW_CONTENT_SENTINEL,
    RAW_REVIEW_SENTINEL,
    RAW_PROVIDER_SENTINEL,
    RAW_WORKLOAD_SENTINEL,
)


@dataclass(frozen=True)
class SeededDemandOwnerIamAuthority:
    actor_user_id: uuid.UUID
    session_id: uuid.UUID
    session_family_id: uuid.UUID
    organization_id: uuid.UUID
    membership_id: uuid.UUID
    membership_role_grant_id: uuid.UUID
    policy_bundle_id: uuid.UUID
    policy_selector_digest: bytes
    required_document_id: uuid.UUID
    required_document_sha256: bytes


def _selector_digest() -> bytes:
    selector_bytes = json.dumps(
        {
            "access_purpose": "ORGANIZATION_MEMBERSHIP",
            "scope_type": "ORGANIZATION_ROLE",
            "target_role": "DEMAND_OWNER",
            "jurisdiction": "CN",
            "locale": "zh-CN",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(selector_bytes).digest()


def owner_authority_marker(
    operation: DemandPostgresOperation,
    *,
    demand_id: uuid.UUID = DEMAND_ID,
) -> bytes:
    token = {
        DemandPostgresOperation.CREATE: "CREATE",
        DemandPostgresOperation.CREATE_VERSION: "CREATE_VERSION",
        DemandPostgresOperation.SUBMIT: "SUBMIT",
        DemandPostgresOperation.CANCEL_OWNER: "CANCEL_OWNER",
    }[operation]
    material = "|".join(
        (
            "iam-demand-owner-authority-v1",
            token,
            str(demand_id),
            str(_new_id(0xDA)), "1",
            str(SESSION_ID), "1", "1",
            str(ACTOR_USER_ID), "7",
            str(ORGANIZATION_ID), "3",
            str(MEMBERSHIP_ID), "1",
            str(MEMBERSHIP_ROLE_GRANT_ID), "1",
            str(_new_id(0xD3)), "2",
            _selector_digest().hex(), "2",
            str(_new_id(0xD1)), "2",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def reviewer_authority_marker(
    operation: DemandPostgresOperation,
    *,
    demand_id: uuid.UUID = DEMAND_ID,
    assignment_id: uuid.UUID = ASSIGNMENT_ID,
) -> bytes:
    token = {
        DemandPostgresOperation.REQUEST_CHANGES: "REQUEST_CHANGES",
        DemandPostgresOperation.VERIFY: "VERIFY",
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
            "RELEASE_REVIEW_ASSIGNMENT"
        ),
        DemandPostgresOperation.REQUEST_MATCHING: "REQUEST_MATCHING",
        DemandPostgresOperation.CANCEL_REVIEW: "CANCEL_REVIEW",
    }[operation]
    material = "|".join(
        (
            "iam-demand-reviewer-duty-v2",
            token,
            str(ORGANIZATION_ID),
            str(demand_id),
            str(assignment_id),
            str(REVIEWER_SESSION_FAMILY_ID), "1",
            "1",
            str(REVIEWER_SESSION_ID), "1", "1",
            str(REVIEWER_USER_ID), "1",
            "3",
            str(REVIEWER_DUTY_GRANT_ID), "1", "none",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def _new_id(kind: int) -> uuid.UUID:
    return uuid.UUID(f"{kind:08x}-0000-4000-8000-000000000001")


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _keyed(label: str, value: str) -> bytes:
    return hmac.new(
        ("demand-pg-test:" + label).encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _canonical_material(
    *,
    demand_id: uuid.UUID = DEMAND_ID,
    version_id: uuid.UUID = DEMAND_VERSION_ID,
    version_no: int = 1,
    taxonomy_id: uuid.UUID = TAXONOMY_ID,
) -> tuple[bytes, bytes]:
    del version_id
    content = thaw_json(valid_content())
    content["risk"]["data_handling_plan"] = RAW_CONTENT_SENTINEL
    canonical = canonical_demand_version_bytes(
        demand_id=str(demand_id),
        version_no=version_no,
        taxonomy_bundle_id=str(taxonomy_id),
        content=freeze_json(content),
    )
    return canonical, hashlib.sha256(canonical).digest()


def seed_exact_demand_owner_iam_authority(
    connection: Any,
    *,
    now: datetime,
) -> SeededDemandOwnerIamAuthority:
    """Insert one valid ACTIVE Session/Organization/DEMAND_OWNER/policy graph."""

    contact_id = _new_id(0xD8)
    auth_transaction_id = _new_id(0xD9)
    session_family_id = _new_id(0xDA)
    selector_digest = _selector_digest()
    policy_bundle_id = _new_id(0xD1)
    policy_document_id = _new_id(0xD2)
    invitation_id = _new_id(0xD3)
    publication_command_id = _new_id(0xD4)
    acceptance_command_id = _new_id(0xD5)
    created_at = now - timedelta(days=30)
    policy_effective_at = now - timedelta(days=21)
    membership_accepted_at = now - timedelta(days=20)
    accepted_at = now - timedelta(hours=6)
    auth_time = now - timedelta(days=2)
    session_created_at = now - timedelta(days=1)
    policy_body = "Reviewed Demand owner covenant v1."
    policy_hash = hashlib.sha256(policy_body.encode("utf-8")).digest()

    connection.execute(
        "INSERT INTO iam.policy_selectors ("
        "selector_digest,canonicalization_version,access_purpose,scope_type,"
        "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,'policy-selector-json-v1','ORGANIZATION_MEMBERSHIP',"
        "'ORGANIZATION_ROLE','DEMAND_OWNER','CN','zh-CN',NULL,1,%s,%s)",
        (selector_digest, created_at, created_at),
    )
    connection.execute(
        "INSERT INTO iam.policy_documents ("
        "id,kind,locale,semantic_version,canonical_body,content_sha256,"
        "legal_effect,jurisdiction,status,effective_at,"
        "superseded_by_document_id,publication_command_id,created_at,updated_at"
        ") VALUES (%s,'COMMUNITY_TRANSACTION_COVENANT','zh-CN','1.0.0',%s,%s,"
        "'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,NULL,%s,%s,%s)",
        (
            policy_document_id,
            policy_body,
            policy_hash,
            policy_effective_at,
            publication_command_id,
            created_at,
            policy_effective_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.policy_bundles ("
        "id,selector_digest,status,effective_at,effective_until,"
        "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
        "release_signing_key_id,publication_command_id,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'demand-pg-signing-v1',"
        "%s,1,%s,%s)",
        (
            policy_bundle_id,
            selector_digest,
            _digest("demand-pg-policy-manifest"),
            b"reviewed-demand-pg-signature",
            publication_command_id,
            created_at,
            created_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.policy_bundle_documents "
        "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
        (policy_bundle_id, policy_document_id),
    )
    connection.execute(
        "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
        "aggregate_version=2,updated_at=%s WHERE id=%s",
        (policy_effective_at, policy_effective_at, policy_bundle_id),
    )
    connection.execute(
        "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
        "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
        (policy_bundle_id, policy_effective_at, selector_digest),
    )
    connection.execute(
        "INSERT INTO iam.users "
        "(id,status,display_handle,aggregate_version,created_at,updated_at) "
        "VALUES (%s,'ACTIVE','demand_pg_owner',7,%s,%s)",
        (ACTOR_USER_ID, created_at, membership_accepted_at),
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
            _digest("demand-pg-contact-binding"),
            membership_accepted_at,
            now + timedelta(days=365),
            created_at,
            membership_accepted_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.organizations ("
        "id,organization_type,public_name,jurisdiction,status,"
        "client_reference_namespace,client_reference,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,'BUSINESS','Demand PG Synthetic Organization','CN','ACTIVE',"
        "'demand-pg','synthetic-org-0001',3,%s,%s)",
        (ORGANIZATION_ID, created_at, membership_accepted_at),
    )
    connection.execute(
        "INSERT INTO iam.access_invitations ("
        "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
        "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
        "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
        "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
        "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
        "%s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION','DEMAND_OWNER',false,"
        "%s,'d***@example.invalid',%s,%s,'ACCEPTED',%s,'USER',%s,%s,"
        "'invitation-token-v1',%s,%s,NULL,2,%s,%s)",
        (
            invitation_id,
            ORGANIZATION_ID,
            contact_id,
            selector_digest,
            policy_bundle_id,
            now + timedelta(days=300),
            ACTOR_USER_ID,
            _digest("demand-pg-invitation-nonce"),
            ACTOR_USER_ID,
            membership_accepted_at,
            created_at,
            membership_accepted_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.memberships ("
        "id,organization_id,user_id,status,source_invitation_id,"
        "aggregate_version,created_at,updated_at) VALUES ("
        "%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
        (
            MEMBERSHIP_ID,
            ORGANIZATION_ID,
            ACTOR_USER_ID,
            invitation_id,
            membership_accepted_at,
            membership_accepted_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.membership_role_grants ("
        "id,organization_id,membership_id,user_id,role_code,"
        "source_invitation_id,policy_selector_digest,granted_by_kind,"
        "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
        "aggregate_version) VALUES ("
        "%s,%s,%s,%s,'DEMAND_OWNER',%s,%s,'USER',%s,%s,NULL,NULL,1)",
        (
            MEMBERSHIP_ROLE_GRANT_ID,
            ORGANIZATION_ID,
            MEMBERSHIP_ID,
            ACTOR_USER_ID,
            invitation_id,
            selector_digest,
            ACTOR_USER_ID,
            membership_accepted_at,
        ),
    )
    transaction_created_at = auth_time - timedelta(minutes=5)
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
            _digest("demand-pg-browser-binding"),
            _digest("demand-pg-state"),
            _digest("demand-pg-nonce"),
            b"reviewed-demand-pg-pkce-ciphertext",
            now + timedelta(days=30),
            auth_time,
            transaction_created_at,
            auth_time,
        ),
    )
    connection.execute(
        "INSERT INTO iam.session_families ("
        "id,user_id,status,current_generation,revoked_at,"
        "revocation_reason_code,aggregate_version,created_at,updated_at) "
        "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
        (session_family_id, ACTOR_USER_ID, session_created_at, session_created_at),
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
            session_family_id,
            _digest(RAW_SESSION_SENTINEL),
            _digest("demand-pg-csrf-salt"),
            _digest(RAW_CSRF_SENTINEL),
            auth_transaction_id,
            auth_time,
            session_created_at,
            now - timedelta(minutes=1),
            now + timedelta(days=1),
            now + timedelta(days=365),
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
            _new_id(0xD6),
            ACTOR_USER_ID,
            policy_document_id,
            policy_hash,
            policy_bundle_id,
            accepted_at,
            SESSION_ID,
            auth_transaction_id,
            auth_time,
            acceptance_command_id,
            _new_id(0xD7),
            accepted_at,
        ),
    )
    reviewer_auth_time = now - timedelta(hours=3)
    reviewer_created_at = now - timedelta(days=2)
    reviewer_session_created_at = now - timedelta(hours=2)
    connection.execute(
        "INSERT INTO iam.users ("
        "id,status,display_handle,aggregate_version,created_at,updated_at) "
        "VALUES (%s,'ACTIVE','demand_pg_reviewer',1,%s,%s)",
        (REVIEWER_USER_ID, reviewer_created_at, reviewer_created_at),
    )
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
            REVIEWER_AUTH_TRANSACTION_ID,
            _digest("demand-pg-reviewer-browser-binding"),
            _digest("demand-pg-reviewer-state"),
            _digest("demand-pg-reviewer-nonce"),
            b"reviewed-demand-pg-reviewer-pkce",
            now + timedelta(days=30),
            reviewer_auth_time,
            reviewer_created_at,
            reviewer_auth_time,
        ),
    )
    connection.execute(
        "INSERT INTO iam.session_families ("
        "id,user_id,status,current_generation,revoked_at,"
        "revocation_reason_code,aggregate_version,created_at,updated_at) "
        "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
        (
            REVIEWER_SESSION_FAMILY_ID,
            REVIEWER_USER_ID,
            reviewer_session_created_at,
            reviewer_session_created_at,
        ),
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
            REVIEWER_SESSION_ID,
            REVIEWER_USER_ID,
            REVIEWER_SESSION_FAMILY_ID,
            _digest("demand-pg-reviewer-session"),
            _digest("demand-pg-reviewer-csrf-salt"),
            _digest("demand-pg-reviewer-csrf"),
            REVIEWER_AUTH_TRANSACTION_ID,
            reviewer_auth_time,
            reviewer_session_created_at,
            now - timedelta(minutes=1),
            now + timedelta(days=1),
            now + timedelta(days=365),
            now - timedelta(minutes=1),
        ),
    )
    connection.execute(
        "INSERT INTO iam.platform_duty_grants ("
        "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
        "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,%s,'OPERATIONS_REVIEWER','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s)",
        (
            REVIEWER_DUTY_GRANT_ID,
            REVIEWER_USER_ID,
            ACTOR_USER_ID,
            reviewer_created_at,
            reviewer_created_at,
            reviewer_created_at,
        ),
    )
    return SeededDemandOwnerIamAuthority(
        actor_user_id=ACTOR_USER_ID,
        session_id=SESSION_ID,
        session_family_id=session_family_id,
        organization_id=ORGANIZATION_ID,
        membership_id=MEMBERSHIP_ID,
        membership_role_grant_id=MEMBERSHIP_ROLE_GRANT_ID,
        policy_bundle_id=policy_bundle_id,
        policy_selector_digest=selector_digest,
        required_document_id=policy_document_id,
        required_document_sha256=policy_hash,
    )


def rule_requirement() -> DemandPostgresRuleRequirement:
    return DemandPostgresRuleRequirement(
        taxonomy_bundle_id=TAXONOMY_ID,
        budget_rule_bundle_id=BUDGET_RULE_ID,
        risk_rule_bundle_id=RISK_RULE_ID,
        matching_rule_bundle_id=MATCHING_RULE_ID,
        reason_code_bundle_id=REASON_RULE_ID,
        composite_rule_requirement_id=COMPOSITE_RULE_ID,
        requirement_sha256=_digest("demand-rule-requirement-v1"),
        effective_at=UTC_NOW - timedelta(days=1),
        effective_until=UTC_NOW + timedelta(days=30),
    )


def content_policy() -> DemandPostgresContentPolicyEvidence:
    _canonical, content_hash = _canonical_material()
    return DemandPostgresContentPolicyEvidence(
        demand_id=DEMAND_ID,
        demand_version_id=DEMAND_VERSION_ID,
        content_sha256=content_hash,
        decision="ALLOW",
        policy_version="demand-content-policy-v1",
        result_sha256=_digest("demand-content-policy-result-v1"),
        evaluated_at=UTC_NOW - timedelta(seconds=1),
        valid_until=UTC_NOW + timedelta(days=30),
    )


def hold(
    operation: DemandPostgresOperation,
    *,
    expected_version: int,
    actor_id: uuid.UUID = ACTOR_USER_ID,
) -> DemandPostgresHoldEvidence:
    _canonical, content_hash = _canonical_material()
    action = {
        DemandPostgresOperation.SUBMIT: "SUBMIT_DEMAND",
        DemandPostgresOperation.VERIFY: "VERIFY_DEMAND",
        DemandPostgresOperation.REQUEST_MATCHING: "REQUEST_MATCHING",
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: "REQUEST_MATCHING",
    }[operation]
    return DemandPostgresHoldEvidence(
        actor_id=actor_id,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        prospective_aggregate_version=expected_version + 1,
        demand_version_id=DEMAND_VERSION_ID,
        content_sha256=content_hash,
        action=action,
        decision="ALLOW",
        policy_version="demand-safety-hold-v1",
        evaluated_at=UTC_NOW - timedelta(seconds=1),
        valid_until=UTC_NOW + timedelta(days=30),
    )


def source_event(operation: DemandPostgresOperation) -> DemandPostgresSourceEvent:
    if operation is DemandPostgresOperation.APPLY_FUNDING_SECURED:
        return DemandPostgresSourceEvent(
            source_event_id=FUNDING_EVENT_ID,
            event_type="FundingSecured",
            schema_version=1,
            source_aggregate_type="Funding",
            source_aggregate_id=FUNDING_ID,
            source_aggregate_version=3,
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
            funding_id=FUNDING_ID,
            amount_currency_sha256=_digest("demand-funding-amount-currency"),
            verification_reference_sha256=_digest(RAW_PROVIDER_SENTINEL),
            envelope_sha256=_digest("demand-funding-envelope"),
            occurred_at=UTC_NOW - timedelta(seconds=10),
        )
    if operation is DemandPostgresOperation.EXPIRE:
        return DemandPostgresSourceEvent(
            source_event_id=EXPIRY_EVENT_ID,
            event_type="DemandExpiryDue",
            schema_version=1,
            source_aggregate_type="Scheduler",
            source_aggregate_id=_new_id(0xE1),
            source_aggregate_version=1,
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
            funding_id=None,
            envelope_sha256=_digest("demand-expiry-envelope"),
            occurred_at=UTC_NOW,
        )
    raise ValueError("source_event requires a source-driven operation")


_COMMAND_NAME = {
    DemandPostgresOperation.CREATE: "CreateDemand",
    DemandPostgresOperation.CREATE_VERSION: "CreateDemandVersion",
    DemandPostgresOperation.SUBMIT: "SubmitDemand",
    DemandPostgresOperation.REQUEST_CHANGES: "RequestDemandChanges",
    DemandPostgresOperation.VERIFY: "VerifyDemand",
    DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
        "ReleaseDemandReviewAssignment"
    ),
    DemandPostgresOperation.REQUEST_MATCHING: "RequestMatching",
    DemandPostgresOperation.REQUEST_MATCHING_SYSTEM: "RequestMatching",
    DemandPostgresOperation.CANCEL_OWNER: "CancelDemand",
    DemandPostgresOperation.CANCEL_REVIEW: "CancelDemand",
}


def _canonical_path(operation: DemandPostgresOperation) -> str:
    organization = str(ORGANIZATION_ID)
    demand_id = str(DEMAND_ID)
    if operation is DemandPostgresOperation.CREATE:
        return f"/v1/organizations/{organization}/demands"
    if operation is DemandPostgresOperation.CREATE_VERSION:
        return f"/v1/organizations/{organization}/demands/{demand_id}/versions"
    if operation is DemandPostgresOperation.SUBMIT:
        return f"/v1/organizations/{organization}/demands/{demand_id}/submit"
    if operation is DemandPostgresOperation.REQUEST_CHANGES:
        return f"/v1/operations/demand-review-assignments/{ASSIGNMENT_ID}/request-changes"
    if operation is DemandPostgresOperation.VERIFY:
        return f"/v1/operations/demand-review-assignments/{ASSIGNMENT_ID}/verify"
    if operation is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT:
        return f"/v1/operations/demand-review-assignments/{ASSIGNMENT_ID}/release"
    if operation in {
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
    }:
        return f"/v1/operations/demands/{demand_id}/request-matching"
    if operation in {DemandPostgresOperation.CANCEL_OWNER, DemandPostgresOperation.CANCEL_REVIEW}:
        return f"/v1/organizations/{organization}/demands/{demand_id}/cancel"
    raise ValueError("source-driven operation has no receipt path")


def postgres_command(
    operation: DemandPostgresOperation,
    *,
    expected_version: int = 1,
    actor_id: Optional[uuid.UUID] = None,
    idempotency_material: str = RAW_IDEMPOTENCY_SENTINEL,
    payload_label: Optional[str] = None,
    command_variant: int = 0,
) -> DemandPostgresCommand:
    writer_operations = tuple(
        item
        for item in DemandPostgresOperation
        if item is not DemandPostgresOperation.CAPTURE_MATCH_INPUTS
    )
    ordinal = writer_operations.index(operation) + 0x90
    identity_ordinal = ordinal + command_variant * 0x100
    command_id = _new_id(identity_ordinal)
    source = (
        source_event(operation)
        if operation
        in {DemandPostgresOperation.APPLY_FUNDING_SECURED, DemandPostgresOperation.EXPIRE}
        else None
    )
    actor_kind = (
        "SYSTEM"
        if source is not None
        or operation is DemandPostgresOperation.REQUEST_MATCHING_SYSTEM
        else "USER"
    )
    reviewer_operation = operation in {
        DemandPostgresOperation.REQUEST_CHANGES,
        DemandPostgresOperation.VERIFY,
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.CANCEL_REVIEW,
    }
    resolved_actor_id = actor_id or (
        REVIEWER_USER_ID if reviewer_operation else ACTOR_USER_ID
    )
    resolved_session_id = (
        REVIEWER_SESSION_ID if reviewer_operation else SESSION_ID
    )
    if operation in {
        DemandPostgresOperation.CREATE,
        DemandPostgresOperation.CREATE_VERSION,
        DemandPostgresOperation.SUBMIT,
        DemandPostgresOperation.CANCEL_OWNER,
    }:
        authority_marker = owner_authority_marker(operation)
    elif reviewer_operation:
        authority_marker = reviewer_authority_marker(operation)
    else:
        authority_marker = _digest("exact-demand-authority-marker")
    causation_id = (
        source.source_event_id
        if source is not None
        else _new_id(identity_ordinal + 0x20)
    )
    event_count = 2 if operation is DemandPostgresOperation.CREATE else 1
    scope = DemandPostgresExecutionScope(
        actor_kind=actor_kind,
        actor_id=resolved_actor_id if actor_kind == "USER" else WORKLOAD_ID,
        session_id=resolved_session_id if actor_kind == "USER" else None,
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        command_id=command_id,
        audit_event_id=_new_id(identity_ordinal + 0x10),
        outbox_event_ids=tuple(
            _new_id(identity_ordinal + 0x30 + index)
            for index in range(event_count)
        ),
        correlation_id=_new_id(identity_ordinal + 0x40),
        causation_id=causation_id,
        trace_id=_new_id(identity_ordinal + 0x50),
        original_actor_id=None,
        expected_authority_marker_sha256=authority_marker,
    )
    receipt = None
    if operation in _COMMAND_NAME:
        receipt = DemandPostgresReceiptMaterial(
            receipt_id=command_id,
            principal_kind=actor_kind,
            principal_id=scope.actor_id,
            organization_id=ORGANIZATION_ID,
            command_name=_COMMAND_NAME[operation],
            command_version=1,
            idempotency_key_digest_key_id="demand-idempotency-2026-01",
            idempotency_key_digest=_keyed("identity", idempotency_material),
            payload_hash_key_id="demand-payload-2026-01",
            canonicalization_version="demand-command-json-v1",
            payload_hash=_keyed(
                "payload",
                payload_label
                or f"{operation.value}:{DEMAND_ID}:{expected_version}",
            ),
            http_method="POST",
            canonical_path=_canonical_path(operation),
            if_match_version=(
                None if operation is DemandPostgresOperation.CREATE else expected_version
            ),
            retain_until=UTC_NOW + timedelta(days=7),
        )
    canonical, content_hash = _canonical_material()
    common = dict(
        operation=operation,
        scope=scope,
        receipt=receipt,
        expected_aggregate_version=(
            None if operation is DemandPostgresOperation.CREATE else expected_version
        ),
    )
    if operation is DemandPostgresOperation.CREATE:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=TAXONOMY_ID,
            canonical_demand_version_bytes=canonical,
            content_sha256=content_hash,
            client_reference_digest_key_id="demand-client-ref-2026-01",
            client_reference_digest=_keyed("client-ref", RAW_CLIENT_REFERENCE_SENTINEL),
        )
    if operation is DemandPostgresOperation.CREATE_VERSION:
        canonical2, content_hash2 = _canonical_material(version_no=2)
        return DemandPostgresCommand(
            **common,
            demand_version_id=SECOND_DEMAND_VERSION_ID,
            based_on_demand_version_id=DEMAND_VERSION_ID,
            taxonomy_bundle_id=TAXONOMY_ID,
            canonical_demand_version_bytes=canonical2,
            content_sha256=content_hash2,
        )
    if operation is DemandPostgresOperation.SUBMIT:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            submission_id=SUBMISSION_ID,
            content_policy=content_policy(),
            hold=hold(
                operation,
                expected_version=expected_version,
                actor_id=resolved_actor_id,
            ),
            rule_requirement=rule_requirement(),
        )
    if operation is DemandPostgresOperation.REQUEST_CHANGES:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            assignment_id=ASSIGNMENT_ID,
            review_id=REVIEW_ID,
            reason_codes=("SCOPE_UNCLEAR",),
            required_field_codes=("SCOPE",),
        )
    if operation is DemandPostgresOperation.VERIFY:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            assignment_id=ASSIGNMENT_ID,
            review_id=REVIEW_ID,
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_summary_sha256=_digest(RAW_REVIEW_SENTINEL),
            hold=hold(
                operation,
                expected_version=expected_version,
                actor_id=resolved_actor_id,
            ),
            rule_requirement=rule_requirement(),
        )
    if operation is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            assignment_id=ASSIGNMENT_ID,
            release_reason_code="WORKLOAD_RELEASE",
        )
    if operation is DemandPostgresOperation.APPLY_FUNDING_SECURED:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            funding_marker_id=FUNDING_MARKER_ID,
            source_event=source,
        )
    if operation in {
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
    }:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            assignment_id=(
                ASSIGNMENT_ID
                if operation is DemandPostgresOperation.REQUEST_MATCHING
                else None
            ),
            matching_request_id=MATCHING_REQUEST_ID,
            hold=hold(
                operation,
                expected_version=expected_version,
                actor_id=scope.actor_id,
            ),
            rule_requirement=rule_requirement(),
        )
    if operation is DemandPostgresOperation.CANCEL_OWNER:
        return DemandPostgresCommand(
            **common,
            demand_version_id=None,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            cancel_reason_code="OWNER_WITHDREW",
        )
    if operation is DemandPostgresOperation.CANCEL_REVIEW:
        return DemandPostgresCommand(
            **common,
            demand_version_id=None,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            assignment_id=ASSIGNMENT_ID,
            cancel_reason_code="REVIEW_CLOSED",
        )
    if operation is DemandPostgresOperation.EXPIRE:
        return DemandPostgresCommand(
            **common,
            demand_version_id=DEMAND_VERSION_ID,
            based_on_demand_version_id=None,
            taxonomy_bundle_id=None,
            deadline=UTC_NOW,
            source_event=source,
        )
    raise ValueError("writer builder received MATCH_INPUT")


def reset_demand_postgres_state(connection: Any) -> None:
    """Reset only the isolated Demand test context and its shared projections."""

    connection.execute(
        "TRUNCATE TABLE demand.command_receipts,demand.source_inbox,"
        "demand.matching_requests,demand.demand_funding_markers,"
        "demand.demand_reviews,demand.demand_review_assignment_releases,"
        "demand.demand_review_assignments,"
        "demand.demand_submissions,demand.demand_versions,demand.demands CASCADE"
    )
    connection.execute("TRUNCATE TABLE audit.audit_events,infra.outbox_events")


def seed_demand_operation_graph(
    connection: Any,
    operation: DemandPostgresOperation,
) -> None:
    """Seed the minimum legal pre-command graph for one fixed program."""

    if operation is DemandPostgresOperation.CREATE:
        return
    connection.execute("SET CONSTRAINTS ALL DEFERRED")
    canonical, content_hash = _canonical_material()
    content = thaw_json(valid_content())
    content["risk"]["data_handling_plan"] = RAW_CONTENT_SENTINEL
    needs_submission = operation in {
        DemandPostgresOperation.REQUEST_CHANGES,
        DemandPostgresOperation.VERIFY,
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        DemandPostgresOperation.APPLY_FUNDING_SECURED,
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
        DemandPostgresOperation.CANCEL_OWNER,
        DemandPostgresOperation.CANCEL_REVIEW,
        DemandPostgresOperation.CAPTURE_MATCH_INPUTS,
    }
    needs_verified = operation in {
        DemandPostgresOperation.APPLY_FUNDING_SECURED,
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
        DemandPostgresOperation.CANCEL_OWNER,
        DemandPostgresOperation.CAPTURE_MATCH_INPUTS,
    }
    needs_funding = operation in {
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.REQUEST_MATCHING_SYSTEM,
        DemandPostgresOperation.CANCEL_OWNER,
        DemandPostgresOperation.CAPTURE_MATCH_INPUTS,
    }
    needs_matching = operation is DemandPostgresOperation.CAPTURE_MATCH_INPUTS
    needs_active_assignment = operation in {
        DemandPostgresOperation.REQUEST_CHANGES,
        DemandPostgresOperation.VERIFY,
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.CANCEL_REVIEW,
    }
    status = (
        "MATCHING"
        if needs_matching
        else "FUNDED"
        if needs_funding
        else "VERIFIED"
        if needs_verified
        else "SUBMITTED"
        if needs_submission
        else "DRAFT"
    )
    expires_at = (
        UTC_NOW
        if operation is DemandPostgresOperation.EXPIRE
        else UTC_NOW + timedelta(days=90)
    )
    connection.execute(
        "INSERT INTO demand.demands ("
        "id,organization_id,creator_user_id,client_reference_digest_key_id,"
        "client_reference_digest,status,aggregate_version,current_version_id,"
        "current_submission_id,current_review_id,verified_version_id,"
        "current_funding_marker_id,current_matching_request_id,expires_at,"
        "created_at,updated_at) VALUES ("
        "%s,%s,%s,'demand-client-ref-2026-01',%s,%s,1,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            DEMAND_ID,
            ORGANIZATION_ID,
            ACTOR_USER_ID,
            _keyed("client-ref", RAW_CLIENT_REFERENCE_SENTINEL),
            status,
            DEMAND_VERSION_ID,
            SUBMISSION_ID if needs_submission else None,
            PRIOR_REVIEW_ID if needs_verified else None,
            DEMAND_VERSION_ID if needs_verified else None,
            FUNDING_MARKER_ID if needs_funding else None,
            MATCHING_REQUEST_ID if needs_matching else None,
            expires_at,
            UTC_NOW - timedelta(days=10),
            UTC_NOW - timedelta(minutes=1),
        ),
    )
    connection.execute(
        "INSERT INTO demand.demand_versions ("
        "id,organization_id,demand_id,version_no,based_on_demand_version_id,"
        "demand_schema_version,canonicalization_version,taxonomy_bundle_id,"
        "canonical_version_bytes,content,content_sha256,created_by_user_id,"
        "created_at) VALUES ("
        "%s,%s,%s,1,NULL,1,'demand-content-json-v1',%s,%s,%s::jsonb,%s,%s,%s)",
        (
            DEMAND_VERSION_ID,
            ORGANIZATION_ID,
            DEMAND_ID,
            TAXONOMY_ID,
            canonical,
            json.dumps(content, ensure_ascii=False, separators=(",", ":")),
            content_hash,
            ACTOR_USER_ID,
            UTC_NOW - timedelta(days=10),
        ),
    )
    if needs_submission:
        connection.execute(
            "INSERT INTO demand.demand_submissions ("
            "id,organization_id,demand_id,demand_version_id,content_sha256,"
            "submitted_by_user_id,content_policy_version,"
            "content_policy_result_sha256,rule_requirement_sha256,submitted_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,'demand-content-policy-v1',%s,%s,%s)",
            (
                SUBMISSION_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                content_hash,
                ACTOR_USER_ID,
                _digest("demand-content-policy-result-v1"),
                _digest("demand-rule-requirement-v1"),
                UTC_NOW - timedelta(days=2),
            ),
        )
    if needs_verified:
        connection.execute(
            "INSERT INTO demand.demand_review_assignments ("
            "id,organization_id,demand_id,submission_id,demand_version_id,"
            "reviewer_user_id,duty_grant_id,duty_grant_version,purpose_code,"
            "conflict_attestation_sha256,authority_marker_sha256,status,"
            "expires_at,aggregate_version,created_at,completed_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,1,'DEMAND_REVIEW',%s,%s,'COMPLETED',"
            "%s,2,%s,%s)",
            (
                PRIOR_ASSIGNMENT_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                SUBMISSION_ID,
                DEMAND_VERSION_ID,
                REVIEWER_USER_ID,
                _new_id(0xF1),
                _digest("reviewer-conflict-clear"),
                _digest("reviewer-duty-authority"),
                UTC_NOW + timedelta(days=30),
                UTC_NOW - timedelta(days=1),
                UTC_NOW - timedelta(hours=12),
            ),
        )
        connection.execute(
            "INSERT INTO demand.demand_reviews ("
            "id,organization_id,demand_id,submission_id,demand_version_id,"
            "content_sha256,assignment_id,reviewer_user_id,decision,"
            "reason_codes,required_field_codes,budget_health_code,risk_code,"
            "evidence_summary_sha256,rule_requirement_sha256,reviewed_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'VERIFIED',ARRAY[]::text[],"
            "ARRAY[]::text[],'HEALTHY','STANDARD',%s,%s,%s)",
            (
                PRIOR_REVIEW_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                SUBMISSION_ID,
                DEMAND_VERSION_ID,
                content_hash,
                PRIOR_ASSIGNMENT_ID,
                REVIEWER_USER_ID,
                _digest("prior-reviewed-evidence"),
                _digest("demand-rule-requirement-v1"),
                UTC_NOW - timedelta(hours=12),
            ),
        )
    if needs_active_assignment:
        connection.execute(
            "INSERT INTO demand.demand_review_assignments ("
            "id,organization_id,demand_id,submission_id,demand_version_id,"
            "reviewer_user_id,duty_grant_id,duty_grant_version,purpose_code,"
            "conflict_attestation_sha256,authority_marker_sha256,status,"
            "expires_at,aggregate_version,created_at,completed_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,1,'DEMAND_REVIEW',%s,%s,'ACTIVE',"
            "%s,1,%s,NULL)",
            (
                ASSIGNMENT_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                SUBMISSION_ID,
                DEMAND_VERSION_ID,
                REVIEWER_USER_ID,
                REVIEWER_DUTY_GRANT_ID,
                _digest("reviewer-conflict-clear-current"),
                _digest("reviewer-duty-authority-current"),
                UTC_NOW + timedelta(days=30),
                UTC_NOW - timedelta(hours=1),
            ),
        )
    if needs_funding:
        connection.execute(
            "INSERT INTO demand.demand_funding_markers ("
            "id,organization_id,demand_id,demand_version_id,funding_id,status,"
            "source_event_id,source_aggregate_version,amount_currency_sha256,"
            "verification_reference_sha256,occurred_at,created_at) VALUES ("
            "%s,%s,%s,%s,%s,'SECURED',%s,3,%s,%s,%s,%s)",
            (
                FUNDING_MARKER_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                FUNDING_ID,
                _new_id(0xF3),
                _digest("demand-funding-amount-currency"),
                _digest("demand-funding-verification"),
                UTC_NOW - timedelta(hours=6),
                UTC_NOW - timedelta(hours=6),
            ),
        )
    if needs_matching:
        connection.execute(
            "INSERT INTO demand.matching_requests ("
            "id,organization_id,demand_id,aggregate_version,status,"
            "demand_version_id,verified_review_id,funding_marker_id,funding_id,"
            "taxonomy_bundle_id,budget_rule_bundle_id,risk_rule_bundle_id,"
            "matching_rule_bundle_id,reason_code_bundle_id,"
            "composite_rule_requirement_id,matching_selector_digest,"
            "rule_requirement_sha256,budget_override_code,"
            "authorized_workload_principal_id,authorization_digest,requested_at) "
            "VALUES (%s,%s,%s,1,'OPEN',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
            "NULL,%s,%s,%s)",
            (
                MATCHING_REQUEST_ID,
                ORGANIZATION_ID,
                DEMAND_ID,
                DEMAND_VERSION_ID,
                PRIOR_REVIEW_ID,
                FUNDING_MARKER_ID,
                FUNDING_ID,
                TAXONOMY_ID,
                BUDGET_RULE_ID,
                RISK_RULE_ID,
                MATCHING_RULE_ID,
                REASON_RULE_ID,
                COMPOSITE_RULE_ID,
                _digest("demand-matching-selector-v1"),
                _digest("demand-rule-requirement-v1"),
                WORKLOAD_ID,
                _digest("exact-demand-match-request-allowlist"),
                UTC_NOW - timedelta(minutes=5),
            ),
        )


def match_capture_request(
    *,
    request_ids: tuple[uuid.UUID, ...] = (MATCHING_REQUEST_ID,),
) -> DemandPostgresMatchCaptureRequest:
    return DemandPostgresMatchCaptureRequest(
        match_run_id=MATCH_RUN_ID,
        workload_principal_id=WORKLOAD_ID,
        matching_request_ids=tuple(sorted(request_ids, key=lambda value: value.bytes)),
        authorization_digest=_digest("exact-demand-match-request-allowlist"),
        requested_at=UTC_NOW,
    )


def match_input_snapshot(
    *,
    matching_request_id: uuid.UUID = MATCHING_REQUEST_ID,
    captured_at: datetime = UTC_NOW,
) -> DemandPostgresMatchInputSnapshot:
    canonical, content_hash = _canonical_material()
    content = thaw_json(valid_content())
    levels = {
        "FOUNDATION": 1,
        "WORKING": 2,
        "ADVANCED": 3,
        "EXPERT": 4,
    }

    def skills(key: str) -> tuple[DemandPostgresMatchSkillRequirement, ...]:
        return tuple(
            sorted(
                (
                    DemandPostgresMatchSkillRequirement(
                        skill_code=item["skill_code"],
                        minimum_level=levels[item["minimum_level_code"]],
                    )
                    for item in content["skills"][key]
                ),
                key=lambda item: item.skill_code.encode("utf-8"),
            )
        )

    def codes(values: Any) -> tuple[str, ...]:
        return tuple(sorted(values, key=lambda item: item.encode("utf-8")))

    ai_policy = content["ai"]
    ai_use_code = (
        "REQUIRED"
        if ai_policy["required"]
        else "OPTIONAL"
        if ai_policy["allowed"]
        else "PROHIBITED"
    )
    return DemandPostgresMatchInputSnapshot(
        matching_request_id=matching_request_id,
        matching_request_version=1,
        matching_request_status="OPEN",
        organization_id=ORGANIZATION_ID,
        demand_id=DEMAND_ID,
        demand_status="MATCHING",
        demand_version_id=DEMAND_VERSION_ID,
        demand_version_no=1,
        verification_decision="VERIFIED",
        content_sha256=content_hash,
        canonical_demand_version_bytes=canonical,
        taxonomy_bundle_id=TAXONOMY_ID,
        funding_id=FUNDING_ID,
        funding_status="SECURED",
        composite_rule_requirement_id=COMPOSITE_RULE_ID,
        budget_rule_bundle_id=BUDGET_RULE_ID,
        risk_rule_bundle_id=RISK_RULE_ID,
        matching_rule_bundle_id=MATCHING_RULE_ID,
        reason_code_bundle_id=REASON_RULE_ID,
        matching_selector_digest=_digest("demand-matching-selector-v1"),
        rule_requirement_sha256=_digest("demand-rule-requirement-v1"),
        problem_type_codes=codes(content["matching"]["problem_codes"]),
        domain_codes=codes(content["matching"]["domain_codes"]),
        task_codes=codes(content["matching"]["task_codes"]),
        must_have_skills=skills("must_have"),
        nice_to_have_skills=skills("nice_to_have"),
        start_date=date.fromisoformat(content["schedule"]["start_date"]),
        due_date=date.fromisoformat(content["schedule"]["due_date"]),
        required_weekly_hours=content["schedule"]["weekly_hours"],
        required_duration_weeks=content["schedule"]["duration_weeks"],
        currency=content["budget"]["currency"],
        minimum_amount_minor=content["budget"]["minimum_amount_minor"],
        maximum_amount_minor=content["budget"]["maximum_amount_minor"],
        allowed_region_codes=codes(
            "REGION." + item.upper()
            for item in content["location"]["allowed_creator_region_codes"]
        ),
        required_language_codes=codes(
            "LANGUAGE." + item.upper()
            for item in content["collaboration"]["languages"]
        ),
        required_work_mode_code=(
            "WORK_MODE." + content["collaboration"]["work_mode"].upper()
        ),
        data_sensitivity_code=content["risk"]["data_sensitivity"],
        ai_use_code=ai_use_code,
        budget_override_code=None,
        captured_at=captured_at,
    )


def match_capture_result(
    *,
    captured_at: datetime = UTC_NOW,
) -> DemandPostgresMatchCaptureResult:
    snapshot = match_input_snapshot(captured_at=captured_at)
    return DemandPostgresMatchCaptureResult(
        match_run_id=MATCH_RUN_ID,
        captured_at=captured_at,
        requested_matching_request_ids=(MATCHING_REQUEST_ID,),
        snapshots=(snapshot,),
        statement_count=2,
    )


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
        transaction_timestamps: list[datetime],
        *,
        lose_commit_ack: bool = False,
    ) -> None:
        self._raw = raw
        self._trace = trace
        self._transaction_timestamps = transaction_timestamps
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
                "synthetic Demand COMMIT acknowledgement loss"
            )
        result = self._raw.execute(query, parameters, *args, **kwargs)
        if normalized.upper() == "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY":
            # Test-only observation: capture the server clock from the same
            # transaction without adding it to the production statement trace.
            self._transaction_timestamps.append(
                self._raw.execute("SELECT transaction_timestamp()").fetchone()[0]
            )
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class TrackingDemandConnectionSource:
    """Role-bound real psycopg source; default-deny RED must not checkout."""

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
        self.transaction_timestamps: list[datetime] = []
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
            self.transaction_timestamps,
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


class InjectedDemandPostgresWriteFailure(RuntimeError):
    pass


class RaiseAtDemandCheckpoint:
    def __init__(self, target: DemandPostgresWriteCheckpoint) -> None:
        self.target = target
        self.calls: list[tuple[DemandPostgresWriteCheckpoint, int]] = []

    def before_write(
        self,
        checkpoint: DemandPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        self.calls.append((checkpoint, ordinal))
        if checkpoint is self.target:
            raise InjectedDemandPostgresWriteFailure(checkpoint.value)


def with_scope(
    request: DemandPostgresCommand,
    *,
    organization_id: Optional[uuid.UUID] = None,
    actor_id: Optional[uuid.UUID] = None,
    authority_marker: Optional[bytes] = None,
) -> DemandPostgresCommand:
    scope = replace(
        request.scope,
        organization_id=organization_id or request.scope.organization_id,
        actor_id=actor_id or request.scope.actor_id,
        expected_authority_marker_sha256=(
            authority_marker or request.scope.expected_authority_marker_sha256
        ),
    )
    receipt = request.receipt
    if receipt is not None:
        canonical_path = receipt.canonical_path
        if organization_id is not None:
            canonical_path = canonical_path.replace(
                str(request.scope.organization_id),
                str(scope.organization_id),
            )
        receipt = replace(
            receipt,
            principal_id=scope.actor_id,
            organization_id=scope.organization_id,
            canonical_path=canonical_path,
        )
    bound_hold = request.hold
    if bound_hold is not None:
        bound_hold = replace(
            bound_hold,
            actor_id=scope.actor_id,
            organization_id=scope.organization_id,
        )
    return replace(request, scope=scope, receipt=receipt, hold=bound_hold)
