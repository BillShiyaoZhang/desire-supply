-- Appeal review storage and fixed-program boundary for PostgreSQL 18.
-- Trust0001 remains byte-frozen.  This forward migration adds only closed
-- Appeal relations, policies, helpers, and trust_api entry points.

DO $appeal_dependencies$
BEGIN
    IF pg_catalog.to_regprocedure(
        'iam_api.resolve_trust_reporter_authority_v1(uuid,uuid,uuid,text)'
    ) IS NULL
       OR pg_catalog.to_regprocedure(
        'iam_api.resolve_appeal_reviewer_authority_v1(uuid,uuid,text)'
       ) IS NULL
       OR pg_catalog.to_regprocedure(
        'demand_api.resolve_appeal_applicant_party_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)'
       ) IS NULL
       OR pg_catalog.to_regclass('trust.case_outcome_versions') IS NULL
       OR pg_catalog.to_regclass('trust.restricted_text_blobs') IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'APPEAL_MIGRATION_DEPENDENCY_UNAVAILABLE';
    END IF;
END
$appeal_dependencies$;

ALTER TABLE trust.cases
ADD CONSTRAINT uq_trust_case_appeal_source_scope UNIQUE (
    organization_id, case_id, demand_id, demand_version_id,
    outcome_version_id
);
ALTER TABLE trust.case_outcome_versions
ADD CONSTRAINT uq_trust_outcome_appeal_source_facts UNIQUE (
    organization_id, case_id, outcome_version_id,
    outcome_code, reason_codes, action_codes,
    evidence_packet_version_id, evidence_packet_digest,
    policy_version, decided_at, appeal_eligible,
    appeal_eligibility_code, appeal_deadline, content_sha256,
    decided_by_user_id
);

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions;
ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_hashes;
ALTER TABLE trust_meta.schema_contracts
ADD COLUMN appeal_api_contract_sha256 bytea NULL,
ADD COLUMN appeal_event_contract_sha256 bytea NULL,
ADD COLUMN appeal_application_contract_sha256 bytea NULL,
ADD COLUMN appeal_review_contract_sha256 bytea NULL;
DELETE FROM trust_meta.schema_contracts;
ALTER TABLE trust_meta.schema_contracts
ALTER COLUMN appeal_api_contract_sha256 SET NOT NULL,
ALTER COLUMN appeal_event_contract_sha256 SET NOT NULL,
ALTER COLUMN appeal_application_contract_sha256 SET NOT NULL,
ALTER COLUMN appeal_review_contract_sha256 SET NOT NULL;
ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 2
    AND min_app_compatible_version = 2
    AND max_app_compatible_version = 2
    AND required_iam_schema_version = 36
    AND required_demand_schema_version = 8
),
ADD CONSTRAINT ck_trust_schema_contract_hashes CHECK (
    octet_length(required_iam_contract_sha256) = 32
    AND octet_length(required_demand_contract_sha256) = 32
    AND octet_length(api_contract_sha256) = 32
    AND octet_length(event_contract_sha256) = 32
    AND octet_length(report_contract_sha256) = 32
    AND octet_length(triage_contract_sha256) = 32
    AND octet_length(appeal_api_contract_sha256) = 32
    AND octet_length(appeal_event_contract_sha256) = 32
    AND octet_length(appeal_application_contract_sha256) = 32
    AND octet_length(appeal_review_contract_sha256) = 32
    AND octet_length(combined_contract_sha256) = 32
    AND octet_length(migration_manifest_sha256) = 32
    AND required_iam_contract_sha256 = decode(
        '8be48226b6fb409f442c6331dffcebc69435d401a75aa423614a9b7e60eb86a4',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        '7d67863b0ce45bf19011d7ed1975fb5a73068f257c13083274689b2c8aa160f3',
        'hex'
    )
    AND api_contract_sha256 = decode(
        '14572f7768f31e9ced0b6ede09eb6eea1da3d2d4abd1c6d80cc4229c28e158bd',
        'hex'
    )
    AND event_contract_sha256 = decode(
        'a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582',
        'hex'
    )
    AND report_contract_sha256 = decode(
        '29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278',
        'hex'
    )
    AND triage_contract_sha256 = decode(
        'de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084',
        'hex'
    )
    AND appeal_api_contract_sha256 = decode(
        'e85d905e407679665e7bea0008253bc4ec2bd941c4442964016caeb4ce62ffa7',
        'hex'
    )
    AND appeal_event_contract_sha256 = decode(
        '7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba',
        'hex'
    )
    AND appeal_application_contract_sha256 = decode(
        '3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223',
        'hex'
    )
    AND appeal_review_contract_sha256 = decode(
        '08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b',
        'hex'
    )
    AND combined_contract_sha256 = sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:combined-contract:v2',
        encode(required_iam_contract_sha256, 'hex'),
        encode(required_demand_contract_sha256, 'hex'),
        encode(api_contract_sha256, 'hex'),
        encode(event_contract_sha256, 'hex'),
        encode(report_contract_sha256, 'hex'),
        encode(triage_contract_sha256, 'hex'),
        encode(appeal_api_contract_sha256, 'hex'),
        encode(appeal_event_contract_sha256, 'hex'),
        encode(appeal_application_contract_sha256, 'hex'),
        encode(appeal_review_contract_sha256, 'hex'),
        encode(migration_manifest_sha256, 'hex')
    ), 'UTF8'))
);

CREATE TABLE trust.appeals (
    appeal_id uuid PRIMARY KEY,
    source_outcome_version_id uuid NOT NULL,
    source_case_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    applicant_user_id uuid NOT NULL,
    applicant_membership_id uuid NOT NULL,
    applicant_role_grant_id uuid NOT NULL,
    applicant_role_grant_version bigint NOT NULL,
    applicant_authority_marker_sha256 bytea NOT NULL,
    applicant_party_marker_sha256 bytea NOT NULL,
    source_outcome_code varchar(64) NOT NULL,
    source_reason_codes text[] NOT NULL,
    source_action_codes text[] NOT NULL,
    source_evidence_packet_version_id uuid NOT NULL,
    source_evidence_packet_sha256 bytea NOT NULL,
    source_policy_version varchar(128) NOT NULL,
    source_decided_at timestamptz NOT NULL,
    source_appeal_deadline timestamptz NOT NULL,
    source_content_sha256 bytea NOT NULL,
    source_deciding_officer_user_id uuid NOT NULL,
    source_appeal_eligible boolean NOT NULL,
    source_appeal_eligibility_code varchar(64) NOT NULL,
    status varchar(16) NOT NULL,
    aggregate_version bigint NOT NULL,
    current_application_draft_version integer NULL,
    submitted_application_version integer NULL,
    current_assignment_id uuid NULL,
    current_review_draft_version integer NULL,
    decision_version_id uuid NULL,
    opened_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_appeal_source_applicant UNIQUE (
        applicant_user_id, source_outcome_version_id
    ),
    CONSTRAINT uq_appeal_scope_root UNIQUE (
        organization_id, source_case_id, appeal_id
    ),
    CONSTRAINT uq_appeal_frozen_source UNIQUE (
        appeal_id, source_outcome_version_id, source_content_sha256
    ),
    CONSTRAINT fk_appeal_source_case FOREIGN KEY (
        organization_id, source_case_id, demand_id, demand_version_id,
        source_outcome_version_id
    ) REFERENCES trust.cases (
        organization_id, case_id, demand_id, demand_version_id,
        outcome_version_id
    ),
    CONSTRAINT fk_appeal_source_outcome FOREIGN KEY (
        organization_id, source_case_id, source_outcome_version_id,
        source_outcome_code, source_reason_codes, source_action_codes,
        source_evidence_packet_version_id, source_evidence_packet_sha256,
        source_policy_version, source_decided_at, source_appeal_eligible,
        source_appeal_eligibility_code, source_appeal_deadline,
        source_content_sha256, source_deciding_officer_user_id
    ) REFERENCES trust.case_outcome_versions (
        organization_id, case_id, outcome_version_id,
        outcome_code, reason_codes, action_codes,
        evidence_packet_version_id, evidence_packet_digest,
        policy_version, decided_at, appeal_eligible,
        appeal_eligibility_code, appeal_deadline, content_sha256,
        decided_by_user_id
    ),
    CONSTRAINT ck_appeal_source_codes CHECK (
        source_outcome_code IN (
            'NO_ACTION', 'PROTECTION_LIFTED', 'PROTECTION_MAINTAINED',
            'PROTECTION_MODIFIED', 'REMEDIATION_REQUIRED'
        )
        AND trust.canonical_code_array_v1(source_reason_codes, 1, 32)
        AND source_reason_codes <@ ARRAY[
            'INSUFFICIENT_VERIFIED_EVIDENCE', 'NO_POLICY_BREACH',
            'POLICY_REQUIREMENT_NOT_MET', 'PRECAUTIONARY_ACTION_REQUIRED',
            'RISK_MITIGATED'
        ]::text[]
        AND trust.canonical_code_array_v1(source_action_codes, 0, 3)
        AND source_action_codes <@ ARRAY[
            'REQUEST_MATCHING', 'SUBMIT_DEMAND', 'VERIFY_DEMAND'
        ]::text[]
        AND (
            (source_outcome_code IN ('NO_ACTION', 'PROTECTION_LIFTED')
             AND cardinality(source_action_codes) = 0)
            OR
            (source_outcome_code NOT IN ('NO_ACTION', 'PROTECTION_LIFTED')
             AND cardinality(source_action_codes) >= 1)
        )
    ),
    CONSTRAINT ck_appeal_source_facts CHECK (
        source_policy_version = 'trust-case-outcome-v1'
        AND source_appeal_eligible
        AND source_appeal_eligibility_code = 'ELIGIBLE'
        AND source_appeal_deadline > source_decided_at
        AND applicant_role_grant_version >= 1
        AND octet_length(applicant_authority_marker_sha256) = 32
        AND octet_length(applicant_party_marker_sha256) = 32
        AND octet_length(source_evidence_packet_sha256) = 32
        AND octet_length(source_content_sha256) = 32
        AND applicant_user_id <> source_deciding_officer_user_id
    ),
    CONSTRAINT ck_appeal_state CHECK (
        status IN ('DRAFT', 'SUBMITTED', 'IN_REVIEW', 'DECIDED', 'WITHDRAWN')
        AND aggregate_version >= 1
        AND updated_at >= opened_at
        AND (
            (status = 'DRAFT'
             AND submitted_application_version IS NULL
             AND current_assignment_id IS NULL
             AND current_review_draft_version IS NULL
             AND decision_version_id IS NULL)
            OR
            (status = 'SUBMITTED'
             AND submitted_application_version = 1
             AND current_assignment_id IS NULL
             AND current_review_draft_version IS NULL
             AND decision_version_id IS NULL)
            OR
            (status = 'IN_REVIEW'
             AND submitted_application_version = 1
             AND current_assignment_id IS NOT NULL
             AND decision_version_id IS NULL)
            OR
            (status = 'DECIDED'
             AND submitted_application_version = 1
             AND current_assignment_id IS NOT NULL
             AND current_review_draft_version IS NOT NULL
             AND decision_version_id IS NOT NULL)
            OR
            (status = 'WITHDRAWN' AND decision_version_id IS NULL)
        )
    )
);

ALTER TABLE trust.restricted_text_blobs
ADD COLUMN appeal_id uuid NULL;
ALTER TABLE trust.restricted_text_blobs
DROP CONSTRAINT uq_trust_restricted_text_idempotency;
ALTER TABLE trust.restricted_text_blobs
DROP CONSTRAINT ck_trust_restricted_text_codes;
ALTER TABLE trust.restricted_text_blobs
ADD CONSTRAINT fk_trust_restricted_text_appeal FOREIGN KEY (
    organization_id, case_id, appeal_id
) REFERENCES trust.appeals (
    organization_id, source_case_id, appeal_id
),
ADD CONSTRAINT ck_trust_restricted_text_codes CHECK (
    (
        (
            purpose_code = 'TRIAGE_NOTE'
            AND retention_class = 'TRUST_CASE_NOTE'
            AND appeal_id IS NULL
        )
        OR (
            purpose_code IN ('APPEAL_STATEMENT', 'APPEAL_REVIEW_NOTE')
            AND retention_class = 'APPEAL_RESTRICTED_TEXT'
            AND appeal_id IS NOT NULL
        )
    )
    AND encryption_key_id ~ '^[a-z0-9][a-z0-9-]{2,127}$'
    AND idempotency_key_digest_key_id ~ '^[a-z0-9][a-z0-9-]{2,127}$'
    AND encryption_key_id <> idempotency_key_digest_key_id
);
CREATE UNIQUE INDEX uq_trust_restricted_text_triage_idempotency
ON trust.restricted_text_blobs (
    actor_user_id, case_id, purpose_code,
    idempotency_key_digest_key_id, idempotency_key_digest
)
WHERE appeal_id IS NULL;
CREATE UNIQUE INDEX uq_trust_restricted_text_appeal_idempotency
ON trust.restricted_text_blobs (
    actor_user_id, appeal_id, purpose_code,
    idempotency_key_digest_key_id, idempotency_key_digest
)
WHERE appeal_id IS NOT NULL;
ALTER TABLE trust.restricted_text_blobs
ADD CONSTRAINT uq_trust_restricted_text_appeal_reference UNIQUE (
    appeal_id, actor_user_id, sealed_note_reference, envelope_sha256
),
ADD CONSTRAINT uq_trust_restricted_text_appeal_purpose_reference UNIQUE (
    appeal_id, actor_user_id, purpose_code,
    sealed_note_reference, envelope_sha256
);

CREATE TABLE trust.appeal_application_drafts (
    appeal_id uuid NOT NULL,
    draft_version integer NOT NULL,
    grounds text[] NOT NULL,
    requested_outcome varchar(32) NOT NULL,
    sealed_statement_reference varchar(288) NOT NULL,
    sealed_statement_sha256 bytea NOT NULL,
    sealed_statement_purpose_code varchar(64) NOT NULL,
    new_evidence_reference_ids uuid[] NOT NULL,
    edited_by_user_id uuid NOT NULL,
    edited_at timestamptz NOT NULL,
    CONSTRAINT pk_appeal_application_drafts PRIMARY KEY (
        appeal_id, draft_version
    ),
    CONSTRAINT fk_appeal_application_draft_root FOREIGN KEY (appeal_id)
        REFERENCES trust.appeals (appeal_id),
    CONSTRAINT fk_appeal_application_draft_blob FOREIGN KEY (
        appeal_id, edited_by_user_id, sealed_statement_purpose_code,
        sealed_statement_reference, sealed_statement_sha256
    ) REFERENCES trust.restricted_text_blobs (
        appeal_id, actor_user_id, purpose_code,
        sealed_note_reference, envelope_sha256
    ),
    CONSTRAINT ck_appeal_application_draft_version CHECK (draft_version >= 1),
    CONSTRAINT ck_appeal_application_draft_codes CHECK (
        trust.canonical_code_array_v1(grounds, 1, 3)
        AND grounds <@ ARRAY[
            'NEW_MATERIAL_EVIDENCE', 'PROCEDURAL_ERROR', 'RULE_MISAPPLICATION'
        ]::text[]
        AND requested_outcome IN (
            'REMOVE_MEASURE', 'MODIFY_MEASURE', 'VACATE_AND_REMAND'
        )
        AND trust.canonical_uuid_array_v1(new_evidence_reference_ids, 0, 32)
        AND (
            NOT 'NEW_MATERIAL_EVIDENCE' = ANY(grounds)
            OR cardinality(new_evidence_reference_ids) >= 1
        )
        AND sealed_statement_purpose_code = 'APPEAL_STATEMENT'
        AND octet_length(sealed_statement_sha256) = 32
    )
);

CREATE TABLE trust.appeal_application_versions (
    appeal_id uuid NOT NULL,
    application_version integer NOT NULL,
    source_draft_version integer NOT NULL,
    grounds text[] NOT NULL,
    requested_outcome varchar(32) NOT NULL,
    sealed_statement_reference varchar(288) NOT NULL,
    sealed_statement_sha256 bytea NOT NULL,
    sealed_statement_purpose_code varchar(64) NOT NULL,
    new_evidence_reference_ids uuid[] NOT NULL,
    submitted_by_user_id uuid NOT NULL,
    submitted_at timestamptz NOT NULL,
    CONSTRAINT pk_appeal_application_versions PRIMARY KEY (
        appeal_id, application_version
    ),
    CONSTRAINT uq_appeal_application_single_submission UNIQUE (appeal_id),
    CONSTRAINT fk_appeal_application_source_draft FOREIGN KEY (
        appeal_id, source_draft_version
    ) REFERENCES trust.appeal_application_drafts (appeal_id, draft_version),
    CONSTRAINT fk_appeal_application_blob FOREIGN KEY (
        appeal_id, submitted_by_user_id, sealed_statement_purpose_code,
        sealed_statement_reference, sealed_statement_sha256
    ) REFERENCES trust.restricted_text_blobs (
        appeal_id, actor_user_id, purpose_code,
        sealed_note_reference, envelope_sha256
    ),
    CONSTRAINT ck_appeal_application_version CHECK (
        application_version = 1
        AND sealed_statement_purpose_code = 'APPEAL_STATEMENT'
    )
);

CREATE TABLE trust.appeal_review_assignments (
    assignment_id uuid PRIMARY KEY,
    appeal_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL,
    duty_grant_id uuid NOT NULL,
    duty_grant_version bigint NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    conflict_attestation_sha256 bytea NOT NULL,
    conflict_evaluated_at timestamptz NOT NULL,
    conflict_valid_until timestamptz NOT NULL,
    assigned_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT uq_appeal_assignment_root UNIQUE (appeal_id, assignment_id),
    CONSTRAINT fk_appeal_assignment_root FOREIGN KEY (appeal_id)
        REFERENCES trust.appeals (appeal_id),
    CONSTRAINT ck_appeal_assignment_facts CHECK (
        duty_grant_version >= 1
        AND octet_length(authority_marker_sha256) = 32
        AND octet_length(conflict_attestation_sha256) = 32
        AND conflict_evaluated_at <= assigned_at
        AND assigned_at < conflict_valid_until
        AND assigned_at < expires_at
        AND expires_at <= conflict_valid_until
    )
);

CREATE TABLE trust.appeal_assignment_releases (
    assignment_id uuid PRIMARY KEY,
    appeal_id uuid NOT NULL,
    released_by_user_id uuid NOT NULL,
    reason_code varchar(32) NOT NULL,
    released_at timestamptz NOT NULL,
    CONSTRAINT fk_appeal_assignment_release FOREIGN KEY (
        appeal_id, assignment_id
    ) REFERENCES trust.appeal_review_assignments (appeal_id, assignment_id),
    CONSTRAINT ck_appeal_assignment_release_reason CHECK (
        reason_code IN (
            'ASSIGNMENT_EXPIRED', 'CONFLICT_DECLARED', 'WORKLOAD_RELEASE'
        )
    )
);

CREATE TABLE trust.appeal_review_drafts (
    appeal_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    draft_version integer NOT NULL,
    assessments jsonb NOT NULL,
    reason_codes text[] NOT NULL,
    remedy_delta_codes text[] NOT NULL,
    sealed_review_note_reference varchar(288) NOT NULL,
    sealed_review_note_sha256 bytea NOT NULL,
    sealed_review_note_purpose_code varchar(64) NOT NULL,
    edited_by_user_id uuid NOT NULL,
    edited_at timestamptz NOT NULL,
    CONSTRAINT pk_appeal_review_drafts PRIMARY KEY (
        appeal_id, assignment_id, draft_version
    ),
    CONSTRAINT fk_appeal_review_draft_assignment FOREIGN KEY (
        appeal_id, assignment_id
    ) REFERENCES trust.appeal_review_assignments (appeal_id, assignment_id),
    CONSTRAINT fk_appeal_review_draft_blob FOREIGN KEY (
        appeal_id, edited_by_user_id, sealed_review_note_purpose_code,
        sealed_review_note_reference, sealed_review_note_sha256
    ) REFERENCES trust.restricted_text_blobs (
        appeal_id, actor_user_id, purpose_code,
        sealed_note_reference, envelope_sha256
    ),
    CONSTRAINT ck_appeal_review_draft_shape CHECK (
        draft_version >= 1
        AND jsonb_typeof(assessments) = 'array'
        AND jsonb_array_length(assessments) BETWEEN 1 AND 3
        AND trust.canonical_code_array_v1(reason_codes, 1, 32)
        AND reason_codes <@ ARRAY[
            'APPEAL_SCOPE_INVALID', 'NEW_EVIDENCE_REVIEWED',
            'PROCEDURAL_REVIEW_COMPLETE', 'REMAND_REQUIRED',
            'SOURCE_OUTCOME_SUPPORTED', 'SOURCE_OUTCOME_UNSUPPORTED'
        ]::text[]
        AND trust.canonical_code_array_v1(remedy_delta_codes, 1, 32)
        AND remedy_delta_codes <@ ARRAY[
            'NARROW_CORRECTIVE_MEASURE', 'NO_CHANGE',
            'REMOVE_CORRECTIVE_MEASURE', 'REPLACE_CORRECTIVE_MEASURE',
            'RETURN_TO_TRUST_REVIEW'
        ]::text[]
        AND sealed_review_note_purpose_code = 'APPEAL_REVIEW_NOTE'
        AND octet_length(sealed_review_note_sha256) = 32
    )
);

CREATE TABLE trust.appeal_decision_versions (
    decision_version_id uuid PRIMARY KEY,
    appeal_id uuid NOT NULL UNIQUE,
    decision_version integer NOT NULL,
    source_outcome_version_id uuid NOT NULL,
    source_outcome_sha256 bytea NOT NULL,
    source_application_version integer NOT NULL,
    source_assignment_id uuid NOT NULL,
    source_review_draft_version integer NOT NULL,
    decision_code varchar(32) NOT NULL,
    assessments jsonb NOT NULL,
    reason_codes text[] NOT NULL,
    remedy_delta_codes text[] NOT NULL,
    policy_version varchar(128) NOT NULL,
    policy_marker_sha256 bytea NOT NULL,
    decided_by_user_id uuid NOT NULL,
    decided_at timestamptz NOT NULL,
    decision_sha256 bytea NOT NULL,
    CONSTRAINT fk_appeal_decision_root FOREIGN KEY (appeal_id)
        REFERENCES trust.appeals (appeal_id),
    CONSTRAINT uq_appeal_decision_root_version UNIQUE (
        appeal_id, decision_version_id
    ),
    CONSTRAINT fk_appeal_decision_application FOREIGN KEY (
        appeal_id, source_application_version
    ) REFERENCES trust.appeal_application_versions (
        appeal_id, application_version
    ),
    CONSTRAINT fk_appeal_decision_review FOREIGN KEY (
        appeal_id, source_assignment_id, source_review_draft_version
    ) REFERENCES trust.appeal_review_drafts (
        appeal_id, assignment_id, draft_version
    ),
    CONSTRAINT fk_appeal_decision_frozen_source FOREIGN KEY (
        appeal_id, source_outcome_version_id, source_outcome_sha256
    ) REFERENCES trust.appeals (
        appeal_id, source_outcome_version_id, source_content_sha256
    ),
    CONSTRAINT ck_appeal_decision_shape CHECK (
        decision_version = 1
        AND decision_code IN ('AFFIRM', 'DISMISS', 'MODIFY', 'VACATE_AND_REMAND')
        AND jsonb_typeof(assessments) = 'array'
        AND jsonb_array_length(assessments) BETWEEN 1 AND 3
        AND policy_version = 'appeal-decision-v1'
        AND octet_length(source_outcome_sha256) = 32
        AND octet_length(policy_marker_sha256) = 32
        AND octet_length(decision_sha256) = 32
    )
);

CREATE TABLE trust.appeal_receipt_key_policy (
    singleton_key boolean PRIMARY KEY,
    active_idempotency_key_id varchar(128) NOT NULL,
    active_payload_key_id varchar(128) NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    retained_idempotency_key_ids text[] NOT NULL,
    retained_payload_key_ids text[] NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_appeal_receipt_policy_singleton CHECK (singleton_key),
    CONSTRAINT ck_appeal_receipt_policy_exact CHECK (
        active_idempotency_key_id ~ '^[a-z0-9][a-z0-9-]{2,127}$'
        AND active_payload_key_id ~ '^[a-z0-9][a-z0-9-]{2,127}$'
        AND active_idempotency_key_id <> active_payload_key_id
        AND canonicalization_version = 'appeal-command-json-v1'
        AND trust.active_first_key_array_v1(
            retained_idempotency_key_ids, active_idempotency_key_id, 4
        )
        AND trust.active_first_key_array_v1(
            retained_payload_key_ids, active_payload_key_id, 4
        )
        AND NOT retained_idempotency_key_ids && retained_payload_key_ids
    )
);

CREATE TABLE trust.appeal_command_receipts (
    receipt_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL,
    organization_id uuid NULL,
    command_name varchar(64) NOT NULL,
    idempotency_key_digest_key_id varchar(128) NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_hash bytea NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    http_method varchar(8) NOT NULL,
    canonical_path varchar(512) NOT NULL,
    if_match_version bigint NULL,
    target_appeal_id uuid NOT NULL,
    status varchar(16) NOT NULL,
    response_http_status integer NULL,
    safe_response jsonb NULL,
    target_version bigint NULL,
    result_status varchar(16) NULL,
    event_types text[] NULL,
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_appeal_receipt_identity UNIQUE (
        principal_id, command_name,
        idempotency_key_digest_key_id, idempotency_key_digest
    ),
    CONSTRAINT fk_appeal_receipt_target FOREIGN KEY (target_appeal_id)
        REFERENCES trust.appeals (appeal_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_appeal_receipt_transport CHECK (
        command_name IN (
            'OPEN_APPEAL', 'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL',
            'CLAIM_APPEAL', 'RELEASE_APPEAL_ASSIGNMENT',
            'SAVE_APPEAL_REVIEW_DRAFT', 'DECIDE_APPEAL'
        )
        AND canonicalization_version = 'appeal-command-json-v1'
        AND octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
        AND idempotency_key_digest_key_id <> payload_hash_key_id
        AND http_method IN ('POST', 'PUT')
        AND canonical_path IN (
            '/v1/app/appeals',
            '/v1/app/appeals/{appeal_id}/draft',
            '/v1/app/appeals/{appeal_id}/submit',
            '/v1/app/appeal-review/queue/{appeal_id}/claim',
            '/v1/app/appeal-review/appeals/{appeal_id}/assignment/release',
            '/v1/app/appeal-review/appeals/{appeal_id}/review-draft',
            '/v1/app/appeal-review/appeals/{appeal_id}/decide'
        )
        AND (
            (command_name = 'OPEN_APPEAL' AND if_match_version IS NULL)
            OR (command_name <> 'OPEN_APPEAL' AND if_match_version >= 1)
        )
    ),
    CONSTRAINT ck_appeal_receipt_shape CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
        AND retain_until > created_at
        AND (
            (status = 'IN_PROGRESS'
             AND response_http_status IS NULL
             AND safe_response IS NULL
             AND target_version IS NULL
             AND result_status IS NULL
             AND event_types IS NULL
             AND completed_at IS NULL)
            OR
            (status = 'COMPLETED'
             AND response_http_status IN (200, 201)
             AND trust.jsonb_has_exact_keys(safe_response, ARRAY[
                'aggregate_version', 'appeal_id', 'appeal_status',
                'application_draft_version', 'application_version',
                'completed_at', 'decision_version_id', 'event_types',
                'review_draft_version'
             ]::text[])
             AND NOT safe_response ?| ARRAY[
                'applicant_user_id', 'reviewer_user_id', 'organization_id',
                'assignment_id', 'duty_grant_id', 'authority_marker_sha256',
                'sealed_statement_reference', 'sealed_review_note_reference',
                'sealed_statement_sha256', 'sealed_review_note_sha256'
             ]::text[]
             AND target_version >= 1
             AND result_status IN (
                'DRAFT', 'SUBMITTED', 'IN_REVIEW', 'DECIDED', 'WITHDRAWN'
             )
             AND cardinality(event_types) = 1
             AND event_types <@ ARRAY[
                'AppealOpened', 'AppealApplicationDraftSaved',
                'AppealSubmitted', 'AppealReviewClaimed',
                'AppealReviewAssignmentReleased',
                'AppealReviewDraftSaved', 'AppealDecisionPublished'
             ]::text[]
             AND completed_at >= created_at)
        )
    )
);

ALTER TABLE trust.appeals
ADD CONSTRAINT fk_appeal_current_application_draft FOREIGN KEY (
    appeal_id, current_application_draft_version
) REFERENCES trust.appeal_application_drafts (appeal_id, draft_version)
DEFERRABLE INITIALLY DEFERRED,
ADD CONSTRAINT fk_appeal_submitted_application FOREIGN KEY (
    appeal_id, submitted_application_version
) REFERENCES trust.appeal_application_versions (appeal_id, application_version)
DEFERRABLE INITIALLY DEFERRED,
ADD CONSTRAINT fk_appeal_current_assignment FOREIGN KEY (
    appeal_id, current_assignment_id
) REFERENCES trust.appeal_review_assignments (appeal_id, assignment_id)
DEFERRABLE INITIALLY DEFERRED,
ADD CONSTRAINT fk_appeal_current_review_draft FOREIGN KEY (
    appeal_id, current_assignment_id, current_review_draft_version
) REFERENCES trust.appeal_review_drafts (
    appeal_id, assignment_id, draft_version
)
DEFERRABLE INITIALLY DEFERRED,
ADD CONSTRAINT fk_appeal_decision FOREIGN KEY (
    appeal_id, decision_version_id
) REFERENCES trust.appeal_decision_versions (
    appeal_id, decision_version_id
)
DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX ix_appeal_applicant
ON trust.appeals (
    organization_id, applicant_user_id, source_outcome_version_id, appeal_id
);
CREATE INDEX ix_appeal_queue
ON trust.appeals (opened_at, appeal_id)
WHERE status = 'SUBMITTED' AND current_assignment_id IS NULL;
CREATE INDEX ix_appeal_assignment_reviewer
ON trust.appeal_review_assignments (
    reviewer_user_id, expires_at, appeal_id, assignment_id
);
CREATE INDEX ix_appeal_receipt_retention
ON trust.appeal_command_receipts (retain_until, receipt_id);

INSERT INTO trust.appeal_receipt_key_policy (
    singleton_key, active_idempotency_key_id, active_payload_key_id,
    canonicalization_version, retained_idempotency_key_ids,
    retained_payload_key_ids, updated_at
) VALUES (
    true, 'trust-idempotency-2026-01', 'trust-payload-2026-01',
    'appeal-command-json-v1',
    ARRAY['trust-idempotency-2026-01']::text[],
    ARRAY['trust-payload-2026-01']::text[],
    transaction_timestamp()
);

CREATE FUNCTION trust.appeal_entity_tag_v1(
    exact_appeal_id uuid,
    exact_aggregate_version bigint,
    exact_status text,
    exact_updated_at timestamptz
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
SELECT format(
    '"appeal-%s-%s"',
    exact_aggregate_version,
    left(encode(sha256(convert_to(concat_ws(
        E'\x1f', 'desire:trust:appeal-entity-tag:v1',
        exact_appeal_id::text, exact_aggregate_version::text,
        exact_status,
        to_char(
            exact_updated_at AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )
    ), 'UTF8')), 'hex'), 24)
)
$function$;

CREATE FUNCTION trust.appeal_definer_scope_allows_v1(
    exact_organization_id uuid,
    exact_appeal_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog
AS $function$
SELECT
    current_user = 'trust_schema_owner'
    AND session_user IN ('trust_self', 'trust_appeal')
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '') IN (
        'APPEAL_COMMAND', 'APPEAL_RECEIPT_READ',
        'APPEAL_OWN_READ', 'APPEAL_QUEUE_READ', 'APPEAL_ASSIGNED_READ',
        'APPEAL_SEALED_TEXT'
    )
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND (
        (
            session_user = 'trust_appeal'
            AND NULLIF(
                current_setting('app.appeal_scope_kind', true), ''
            ) IN (
                'APPEAL_COMMAND', 'APPEAL_RECEIPT_READ',
                'APPEAL_QUEUE_READ', 'APPEAL_ASSIGNED_READ',
                'APPEAL_SEALED_TEXT'
            )
        )
        OR exact_organization_id IS NULL
        OR exact_organization_id = NULLIF(
            current_setting('app.organization_id', true), ''
        )::uuid
    )
    AND (
        exact_appeal_id IS NULL
        OR NULLIF(current_setting('app.appeal_id', true), '') IS NULL
        OR exact_appeal_id = NULLIF(
            current_setting('app.appeal_id', true), ''
        )::uuid
    )
$function$;

CREATE FUNCTION trust.guard_appeal_update_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.appeal_id <> OLD.appeal_id
       OR NEW.source_outcome_version_id <> OLD.source_outcome_version_id
       OR NEW.source_case_id <> OLD.source_case_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.demand_id <> OLD.demand_id
       OR NEW.demand_version_id <> OLD.demand_version_id
       OR NEW.applicant_user_id <> OLD.applicant_user_id
       OR NEW.applicant_membership_id <> OLD.applicant_membership_id
       OR NEW.applicant_role_grant_id <> OLD.applicant_role_grant_id
       OR NEW.applicant_role_grant_version <> OLD.applicant_role_grant_version
       OR NEW.applicant_authority_marker_sha256
            <> OLD.applicant_authority_marker_sha256
       OR NEW.applicant_party_marker_sha256
            <> OLD.applicant_party_marker_sha256
       OR NEW.source_outcome_code <> OLD.source_outcome_code
       OR NEW.source_reason_codes <> OLD.source_reason_codes
       OR NEW.source_action_codes <> OLD.source_action_codes
       OR NEW.source_evidence_packet_version_id
            <> OLD.source_evidence_packet_version_id
       OR NEW.source_evidence_packet_sha256
            <> OLD.source_evidence_packet_sha256
       OR NEW.source_policy_version <> OLD.source_policy_version
       OR NEW.source_decided_at <> OLD.source_decided_at
       OR NEW.source_appeal_deadline <> OLD.source_appeal_deadline
       OR NEW.source_content_sha256 <> OLD.source_content_sha256
       OR NEW.source_deciding_officer_user_id
            <> OLD.source_deciding_officer_user_id
       OR NEW.source_appeal_eligible <> OLD.source_appeal_eligible
       OR NEW.source_appeal_eligibility_code
            <> OLD.source_appeal_eligibility_code
       OR NEW.opened_at <> OLD.opened_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.updated_at < OLD.updated_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_appeal_guard',
            MESSAGE = 'APPEAL_STATE_CONFLICT';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.appeal_source_projection_v1(root trust.appeals)
RETURNS jsonb
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog, trust
AS $function$
SELECT jsonb_build_object(
    'action_codes', to_jsonb(root.source_action_codes),
    'appeal_deadline', root.source_appeal_deadline,
    'appeal_eligibility_code', root.source_appeal_eligibility_code,
    'appeal_eligible', root.source_appeal_eligible,
    'case_id', root.source_case_id,
    'content_sha256', encode(root.source_content_sha256, 'hex'),
    'decided_at', root.source_decided_at,
    'demand_id', root.demand_id,
    'demand_version_id', root.demand_version_id,
    'evidence_packet_sha256',
        encode(root.source_evidence_packet_sha256, 'hex'),
    'evidence_packet_version_id', root.source_evidence_packet_version_id,
    'outcome_code', root.source_outcome_code,
    'outcome_version_id', root.source_outcome_version_id,
    'policy_version', root.source_policy_version,
    'reason_codes', to_jsonb(root.source_reason_codes)
)
$function$;

CREATE FUNCTION trust.appeal_own_projection_v1(root trust.appeals)
RETURNS jsonb
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog, trust
AS $function$
SELECT jsonb_build_object(
    'aggregate_version', root.aggregate_version,
    'appeal_id', root.appeal_id,
    'application', CASE WHEN application.appeal_id IS NULL
        THEN 'null'::jsonb ELSE jsonb_build_object(
            'grounds', to_jsonb(application.grounds),
            'new_evidence_reference_ids',
                to_jsonb(application.new_evidence_reference_ids),
            'requested_outcome', application.requested_outcome,
            'statement_recorded', true,
            'submitted_at', application.submitted_at
        ) END,
    'application_draft', CASE WHEN draft.appeal_id IS NULL
        THEN 'null'::jsonb ELSE jsonb_build_object(
            'edited_at', draft.edited_at,
            'grounds', to_jsonb(draft.grounds),
            'new_evidence_reference_ids',
                to_jsonb(draft.new_evidence_reference_ids),
            'requested_outcome', draft.requested_outcome,
            'statement_recorded', true,
            'version', draft.draft_version
        ) END,
    'decision', CASE WHEN decision.appeal_id IS NULL
        THEN 'null'::jsonb ELSE jsonb_build_object(
            'assessments', decision.assessments,
            'decided_at', decision.decided_at,
            'decision_code', decision.decision_code,
            'decision_sha256', encode(decision.decision_sha256, 'hex'),
            'decision_version_id', decision.decision_version_id,
            'policy_version', decision.policy_version,
            'reason_codes', to_jsonb(decision.reason_codes),
            'remedy_delta_codes', to_jsonb(decision.remedy_delta_codes)
        ) END,
    'entity_tag', trust.appeal_entity_tag_v1(
        root.appeal_id, root.aggregate_version, root.status, root.updated_at
    ),
    'source', trust.appeal_source_projection_v1(root),
    'source_case_id', root.source_case_id,
    'source_outcome_version_id', root.source_outcome_version_id,
    'status', root.status
)
FROM (SELECT 1) AS singleton
LEFT JOIN trust.appeal_application_drafts AS draft
  ON draft.appeal_id = root.appeal_id
 AND draft.draft_version = root.current_application_draft_version
LEFT JOIN trust.appeal_application_versions AS application
  ON application.appeal_id = root.appeal_id
 AND application.application_version = root.submitted_application_version
LEFT JOIN trust.appeal_decision_versions AS decision
  ON decision.appeal_id = root.appeal_id
 AND decision.decision_version_id = root.decision_version_id
$function$;

CREATE FUNCTION trust_api.find_own_appeal_by_source_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_source_outcome_version_id uuid
)
RETURNS TABLE (projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_source_outcome_version_id IS NULL THEN RETURN;
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_OWN_READ', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.appeal_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_applicant_authority_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        'READ_OWN_APPEAL'
    ) AS row;
    RETURN QUERY
    SELECT trust.appeal_own_projection_v1(root)
    FROM trust.appeals AS root
    WHERE root.organization_id = exact_organization_id
      AND root.applicant_user_id = exact_actor_user_id
      AND root.source_outcome_version_id = exact_source_outcome_version_id;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN RETURN;
END
$function$;

CREATE FUNCTION trust_api.read_own_appeal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_appeal_id uuid
)
RETURNS TABLE (projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_appeal_id IS NULL THEN RETURN;
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_OWN_READ', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_applicant_authority_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        'READ_OWN_APPEAL'
    ) AS row;
    RETURN QUERY
    SELECT trust.appeal_own_projection_v1(root)
    FROM trust.appeals AS root
    WHERE root.appeal_id = exact_appeal_id
      AND root.organization_id = exact_organization_id
      AND root.applicant_user_id = exact_actor_user_id;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN RETURN;
END
$function$;

CREATE FUNCTION trust_api.list_appeal_queue_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_limit integer
)
RETURNS TABLE (projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_limit IS NULL
       OR exact_limit NOT BETWEEN 1 AND 100 THEN RETURN;
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_QUEUE_READ', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id, 'LIST_APPEAL_QUEUE'
    ) AS row;
    RETURN QUERY
    WITH queue_rows AS MATERIALIZED (
        SELECT
            root.appeal_id, root.aggregate_version, application.submitted_at,
            jsonb_build_object(
                'appeal_id', root.appeal_id,
                'entity_tag', trust.appeal_entity_tag_v1(
                    root.appeal_id, root.aggregate_version,
                    root.status, root.updated_at
                ),
                'grounds', to_jsonb(application.grounds),
                'requested_outcome', application.requested_outcome,
                'source_case_id', root.source_case_id,
                'source_outcome_version_id', root.source_outcome_version_id,
                'submitted_at', application.submitted_at
            ) AS item
        FROM trust.appeals AS root
        JOIN trust.appeal_application_versions AS application
          ON application.appeal_id = root.appeal_id
         AND application.application_version = root.submitted_application_version
        WHERE root.status = 'SUBMITTED'
          AND root.current_assignment_id IS NULL
        ORDER BY application.submitted_at, root.appeal_id
        LIMIT exact_limit
    ), document AS (
        SELECT COALESCE(
            jsonb_agg(item ORDER BY submitted_at, appeal_id), '[]'::jsonb
        ) AS items,
        COALESCE(max(aggregate_version), 1)::bigint AS collection_version
        FROM queue_rows
    )
    SELECT jsonb_build_object(
        'entity_tag', format(
            '"appeal-%s-%s"', document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:appeal-queue:v1' || E'\x1f'
                    || document.items::text,
                'UTF8'
            )), 'hex'), 24)
        ),
        'items', document.items
    )
    FROM document;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN;
END
$function$;

CREATE FUNCTION trust_api.read_assigned_appeal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_appeal_id uuid
)
RETURNS TABLE (projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_appeal_id IS NULL THEN RETURN;
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_ASSIGNED_READ', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id, 'READ_ASSIGNED_APPEAL'
    ) AS row;
    RETURN QUERY
    SELECT jsonb_build_object(
        'appeal', trust.appeal_own_projection_v1(root),
        'application', jsonb_build_object(
            'grounds', to_jsonb(application.grounds),
            'new_evidence_reference_ids',
                to_jsonb(application.new_evidence_reference_ids),
            'requested_outcome', application.requested_outcome,
            'statement_recorded', true,
            'submitted_at', application.submitted_at
        ),
        'assignment_expires_at', assignment.expires_at,
        'entity_tag', trust.appeal_entity_tag_v1(
            root.appeal_id, root.aggregate_version,
            root.status, root.updated_at
        ),
        'review_draft', CASE WHEN review.appeal_id IS NULL
            THEN 'null'::jsonb ELSE jsonb_build_object(
                'assessments', review.assessments,
                'edited_at', review.edited_at,
                'reason_codes', to_jsonb(review.reason_codes),
                'remedy_delta_codes', to_jsonb(review.remedy_delta_codes),
                'review_note_recorded', true,
                'version', review.draft_version
            ) END,
        'source', trust.appeal_source_projection_v1(root)
    )
    FROM trust.appeals AS root
    JOIN trust.appeal_review_assignments AS assignment
      ON assignment.appeal_id = root.appeal_id
     AND assignment.assignment_id = root.current_assignment_id
    JOIN trust.appeal_application_versions AS application
      ON application.appeal_id = root.appeal_id
     AND application.application_version = root.submitted_application_version
    LEFT JOIN trust.appeal_review_drafts AS review
      ON review.appeal_id = root.appeal_id
     AND review.assignment_id = assignment.assignment_id
     AND review.draft_version = root.current_review_draft_version
    WHERE root.appeal_id = exact_appeal_id
      AND root.status = 'IN_REVIEW'
      AND assignment.reviewer_user_id = exact_actor_user_id
      AND assignment.duty_grant_id = authority.duty_grant_id
      AND assignment.duty_grant_version = authority.duty_grant_version
      AND transaction_timestamp() < assignment.expires_at
      AND NOT EXISTS (
          SELECT 1 FROM trust.appeal_assignment_releases AS release
          WHERE release.assignment_id = assignment.assignment_id
      );
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN;
END
$function$;

CREATE FUNCTION trust_api.read_completed_appeal_receipt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_command_name text,
    exact_target_appeal_id uuid,
    exact_if_match_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    policy trust.appeal_receipt_key_policy%ROWTYPE;
    existing trust.appeal_command_receipts%ROWTYPE;
    matching_count integer;
    expected_method text;
    expected_path text;
    expected_event_type text;
    expected_status text;
    expected_http_status integer;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    expected_method := CASE exact_command_name
        WHEN 'OPEN_APPEAL' THEN 'POST'
        WHEN 'SAVE_APPEAL_DRAFT' THEN 'PUT'
        WHEN 'SUBMIT_APPEAL' THEN 'POST'
        WHEN 'CLAIM_APPEAL' THEN 'POST'
        WHEN 'RELEASE_APPEAL_ASSIGNMENT' THEN 'POST'
        WHEN 'SAVE_APPEAL_REVIEW_DRAFT' THEN 'PUT'
        WHEN 'DECIDE_APPEAL' THEN 'POST'
        ELSE NULL
    END;
    expected_path := CASE exact_command_name
        WHEN 'OPEN_APPEAL' THEN '/v1/app/appeals'
        WHEN 'SAVE_APPEAL_DRAFT' THEN '/v1/app/appeals/{appeal_id}/draft'
        WHEN 'SUBMIT_APPEAL' THEN '/v1/app/appeals/{appeal_id}/submit'
        WHEN 'CLAIM_APPEAL' THEN
            '/v1/app/appeal-review/queue/{appeal_id}/claim'
        WHEN 'RELEASE_APPEAL_ASSIGNMENT' THEN
            '/v1/app/appeal-review/appeals/{appeal_id}/assignment/release'
        WHEN 'SAVE_APPEAL_REVIEW_DRAFT' THEN
            '/v1/app/appeal-review/appeals/{appeal_id}/review-draft'
        WHEN 'DECIDE_APPEAL' THEN
            '/v1/app/appeal-review/appeals/{appeal_id}/decide'
        ELSE NULL
    END;
    expected_event_type := CASE exact_command_name
        WHEN 'OPEN_APPEAL' THEN 'AppealOpened'
        WHEN 'SAVE_APPEAL_DRAFT' THEN 'AppealApplicationDraftSaved'
        WHEN 'SUBMIT_APPEAL' THEN 'AppealSubmitted'
        WHEN 'CLAIM_APPEAL' THEN 'AppealReviewClaimed'
        WHEN 'RELEASE_APPEAL_ASSIGNMENT' THEN
            'AppealReviewAssignmentReleased'
        WHEN 'SAVE_APPEAL_REVIEW_DRAFT' THEN 'AppealReviewDraftSaved'
        WHEN 'DECIDE_APPEAL' THEN 'AppealDecisionPublished'
        ELSE NULL
    END;
    expected_status := CASE exact_command_name
        WHEN 'OPEN_APPEAL' THEN 'DRAFT'
        WHEN 'SAVE_APPEAL_DRAFT' THEN 'DRAFT'
        WHEN 'SUBMIT_APPEAL' THEN 'SUBMITTED'
        WHEN 'CLAIM_APPEAL' THEN 'IN_REVIEW'
        WHEN 'RELEASE_APPEAL_ASSIGNMENT' THEN 'SUBMITTED'
        WHEN 'SAVE_APPEAL_REVIEW_DRAFT' THEN 'IN_REVIEW'
        WHEN 'DECIDE_APPEAL' THEN 'DECIDED'
        ELSE NULL
    END;
    expected_http_status := CASE
        WHEN exact_command_name IN ('OPEN_APPEAL', 'CLAIM_APPEAL') THEN 201
        ELSE 200
    END;
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR expected_method IS NULL OR expected_path IS NULL
       OR (
            exact_command_name = 'OPEN_APPEAL'
            AND exact_target_appeal_id IS NOT NULL
       )
       OR (
            exact_command_name <> 'OPEN_APPEAL'
            AND (
                exact_target_appeal_id IS NULL
                OR exact_target_appeal_id
                    = '00000000-0000-0000-0000-000000000000'::uuid
            )
       )
       OR cardinality(exact_idempotency_key_digest_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_RECEIPT_READ', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config(
        'app.organization_id', COALESCE(exact_organization_id::text, ''), true
    );
    PERFORM set_config(
        'app.appeal_id', CASE WHEN exact_command_name = 'OPEN_APPEAL'
            THEN '' ELSE exact_target_appeal_id::text END, true
    );
    IF exact_command_name IN (
        'OPEN_APPEAL', 'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
    ) THEN
        IF exact_organization_id IS NULL OR session_user <> 'trust_self' THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
        END IF;
        SELECT row.* INTO STRICT authority
        FROM trust.resolve_appeal_applicant_authority_v1(
            exact_actor_user_id, exact_session_id, exact_organization_id,
            exact_command_name
        ) AS row;
    ELSE
        IF exact_organization_id IS NOT NULL
           OR session_user <> 'trust_appeal' THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
        END IF;
        SELECT row.* INTO STRICT authority
        FROM trust.resolve_appeal_reviewer_authority_v1(
            exact_actor_user_id, exact_session_id, exact_command_name
        ) AS row;
    END IF;
    SELECT row.* INTO STRICT policy
    FROM trust.appeal_receipt_key_policy AS row
    WHERE row.singleton_key
    FOR SHARE;
    IF exact_idempotency_key_digest_key_ids
            IS DISTINCT FROM policy.retained_idempotency_key_ids
       OR exact_payload_hash_key_ids
            IS DISTINCT FROM policy.retained_payload_key_ids
       OR EXISTS (
            SELECT 1 FROM unnest(exact_idempotency_key_digests) AS hash(value)
            WHERE hash.value IS NULL OR octet_length(hash.value) <> 32
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_payload_hashes) AS hash(value)
            WHERE hash.value IS NULL OR octet_length(hash.value) <> 32
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'APPEAL_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;
    SELECT count(*) INTO matching_count
    FROM trust.appeal_command_receipts AS receipt
    WHERE receipt.principal_id = exact_actor_user_id
      AND receipt.command_name = exact_command_name
      AND EXISTS (
          SELECT 1 FROM generate_subscripts(
              exact_idempotency_key_digests, 1
          ) AS slot(index)
          WHERE receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_ids[slot.index]
            AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digests[slot.index]
      );
    IF matching_count = 0 THEN RETURN;
    ELSIF matching_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003', MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    SELECT receipt.* INTO STRICT existing
    FROM trust.appeal_command_receipts AS receipt
    WHERE receipt.principal_id = exact_actor_user_id
      AND receipt.command_name = exact_command_name
      AND EXISTS (
          SELECT 1 FROM generate_subscripts(
              exact_idempotency_key_digests, 1
          ) AS slot(index)
          WHERE receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_ids[slot.index]
            AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digests[slot.index]
      )
    FOR SHARE;
    IF NOT EXISTS (
        SELECT 1 FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
        WHERE exact_payload_hash_key_ids[slot.index]
                = existing.payload_hash_key_id
          AND exact_payload_hashes[slot.index] = existing.payload_hash
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'uq_appeal_receipt_identity',
            MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
    END IF;
    IF existing.organization_id IS DISTINCT FROM exact_organization_id
       OR existing.http_method <> expected_method
       OR existing.canonical_path <> expected_path
       OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
       OR (
            exact_command_name <> 'OPEN_APPEAL'
            AND existing.target_appeal_id <> exact_target_appeal_id
       )
       OR existing.retain_until <= evaluated_time
       OR existing.status <> 'COMPLETED'
       OR NOT trust.jsonb_has_exact_keys(existing.safe_response, ARRAY[
            'aggregate_version', 'appeal_id', 'appeal_status',
            'application_draft_version', 'application_version',
            'completed_at', 'decision_version_id', 'event_types',
            'review_draft_version'
       ]::text[])
       OR existing.response_http_status <> expected_http_status
       OR existing.target_version IS NULL OR existing.target_version < 1
       OR existing.result_status <> expected_status
       OR existing.event_types <> ARRAY[expected_event_type]::text[]
       OR existing.completed_at IS NULL
       OR existing.safe_response->>'appeal_id'
            <> existing.target_appeal_id::text
       OR (existing.safe_response->>'aggregate_version')::bigint
            <> existing.target_version
       OR existing.safe_response->>'appeal_status' <> expected_status
       OR existing.safe_response->'event_types'
            <> jsonb_build_array(expected_event_type)
       OR existing.safe_response->>'completed_at'
            <> trust.utc_timestamp_text_v1(existing.completed_at)
       OR (
            exact_command_name = 'OPEN_APPEAL'
            AND (
                existing.safe_response->'application_draft_version'
                    <> 'null'::jsonb
                OR existing.safe_response->'application_version'
                    <> 'null'::jsonb
                OR existing.safe_response->'review_draft_version'
                    <> 'null'::jsonb
                OR existing.safe_response->'decision_version_id'
                    <> 'null'::jsonb
            )
       )
       OR (
            exact_command_name = 'SAVE_APPEAL_DRAFT'
            AND (
                jsonb_typeof(existing.safe_response->'application_draft_version')
                    <> 'number'
                OR existing.safe_response->'application_version'
                    <> 'null'::jsonb
                OR existing.safe_response->'review_draft_version'
                    <> 'null'::jsonb
                OR existing.safe_response->'decision_version_id'
                    <> 'null'::jsonb
            )
       )
       OR (
            exact_command_name IN (
                'SUBMIT_APPEAL', 'CLAIM_APPEAL',
                'RELEASE_APPEAL_ASSIGNMENT'
            )
            AND (
                jsonb_typeof(existing.safe_response->'application_draft_version')
                    <> 'number'
                OR (existing.safe_response->>'application_version')::integer
                    IS DISTINCT FROM 1
                OR existing.safe_response->'review_draft_version'
                    <> 'null'::jsonb
                OR existing.safe_response->'decision_version_id'
                    <> 'null'::jsonb
            )
       )
       OR (
            exact_command_name = 'SAVE_APPEAL_REVIEW_DRAFT'
            AND (
                jsonb_typeof(existing.safe_response->'application_draft_version')
                    <> 'number'
                OR (existing.safe_response->>'application_version')::integer
                    IS DISTINCT FROM 1
                OR jsonb_typeof(existing.safe_response->'review_draft_version')
                    <> 'number'
                OR existing.safe_response->'decision_version_id'
                    <> 'null'::jsonb
            )
       )
       OR (
            exact_command_name = 'DECIDE_APPEAL'
            AND (
                jsonb_typeof(existing.safe_response->'application_draft_version')
                    <> 'number'
                OR (existing.safe_response->>'application_version')::integer
                    IS DISTINCT FROM 1
                OR jsonb_typeof(existing.safe_response->'review_draft_version')
                    <> 'number'
                OR jsonb_typeof(existing.safe_response->'decision_version_id')
                    <> 'string'
            )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003', MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    RETURN QUERY SELECT existing.safe_response, true;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

CREATE FUNCTION trust_api.decide_appeal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_decision_version_id uuid,
    exact_appeal_id uuid,
    exact_expected_appeal_version bigint,
    exact_expected_review_draft_version integer,
    exact_decision_code text,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    receipt record;
    root trust.appeals%ROWTYPE;
    assignment trust.appeal_review_assignments%ROWTYPE;
    application trust.appeal_application_versions%ROWTYPE;
    review trust.appeal_review_drafts%ROWTYPE;
    policy_marker bytea;
    decision_digest bytea;
    any_accepted boolean;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_correlation_id IS NULL
       OR exact_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_causation_id IS NULL
       OR exact_causation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_trace_id IS NULL
       OR exact_trace_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_receipt_id IS NULL
       OR exact_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_audit_event_id IS NULL
       OR exact_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_outbox_event_id IS NULL
       OR exact_outbox_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_decision_version_id IS NULL
       OR exact_decision_version_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_expected_appeal_version < 1
       OR exact_expected_review_draft_version < 1
       OR exact_decision_code NOT IN (
            'AFFIRM', 'DISMISS', 'MODIFY', 'VACATE_AND_REMAND'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id, 'DECIDE_APPEAL'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, NULL,
        'DECIDE_APPEAL', exact_appeal_id,
        exact_expected_appeal_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    PERFORM set_config('app.organization_id', root.organization_id::text, true);
    PERFORM set_config('app.case_id', root.source_case_id::text, true);
    PERFORM set_config('app.demand_id', root.demand_id::text, true);
    IF root.aggregate_version <> exact_expected_appeal_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'PRECONDITION_FAILED';
    ELSIF root.current_review_draft_version
            IS DISTINCT FROM exact_expected_review_draft_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_DECISION_INVALID';
    END IF;
    assignment := trust.require_appeal_assignment_v1(
        root.appeal_id, exact_actor_user_id,
        authority.duty_grant_id, authority.duty_grant_version, false
    );
    SELECT row.* INTO STRICT application
    FROM trust.appeal_application_versions AS row
    WHERE row.appeal_id = root.appeal_id
      AND row.application_version = root.submitted_application_version
    FOR SHARE;
    SELECT row.* INTO STRICT review
    FROM trust.appeal_review_drafts AS row
    WHERE row.appeal_id = root.appeal_id
      AND row.assignment_id = assignment.assignment_id
      AND row.draft_version = exact_expected_review_draft_version
    FOR SHARE;
    IF NOT trust.valid_appeal_assessments_v1(
        review.assessments, application.grounds,
        application.new_evidence_reference_ids
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_DECISION_INVALID';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM jsonb_array_elements(review.assessments) AS item(value)
        WHERE item.value->>'assessment_code' IN (
            'ACCEPTED', 'PARTIALLY_ACCEPTED'
        )
    ) INTO any_accepted;
    IF (
        exact_decision_code IN ('MODIFY', 'VACATE_AND_REMAND')
        AND (
            NOT any_accepted
            OR review.remedy_delta_codes = ARRAY['NO_CHANGE']::text[]
        )
       ) OR (
        exact_decision_code IN ('AFFIRM', 'DISMISS')
        AND (
            any_accepted
            OR review.remedy_delta_codes <> ARRAY['NO_CHANGE']::text[]
        )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_DECISION_INVALID';
    END IF;
    policy_marker := sha256(convert_to(concat_ws(
        E'\x1f', 'desire:trust:appeal-decision-policy:v1',
        root.appeal_id::text, root.aggregate_version::text,
        root.source_outcome_version_id::text,
        review.draft_version::text, exact_decision_code,
        authority.duty_grant_id::text,
        authority.duty_grant_version::text,
        encode(authority.authority_marker_sha256, 'hex'),
        trust.utc_timestamp_text_v1(evaluated_time)
    ), 'UTF8'));
    decision_digest := sha256(convert_to(concat_ws(
        E'\x1f', 'desire:trust:appeal-decision:v1',
        root.appeal_id::text, root.source_outcome_version_id::text,
        encode(root.source_content_sha256, 'hex'),
        application.application_version::text,
        review.draft_version::text, exact_decision_code,
        review.assessments::text,
        array_to_string(review.reason_codes, E'\x1e'),
        array_to_string(review.remedy_delta_codes, E'\x1e'),
        'appeal-decision-v1'
    ), 'UTF8'));
    INSERT INTO trust.appeal_decision_versions (
        decision_version_id, appeal_id, decision_version,
        source_outcome_version_id, source_outcome_sha256,
        source_application_version, source_assignment_id,
        source_review_draft_version, decision_code, assessments,
        reason_codes, remedy_delta_codes, policy_version,
        policy_marker_sha256, decided_by_user_id, decided_at,
        decision_sha256
    ) VALUES (
        exact_decision_version_id, root.appeal_id, 1,
        root.source_outcome_version_id, root.source_content_sha256,
        application.application_version, assignment.assignment_id,
        review.draft_version, exact_decision_code, review.assessments,
        review.reason_codes, review.remedy_delta_codes,
        'appeal-decision-v1', policy_marker,
        exact_actor_user_id, evaluated_time, decision_digest
    );
    UPDATE trust.appeals AS row
    SET status = 'DECIDED',
        aggregate_version = row.aggregate_version + 1,
        decision_version_id = exact_decision_version_id,
        updated_at = evaluated_time
    WHERE row.appeal_id = root.appeal_id;
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, root.organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.appeal_id, root.status, root.aggregate_version,
        'AppealDecisionPublished'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '42501', MESSAGE = 'APPEAL_ASSIGNMENT_REQUIRED';
END
$function$;

CREATE FUNCTION trust_api.save_appeal_review_draft_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_appeal_id uuid,
    exact_expected_appeal_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_sealed_review_note_reference text,
    exact_sealed_review_note_sha256 bytea,
    exact_assessments jsonb,
    exact_reason_codes text[],
    exact_remedy_delta_codes text[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    receipt record;
    root trust.appeals%ROWTYPE;
    assignment trust.appeal_review_assignments%ROWTYPE;
    application trust.appeal_application_versions%ROWTYPE;
    draft_version integer;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_correlation_id IS NULL
       OR exact_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_causation_id IS NULL
       OR exact_causation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_trace_id IS NULL
       OR exact_trace_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_receipt_id IS NULL
       OR exact_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_audit_event_id IS NULL
       OR exact_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_outbox_event_id IS NULL
       OR exact_outbox_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_expected_appeal_version < 1
       OR NOT trust.canonical_code_array_v1(exact_reason_codes, 1, 32)
       OR NOT exact_reason_codes <@ ARRAY[
            'APPEAL_SCOPE_INVALID', 'NEW_EVIDENCE_REVIEWED',
            'PROCEDURAL_REVIEW_COMPLETE', 'REMAND_REQUIRED',
            'SOURCE_OUTCOME_SUPPORTED', 'SOURCE_OUTCOME_UNSUPPORTED'
       ]::text[]
       OR NOT trust.canonical_code_array_v1(
            exact_remedy_delta_codes, 1, 32
       )
       OR NOT exact_remedy_delta_codes <@ ARRAY[
            'NARROW_CORRECTIVE_MEASURE', 'NO_CHANGE',
            'REMOVE_CORRECTIVE_MEASURE', 'REPLACE_CORRECTIVE_MEASURE',
            'RETURN_TO_TRUST_REVIEW'
       ]::text[]
       OR octet_length(exact_sealed_review_note_sha256) <> 32
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id,
        'SAVE_APPEAL_REVIEW_DRAFT'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, NULL,
        'SAVE_APPEAL_REVIEW_DRAFT', exact_appeal_id,
        exact_expected_appeal_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    PERFORM set_config('app.organization_id', root.organization_id::text, true);
    PERFORM set_config('app.case_id', root.source_case_id::text, true);
    PERFORM set_config('app.demand_id', root.demand_id::text, true);
    IF root.aggregate_version <> exact_expected_appeal_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    assignment := trust.require_appeal_assignment_v1(
        root.appeal_id, exact_actor_user_id,
        authority.duty_grant_id, authority.duty_grant_version, false
    );
    SELECT row.* INTO STRICT application
    FROM trust.appeal_application_versions AS row
    WHERE row.appeal_id = root.appeal_id
      AND row.application_version = root.submitted_application_version
    FOR SHARE;
    IF NOT trust.valid_appeal_assessments_v1(
        exact_assessments, application.grounds,
        application.new_evidence_reference_ids
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_REVIEW_INVALID';
    END IF;
    PERFORM 1
    FROM trust.restricted_text_blobs AS blob
    WHERE blob.appeal_id = root.appeal_id
      AND blob.organization_id = root.organization_id
      AND blob.case_id = root.source_case_id
      AND blob.actor_user_id = exact_actor_user_id
      AND blob.purpose_code = 'APPEAL_REVIEW_NOTE'
      AND blob.sealed_note_reference = exact_sealed_review_note_reference
      AND blob.envelope_sha256 = exact_sealed_review_note_sha256
      AND blob.retain_until > evaluated_time;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'APPEAL_SEALED_TEXT_REQUIRED';
    END IF;
    draft_version := COALESCE(root.current_review_draft_version, 0) + 1;
    INSERT INTO trust.appeal_review_drafts (
        appeal_id, assignment_id, draft_version, assessments,
        reason_codes, remedy_delta_codes,
        sealed_review_note_reference, sealed_review_note_sha256,
        sealed_review_note_purpose_code, edited_by_user_id, edited_at
    ) VALUES (
        root.appeal_id, assignment.assignment_id, draft_version,
        exact_assessments, exact_reason_codes, exact_remedy_delta_codes,
        exact_sealed_review_note_reference,
        exact_sealed_review_note_sha256, 'APPEAL_REVIEW_NOTE',
        exact_actor_user_id, evaluated_time
    );
    UPDATE trust.appeals AS row
    SET aggregate_version = row.aggregate_version + 1,
        current_review_draft_version = draft_version,
        updated_at = evaluated_time
    WHERE row.appeal_id = root.appeal_id;
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, root.organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.appeal_id, root.status, root.aggregate_version,
        'AppealReviewDraftSaved'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '42501', MESSAGE = 'APPEAL_ASSIGNMENT_REQUIRED';
END
$function$;

CREATE FUNCTION trust_api.release_appeal_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_appeal_id uuid,
    exact_expected_appeal_version bigint,
    exact_reason_code text,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    receipt record;
    root trust.appeals%ROWTYPE;
    assignment trust.appeal_review_assignments%ROWTYPE;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_correlation_id IS NULL
       OR exact_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_causation_id IS NULL
       OR exact_causation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_trace_id IS NULL
       OR exact_trace_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_receipt_id IS NULL
       OR exact_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_audit_event_id IS NULL
       OR exact_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_outbox_event_id IS NULL
       OR exact_outbox_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_expected_appeal_version < 1
       OR exact_reason_code NOT IN (
            'ASSIGNMENT_EXPIRED', 'CONFLICT_DECLARED', 'WORKLOAD_RELEASE'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id,
        'RELEASE_APPEAL_ASSIGNMENT'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, NULL,
        'RELEASE_APPEAL_ASSIGNMENT', exact_appeal_id,
        exact_expected_appeal_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    IF root.aggregate_version <> exact_expected_appeal_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    assignment := trust.require_appeal_assignment_v1(
        root.appeal_id, exact_actor_user_id,
        authority.duty_grant_id, authority.duty_grant_version,
        exact_reason_code = 'ASSIGNMENT_EXPIRED'
    );
    INSERT INTO trust.appeal_assignment_releases (
        assignment_id, appeal_id, released_by_user_id,
        reason_code, released_at
    ) VALUES (
        assignment.assignment_id, root.appeal_id,
        exact_actor_user_id, exact_reason_code, evaluated_time
    );
    UPDATE trust.appeals AS row
    SET status = 'SUBMITTED',
        aggregate_version = row.aggregate_version + 1,
        current_assignment_id = NULL,
        current_review_draft_version = NULL,
        updated_at = evaluated_time
    WHERE row.appeal_id = root.appeal_id;
    PERFORM set_config('app.organization_id', root.organization_id::text, true);
    PERFORM set_config('app.case_id', root.source_case_id::text, true);
    PERFORM set_config('app.demand_id', root.demand_id::text, true);
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, root.organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.appeal_id, root.status, root.aggregate_version,
        'AppealReviewAssignmentReleased'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '42501', MESSAGE = 'APPEAL_ASSIGNMENT_REQUIRED';
END
$function$;

CREATE FUNCTION trust_api.claim_appeal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_assignment_id uuid,
    exact_appeal_id uuid,
    exact_expected_appeal_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    receipt record;
    conflict record;
    root trust.appeals%ROWTYPE;
    assignment_expiry timestamptz;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_correlation_id IS NULL
       OR exact_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_causation_id IS NULL
       OR exact_causation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_trace_id IS NULL
       OR exact_trace_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_receipt_id IS NULL
       OR exact_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_audit_event_id IS NULL
       OR exact_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_outbox_event_id IS NULL
       OR exact_outbox_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_assignment_id IS NULL
       OR exact_assignment_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_expected_appeal_version < 1
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id, 'CLAIM_APPEAL'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, NULL,
        'CLAIM_APPEAL', exact_appeal_id, exact_expected_appeal_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    IF root.aggregate_version <> exact_expected_appeal_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'PRECONDITION_FAILED';
    ELSIF root.status <> 'SUBMITTED' OR root.current_assignment_id IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_ALREADY_ASSIGNED';
    END IF;
    SELECT row.* INTO STRICT conflict
    FROM trust.resolve_appeal_reviewer_conflict_v1(
        root.appeal_id, exact_actor_user_id,
        authority.duty_grant_id, authority.duty_grant_version,
        authority.authority_marker_sha256
    ) AS row;
    assignment_expiry := LEAST(
        evaluated_time + interval '4 hours', conflict.valid_until,
        COALESCE(authority.duty_expires_at, conflict.valid_until)
    );
    IF assignment_expiry <= evaluated_time THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'SESSION_EXPIRED';
    END IF;
    INSERT INTO trust.appeal_review_assignments (
        assignment_id, appeal_id, reviewer_user_id,
        duty_grant_id, duty_grant_version, authority_marker_sha256,
        conflict_attestation_sha256, conflict_evaluated_at,
        conflict_valid_until, assigned_at, expires_at
    ) VALUES (
        exact_assignment_id, root.appeal_id, exact_actor_user_id,
        authority.duty_grant_id, authority.duty_grant_version,
        authority.authority_marker_sha256,
        conflict.conflict_attestation_sha256,
        conflict.evaluated_at, conflict.valid_until,
        evaluated_time, assignment_expiry
    );
    UPDATE trust.appeals AS row
    SET status = 'IN_REVIEW',
        aggregate_version = row.aggregate_version + 1,
        current_assignment_id = exact_assignment_id,
        current_review_draft_version = NULL,
        updated_at = evaluated_time
    WHERE row.appeal_id = root.appeal_id;
    PERFORM set_config('app.organization_id', root.organization_id::text, true);
    PERFORM set_config('app.case_id', root.source_case_id::text, true);
    PERFORM set_config('app.demand_id', root.demand_id::text, true);
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, root.organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.appeal_id, root.status, root.aggregate_version,
        'AppealReviewClaimed'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_FOUND';
END
$function$;

CREATE FUNCTION trust_api.submit_appeal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_appeal_id uuid,
    exact_expected_appeal_version bigint,
    exact_expected_draft_version integer,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    receipt record;
    root trust.appeals%ROWTYPE;
    draft trust.appeal_application_drafts%ROWTYPE;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_organization_id IS NULL
       OR exact_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_correlation_id IS NULL
       OR exact_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_causation_id IS NULL
       OR exact_causation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_trace_id IS NULL
       OR exact_trace_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_receipt_id IS NULL
       OR exact_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_audit_event_id IS NULL
       OR exact_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_outbox_event_id IS NULL
       OR exact_outbox_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_expected_appeal_version < 1
       OR exact_expected_draft_version < 1
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_applicant_authority_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        'SUBMIT_APPEAL'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, exact_organization_id,
        'SUBMIT_APPEAL', exact_appeal_id, exact_expected_appeal_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    IF root.organization_id <> exact_organization_id
       OR root.applicant_user_id <> exact_actor_user_id
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_FOUND';
    ELSIF root.aggregate_version <> exact_expected_appeal_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'PRECONDITION_FAILED';
    ELSIF root.status <> 'DRAFT' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_STATE_CONFLICT';
    ELSIF root.current_application_draft_version
            IS DISTINCT FROM exact_expected_draft_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'APPEAL_DRAFT_VERSION_CONFLICT';
    ELSIF evaluated_time >= root.source_appeal_deadline THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_DEADLINE_PASSED';
    END IF;
    SELECT row.* INTO STRICT draft
    FROM trust.appeal_application_drafts AS row
    WHERE row.appeal_id = root.appeal_id
      AND row.draft_version = exact_expected_draft_version
    FOR SHARE;
    INSERT INTO trust.appeal_application_versions (
        appeal_id, application_version, source_draft_version,
        grounds, requested_outcome, sealed_statement_reference,
        sealed_statement_sha256, sealed_statement_purpose_code,
        new_evidence_reference_ids, submitted_by_user_id, submitted_at
    ) VALUES (
        root.appeal_id, 1, draft.draft_version, draft.grounds,
        draft.requested_outcome, draft.sealed_statement_reference,
        draft.sealed_statement_sha256, 'APPEAL_STATEMENT',
        draft.new_evidence_reference_ids, exact_actor_user_id,
        evaluated_time
    );
    UPDATE trust.appeals AS row
    SET status = 'SUBMITTED',
        aggregate_version = row.aggregate_version + 1,
        submitted_application_version = 1,
        updated_at = evaluated_time
    WHERE row.appeal_id = root.appeal_id;
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, root.organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.appeal_id, root.status, root.aggregate_version,
        'AppealSubmitted'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_FOUND';
END
$function$;

CREATE FUNCTION trust_api.save_appeal_draft_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_appeal_id uuid,
    exact_expected_appeal_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_sealed_statement_reference text,
    exact_sealed_statement_sha256 bytea,
    exact_grounds text[],
    exact_requested_outcome text,
    exact_new_evidence_reference_ids uuid[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    authority record;
    receipt record;
    root trust.appeals%ROWTYPE;
    draft_version integer;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_organization_id IS NULL
       OR exact_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_correlation_id IS NULL
       OR exact_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_causation_id IS NULL
       OR exact_causation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_trace_id IS NULL
       OR exact_trace_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_receipt_id IS NULL
       OR exact_receipt_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_audit_event_id IS NULL
       OR exact_audit_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_outbox_event_id IS NULL
       OR exact_outbox_event_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_expected_appeal_version < 1
       OR NOT trust.canonical_code_array_v1(exact_grounds, 1, 3)
       OR NOT exact_grounds <@ ARRAY[
            'NEW_MATERIAL_EVIDENCE', 'PROCEDURAL_ERROR',
            'RULE_MISAPPLICATION'
       ]::text[]
       OR exact_requested_outcome NOT IN (
            'REMOVE_MEASURE', 'MODIFY_MEASURE', 'VACATE_AND_REMAND'
       )
       OR NOT trust.canonical_uuid_array_v1(
            exact_new_evidence_reference_ids, 0, 32
       )
       OR (
            'NEW_MATERIAL_EVIDENCE' = ANY(exact_grounds)
            AND cardinality(exact_new_evidence_reference_ids) = 0
       )
       OR octet_length(exact_sealed_statement_sha256) <> 32
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_applicant_authority_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        'SAVE_APPEAL_DRAFT'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, exact_organization_id,
        'SAVE_APPEAL_DRAFT', exact_appeal_id,
        exact_expected_appeal_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    IF root.organization_id <> exact_organization_id
       OR root.applicant_user_id <> exact_actor_user_id
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_FOUND';
    ELSIF root.aggregate_version <> exact_expected_appeal_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'PRECONDITION_FAILED';
    ELSIF root.status <> 'DRAFT' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_APPLICATION_FROZEN';
    ELSIF evaluated_time >= root.source_appeal_deadline THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_DEADLINE_PASSED';
    END IF;
    PERFORM 1
    FROM trust.restricted_text_blobs AS blob
    WHERE blob.appeal_id = root.appeal_id
      AND blob.organization_id = root.organization_id
      AND blob.case_id = root.source_case_id
      AND blob.actor_user_id = exact_actor_user_id
      AND blob.purpose_code = 'APPEAL_STATEMENT'
      AND blob.sealed_note_reference = exact_sealed_statement_reference
      AND blob.envelope_sha256 = exact_sealed_statement_sha256
      AND blob.retain_until > evaluated_time;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'APPEAL_SEALED_TEXT_REQUIRED';
    END IF;
    draft_version := COALESCE(root.current_application_draft_version, 0) + 1;
    INSERT INTO trust.appeal_application_drafts (
        appeal_id, draft_version, grounds, requested_outcome,
        sealed_statement_reference, sealed_statement_sha256,
        sealed_statement_purpose_code, new_evidence_reference_ids,
        edited_by_user_id, edited_at
    ) VALUES (
        root.appeal_id, draft_version, exact_grounds,
        exact_requested_outcome, exact_sealed_statement_reference,
        exact_sealed_statement_sha256, 'APPEAL_STATEMENT',
        exact_new_evidence_reference_ids, exact_actor_user_id,
        evaluated_time
    );
    UPDATE trust.appeals AS row
    SET aggregate_version = row.aggregate_version + 1,
        current_application_draft_version = draft_version,
        updated_at = evaluated_time
    WHERE row.appeal_id = root.appeal_id;
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, root.organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.appeal_id, root.status, root.aggregate_version,
        'AppealApplicationDraftSaved'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_FOUND';
END
$function$;

CREATE FUNCTION trust_api.open_appeal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_appeal_id uuid,
    exact_source_outcome_version_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    authority record;
    receipt record;
    source record;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_appeal_id IS NULL OR exact_appeal_id = zero_uuid
       OR exact_source_outcome_version_id IS NULL
       OR exact_source_outcome_version_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.appeal_id', '', true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    SELECT row.* INTO STRICT authority
    FROM trust.resolve_appeal_applicant_authority_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        'OPEN_APPEAL'
    ) AS row;
    SELECT row.* INTO STRICT receipt
    FROM trust.claim_or_replay_appeal_receipt_v1(
        exact_receipt_id, exact_actor_user_id, exact_organization_id,
        'OPEN_APPEAL', exact_appeal_id, NULL,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids, exact_payload_hashes
    ) AS row;
    IF receipt.replayed THEN
        RETURN QUERY SELECT receipt.replay_safe_response, true;
        RETURN;
    END IF;

    SELECT row.* INTO STRICT source
    FROM trust.resolve_appeal_applicant_source_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        exact_source_outcome_version_id, authority.membership_id,
        authority.membership_role_grant_id,
        authority.membership_role_grant_version,
        authority.authority_marker_sha256
    ) AS row
    WHERE row.valid_until > evaluated_time;
    PERFORM set_config('app.appeal_id', '', true);
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(
        E'\x1f', 'desire:trust:appeal-source-applicant-lock:v1',
        exact_actor_user_id::text, exact_source_outcome_version_id::text
    ), 0));
    IF EXISTS (
        SELECT 1 FROM trust.appeals AS prior
        WHERE prior.applicant_user_id = exact_actor_user_id
          AND prior.source_outcome_version_id
                = exact_source_outcome_version_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'uq_appeal_source_applicant',
            MESSAGE = 'APPEAL_ALREADY_EXISTS';
    END IF;
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.case_id', source.source_case_id::text, true);
    PERFORM set_config('app.demand_id', source.demand_id::text, true);

    INSERT INTO trust.appeals (
        appeal_id, source_outcome_version_id, source_case_id,
        organization_id, demand_id, demand_version_id,
        applicant_user_id, applicant_membership_id,
        applicant_role_grant_id, applicant_role_grant_version,
        applicant_authority_marker_sha256, applicant_party_marker_sha256,
        source_outcome_code, source_reason_codes, source_action_codes,
        source_evidence_packet_version_id, source_evidence_packet_sha256,
        source_policy_version, source_decided_at, source_appeal_deadline,
        source_content_sha256, source_deciding_officer_user_id,
        source_appeal_eligible, source_appeal_eligibility_code,
        status, aggregate_version, current_application_draft_version,
        submitted_application_version, current_assignment_id,
        current_review_draft_version, decision_version_id,
        opened_at, updated_at
    ) VALUES (
        exact_appeal_id, exact_source_outcome_version_id,
        source.source_case_id, exact_organization_id,
        source.demand_id, source.demand_version_id,
        exact_actor_user_id, authority.membership_id,
        authority.membership_role_grant_id,
        authority.membership_role_grant_version,
        authority.authority_marker_sha256,
        source.applicant_party_marker_sha256,
        source.source_outcome_code, source.source_reason_codes,
        source.source_action_codes, source.source_evidence_packet_version_id,
        source.source_evidence_packet_sha256, source.source_policy_version,
        source.source_decided_at, source.source_appeal_deadline,
        source.source_content_sha256,
        source.source_deciding_officer_user_id,
        true, 'ELIGIBLE', 'DRAFT', 1,
        NULL, NULL, NULL, NULL, NULL, evaluated_time, evaluated_time
    );
    completed := trust.complete_appeal_command_v1(
        receipt.claimed_receipt_id, exact_audit_event_id,
        exact_outbox_event_id, exact_actor_user_id, exact_organization_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        exact_appeal_id, NULL, NULL, 'AppealOpened'
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

CREATE FUNCTION trust.complete_appeal_command_v1(
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_actor_user_id uuid,
    exact_organization_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_appeal_id uuid,
    exact_before_status text,
    exact_before_version bigint,
    exact_event_type text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, trust, audit, infra
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    root trust.appeals%ROWTYPE;
    completed_time timestamptz := transaction_timestamp();
    safe_result jsonb;
    event_payload jsonb;
    expected_status text;
    audit_action text;
    response_status integer;
    affected integer;
BEGIN
    expected_status := CASE exact_event_type
        WHEN 'AppealOpened' THEN 'DRAFT'
        WHEN 'AppealApplicationDraftSaved' THEN 'DRAFT'
        WHEN 'AppealSubmitted' THEN 'SUBMITTED'
        WHEN 'AppealReviewClaimed' THEN 'IN_REVIEW'
        WHEN 'AppealReviewAssignmentReleased' THEN 'SUBMITTED'
        WHEN 'AppealReviewDraftSaved' THEN 'IN_REVIEW'
        WHEN 'AppealDecisionPublished' THEN 'DECIDED'
        ELSE NULL
    END;
    audit_action := CASE exact_event_type
        WHEN 'AppealOpened' THEN 'appeal.opened'
        WHEN 'AppealApplicationDraftSaved' THEN 'appeal.application_draft_saved'
        WHEN 'AppealSubmitted' THEN 'appeal.submitted'
        WHEN 'AppealReviewClaimed' THEN 'appeal.review_claimed'
        WHEN 'AppealReviewAssignmentReleased' THEN
            'appeal.review_assignment_released'
        WHEN 'AppealReviewDraftSaved' THEN 'appeal.review_draft_saved'
        WHEN 'AppealDecisionPublished' THEN 'appeal.decision_published'
        ELSE NULL
    END;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id;
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_audit_event_id IS NULL OR exact_audit_event_id = zero_uuid
       OR exact_outbox_event_id IS NULL OR exact_outbox_event_id = zero_uuid
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_appeal_id IS NULL OR exact_appeal_id = zero_uuid
       OR expected_status IS NULL OR audit_action IS NULL
       OR root.organization_id <> exact_organization_id
       OR root.status <> expected_status
       OR root.aggregate_version < 1
       OR exact_before_version IS NOT NULL
            AND root.aggregate_version <> exact_before_version + 1
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_EVENT_CONTRACT_INVALID';
    END IF;
    event_payload := jsonb_strip_nulls(jsonb_build_object(
        'appeal_id', root.appeal_id,
        'appeal_status', root.status,
        'application_draft_version', root.current_application_draft_version,
        'application_version', root.submitted_application_version,
        'decision_version_id', root.decision_version_id,
        'review_draft_version', root.current_review_draft_version,
        'source_outcome_version_id', root.source_outcome_version_id
    ));
    IF event_payload ?| ARRAY[
            'applicant_user_id', 'reviewer_user_id', 'organization_id',
            'assignment_id', 'duty_grant_id', 'authority_marker_sha256',
            'sealed_statement_reference', 'sealed_review_note_reference',
            'sealed_statement_sha256', 'sealed_review_note_sha256'
       ]::text[]
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'APPEAL_EVENT_CONTRACT_INVALID';
    END IF;
    safe_result := jsonb_build_object(
        'aggregate_version', root.aggregate_version,
        'appeal_id', root.appeal_id,
        'appeal_status', root.status,
        'application_draft_version', root.current_application_draft_version,
        'application_version', root.submitted_application_version,
        'completed_at', trust.utc_timestamp_text_v1(completed_time),
        'decision_version_id', root.decision_version_id,
        'event_types', jsonb_build_array(exact_event_type),
        'review_draft_version', root.current_review_draft_version
    );

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id,
        before_status, after_status, before_version, after_version,
        role_code, purpose_code, reason_code, auth_strength_code,
        result_code, command_id, correlation_id, causation_id, trace_id,
        safe_attributes
    ) VALUES (
        exact_audit_event_id, completed_time, 'USER', exact_actor_user_id,
        NULL, audit_action, 'Appeal', root.appeal_id, root.organization_id,
        exact_before_status, root.status, exact_before_version,
        root.aggregate_version,
        CASE WHEN session_user = 'trust_appeal'
            THEN 'APPEAL_REVIEWER' ELSE 'DEMAND_OWNER' END,
        'TRUST_APPEAL', NULL, NULL, 'SUCCESS', exact_receipt_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        jsonb_build_object(
            'appeal_id', root.appeal_id,
            'appeal_status', root.status,
            'event_type', exact_event_type
        )
    );
    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at,
        aggregate_type, aggregate_id, aggregate_version,
        actor_kind, actor_id, original_actor_id,
        correlation_id, causation_id, trace_id, organization_id,
        payload, delivery_status, attempt_count, available_at,
        lease_owner, lease_until, published_at, last_error_code, created_at
    ) VALUES (
        exact_outbox_event_id, exact_event_type, 1, completed_time,
        'Appeal', root.appeal_id, root.aggregate_version,
        'USER', exact_actor_user_id, NULL,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        root.organization_id, event_payload, 'PENDING', 0, completed_time,
        NULL, NULL, NULL, NULL, completed_time
    );

    response_status := CASE
        WHEN exact_event_type IN ('AppealOpened', 'AppealReviewClaimed')
            THEN 201
        ELSE 200
    END;
    UPDATE trust.appeal_command_receipts AS receipt
    SET status = 'COMPLETED',
        response_http_status = response_status,
        safe_response = safe_result,
        target_version = root.aggregate_version,
        result_status = root.status,
        event_types = ARRAY[exact_event_type]::text[],
        completed_at = completed_time
    WHERE receipt.receipt_id = exact_receipt_id
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.target_appeal_id = root.appeal_id
      AND receipt.status = 'IN_PROGRESS';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003', MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    RETURN safe_result;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '40003', MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
END
$function$;

CREATE FUNCTION trust_api.store_appeal_restricted_text_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_appeal_id uuid,
    exact_purpose_code text,
    exact_encryption_key_ids text[],
    exact_candidate_references text[],
    exact_plaintext_hmac_sha256s bytea[],
    exact_envelope_sha256 bytea,
    exact_encryption_key_id text,
    exact_encryption_nonce bytea,
    exact_ciphertext bytea,
    exact_aad_sha256 bytea,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_retention_class text,
    exact_retain_until timestamptz,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint
)
RETURNS TABLE (
    sealed_note_reference text,
    sealed_note_sha256 bytea,
    retention_class text,
    sealed_at timestamptz,
    reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    root trust.appeals%ROWTYPE;
    applicant_authority record;
    reviewer_authority record;
    assignment trust.appeal_review_assignments%ROWTYPE;
    receipt_policy trust.appeal_receipt_key_policy%ROWTYPE;
    sealed_policy trust.sealed_text_key_policy%ROWTYPE;
    existing trust.restricted_text_blobs%ROWTYPE;
    matching_count integer;
    expected_aad_sha256 bytea;
    operation text;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    operation := CASE exact_purpose_code
        WHEN 'APPEAL_STATEMENT' THEN 'SAVE_APPEAL_DRAFT'
        WHEN 'APPEAL_REVIEW_NOTE' THEN 'SAVE_APPEAL_REVIEW_DRAFT'
        ELSE NULL
    END;
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_session_id IS NULL
       OR exact_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR operation IS NULL
       OR exact_retention_class <> 'APPEAL_RESTRICTED_TEXT'
       OR (
            exact_purpose_code = 'APPEAL_STATEMENT'
            AND (
                session_user <> 'trust_self'
                OR exact_organization_id IS NULL
                OR exact_organization_id
                    = '00000000-0000-0000-0000-000000000000'::uuid
                OR exact_duty_grant_id IS NOT NULL
                OR exact_duty_grant_version IS NOT NULL
            )
       )
       OR (
            exact_purpose_code = 'APPEAL_REVIEW_NOTE'
            AND (
                session_user <> 'trust_appeal'
                OR exact_organization_id IS NOT NULL
                OR (exact_duty_grant_id IS NULL)
                    <> (exact_duty_grant_version IS NULL)
                OR (
                    exact_duty_grant_id IS NOT NULL
                    AND (
                        exact_duty_grant_id
                            = '00000000-0000-0000-0000-000000000000'::uuid
                        OR exact_duty_grant_version < 1
                    )
                )
            )
       )
       OR cardinality(exact_encryption_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_encryption_key_ids)
            <> cardinality(exact_candidate_references)
       OR cardinality(exact_encryption_key_ids)
            <> cardinality(exact_plaintext_hmac_sha256s)
       OR cardinality(exact_idempotency_key_digest_key_ids)
            NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR EXISTS (
            SELECT 1 FROM unnest(exact_encryption_key_ids) AS key(value)
            WHERE key.value IS NULL
               OR key.value !~ '^[a-z0-9][a-z0-9-]{2,127}$'
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_candidate_references) AS ref(value)
            WHERE ref.value IS NULL
               OR ref.value !~ '^sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}$'
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_plaintext_hmac_sha256s) AS hash(value)
            WHERE hash.value IS NULL OR octet_length(hash.value) <> 32
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_idempotency_key_digests) AS hash(value)
            WHERE hash.value IS NULL OR octet_length(hash.value) <> 32
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_encryption_key_ids) AS key(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_candidate_references) AS ref(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS key(value)
       )
       OR octet_length(exact_envelope_sha256) <> 32
       OR exact_encryption_key_id !~ '^[a-z0-9][a-z0-9-]{2,127}$'
       OR octet_length(exact_encryption_nonce) <> 12
       OR octet_length(exact_ciphertext) NOT BETWEEN 17 AND 16384
       OR octet_length(exact_aad_sha256) <> 32
       OR exact_retain_until <= evaluated_time
       OR exact_retain_until > evaluated_time + interval '10 years'
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    PERFORM set_config('app.appeal_scope_kind', 'APPEAL_SEALED_TEXT', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.trust_scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    IF exact_purpose_code = 'APPEAL_STATEMENT' THEN
        SELECT authority.* INTO STRICT applicant_authority
        FROM trust.resolve_appeal_applicant_authority_v1(
            exact_actor_user_id, exact_session_id,
            exact_organization_id, operation
        ) AS authority;
    ELSE
        SELECT authority.* INTO STRICT reviewer_authority
        FROM trust.resolve_appeal_reviewer_authority_v1(
            exact_actor_user_id, exact_session_id, operation
        ) AS authority;
        IF exact_duty_grant_id IS NOT NULL
           AND (
                exact_duty_grant_id <> reviewer_authority.duty_grant_id
                OR exact_duty_grant_version
                    <> reviewer_authority.duty_grant_version
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
        END IF;
    END IF;

    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR SHARE;
    PERFORM set_config('app.organization_id', root.organization_id::text, true);
    PERFORM set_config('app.case_id', root.source_case_id::text, true);
    PERFORM set_config('app.demand_id', root.demand_id::text, true);
    IF exact_purpose_code = 'APPEAL_STATEMENT' THEN
        IF root.organization_id <> exact_organization_id
           OR root.applicant_user_id <> exact_actor_user_id
           OR root.status <> 'DRAFT'
           OR evaluated_time >= root.source_appeal_deadline
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_FOUND';
        END IF;
    ELSE
        assignment := trust.require_appeal_assignment_v1(
            root.appeal_id,
            exact_actor_user_id,
            reviewer_authority.duty_grant_id,
            reviewer_authority.duty_grant_version,
            false
        );
    END IF;

    SELECT row.* INTO STRICT receipt_policy
    FROM trust.appeal_receipt_key_policy AS row
    WHERE row.singleton_key
    FOR SHARE;
    SELECT row.* INTO STRICT sealed_policy
    FROM trust.sealed_text_key_policy AS row
    WHERE row.singleton_key
    FOR SHARE;
    IF exact_idempotency_key_digest_key_ids
            IS DISTINCT FROM receipt_policy.retained_idempotency_key_ids
       OR exact_idempotency_key_digest_key_ids[1]
            <> receipt_policy.active_idempotency_key_id
       OR exact_encryption_key_ids
            IS DISTINCT FROM sealed_policy.retained_encryption_key_ids
       OR exact_encryption_key_ids[1] <> sealed_policy.active_encryption_key_id
       OR exact_encryption_key_id <> sealed_policy.active_encryption_key_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'APPEAL_SEALED_TEXT_KEY_POLICY_UNAVAILABLE';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(
        E'\x1f', 'desire:trust:appeal-restricted-text-lock:v1',
        exact_actor_user_id::text, exact_appeal_id::text,
        exact_purpose_code, candidate.value
    ), 0))
    FROM unnest(exact_candidate_references) AS candidate(value)
    ORDER BY candidate.value;
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(
        E'\x1f', 'desire:trust:appeal-restricted-text-idempotency-lock:v1',
        exact_actor_user_id::text, exact_appeal_id::text,
        exact_purpose_code,
        exact_idempotency_key_digest_key_ids[slot.index],
        encode(exact_idempotency_key_digests[slot.index], 'hex')
    ), 0))
    FROM generate_subscripts(
        exact_idempotency_key_digests, 1
    ) AS slot(index)
    ORDER BY exact_idempotency_key_digest_key_ids[slot.index],
             encode(exact_idempotency_key_digests[slot.index], 'hex');

    SELECT count(*) INTO matching_count
    FROM trust.restricted_text_blobs AS blob
    WHERE blob.actor_user_id = exact_actor_user_id
      AND blob.appeal_id = exact_appeal_id
      AND blob.purpose_code = exact_purpose_code
      AND (
          blob.sealed_note_reference = ANY(exact_candidate_references)
          OR EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_key_digests, 1
              ) AS slot(index)
              WHERE blob.idempotency_key_digest_key_id
                        = exact_idempotency_key_digest_key_ids[slot.index]
                AND blob.idempotency_key_digest
                        = exact_idempotency_key_digests[slot.index]
          )
      );
    IF matching_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'APPEAL_SEALED_TEXT_AMBIGUOUS';
    ELSIF matching_count = 1 THEN
        SELECT blob.* INTO STRICT existing
        FROM trust.restricted_text_blobs AS blob
        WHERE blob.actor_user_id = exact_actor_user_id
          AND blob.appeal_id = exact_appeal_id
          AND blob.purpose_code = exact_purpose_code
          AND (
              blob.sealed_note_reference = ANY(exact_candidate_references)
              OR EXISTS (
                  SELECT 1
                  FROM generate_subscripts(
                      exact_idempotency_key_digests, 1
                  ) AS slot(index)
                  WHERE blob.idempotency_key_digest_key_id
                            = exact_idempotency_key_digest_key_ids[slot.index]
                    AND blob.idempotency_key_digest
                            = exact_idempotency_key_digests[slot.index]
              )
          )
        FOR SHARE;
        IF NOT EXISTS (
            SELECT 1
            FROM generate_subscripts(
                exact_plaintext_hmac_sha256s, 1
            ) AS slot(index)
            WHERE exact_encryption_key_ids[slot.index]
                    = existing.encryption_key_id
              AND exact_plaintext_hmac_sha256s[slot.index]
                    = existing.plaintext_hmac_sha256
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'uq_trust_restricted_text_appeal_idempotency',
                MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.organization_id <> root.organization_id
           OR existing.case_id <> root.source_case_id
           OR existing.retain_until <= evaluated_time
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'APPEAL_SEALED_TEXT_REPLAY_INVALID';
        END IF;
        RETURN QUERY SELECT
            existing.sealed_note_reference::text,
            existing.envelope_sha256,
            existing.retention_class::text,
            existing.sealed_at,
            true;
        RETURN;
    END IF;

    expected_aad_sha256 := sha256(convert_to(concat_ws(
        E'\x1f', 'desire:trust:appeal-restricted-text-aad:v1',
        exact_candidate_references[1],
        exact_appeal_id::text,
        exact_actor_user_id::text,
        exact_purpose_code,
        encode(exact_plaintext_hmac_sha256s[1], 'hex'),
        exact_encryption_key_id
    ), 'UTF8'));
    IF exact_aad_sha256 <> expected_aad_sha256
       OR exact_envelope_sha256 <> sha256(convert_to(concat_ws(
            E'\x1f', 'desire:trust:appeal-restricted-text-envelope:v1',
            exact_encryption_key_id,
            encode(exact_encryption_nonce, 'hex'),
            encode(exact_ciphertext, 'hex'),
            encode(exact_aad_sha256, 'hex')
       ), 'UTF8'))
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    INSERT INTO trust.restricted_text_blobs (
        sealed_note_reference, organization_id, case_id, actor_user_id,
        purpose_code, plaintext_hmac_sha256, envelope_sha256,
        encryption_key_id, encryption_nonce, ciphertext, aad_sha256,
        idempotency_key_digest_key_id, idempotency_key_digest,
        retention_class, sealed_at, retain_until, appeal_id
    ) VALUES (
        exact_candidate_references[1], root.organization_id,
        root.source_case_id, exact_actor_user_id, exact_purpose_code,
        exact_plaintext_hmac_sha256s[1], exact_envelope_sha256,
        exact_encryption_key_id, exact_encryption_nonce, exact_ciphertext,
        exact_aad_sha256, exact_idempotency_key_digest_key_ids[1],
        exact_idempotency_key_digests[1], exact_retention_class,
        evaluated_time, exact_retain_until, exact_appeal_id
    );
    RETURN QUERY SELECT
        exact_candidate_references[1], exact_envelope_sha256,
        exact_retention_class, evaluated_time, false;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

CREATE FUNCTION trust.appeal_key_rotation_scope_v1()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog
AS $function$
SELECT current_user = 'trust_schema_owner'
   AND session_user = 'trust_migration_runner'
   AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
        = 'APPEAL_KEY_ROTATION'
$function$;

CREATE FUNCTION trust.resolve_appeal_applicant_source_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_source_outcome_version_id uuid,
    exact_membership_id uuid,
    exact_membership_role_grant_id uuid,
    exact_membership_role_grant_version bigint,
    exact_authority_marker_sha256 bytea
)
RETURNS TABLE (
    source_case_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    source_outcome_code text,
    source_reason_codes text[],
    source_action_codes text[],
    source_evidence_packet_version_id uuid,
    source_evidence_packet_sha256 bytea,
    source_policy_version text,
    source_decided_at timestamptz,
    source_appeal_deadline timestamptz,
    source_content_sha256 bytea,
    source_deciding_officer_user_id uuid,
    applicant_party_marker_sha256 bytea,
    evaluated_at timestamptz,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust, demand_api
AS $function$
DECLARE
    source_row record;
    party_marker bytea;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR octet_length(exact_authority_marker_sha256) <> 32
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    SELECT
        outcome.organization_id,
        outcome.case_id,
        safety_case.demand_id,
        safety_case.demand_version_id,
        outcome.outcome_code,
        outcome.reason_codes,
        outcome.action_codes,
        outcome.evidence_packet_version_id,
        outcome.evidence_packet_digest,
        outcome.policy_version,
        outcome.decided_at,
        outcome.appeal_deadline,
        outcome.content_sha256,
        outcome.decided_by_user_id
    INTO STRICT source_row
    FROM trust.case_outcome_versions AS outcome
    JOIN trust.cases AS safety_case
      ON safety_case.organization_id = outcome.organization_id
     AND safety_case.case_id = outcome.case_id
     AND safety_case.outcome_version_id = outcome.outcome_version_id
    WHERE outcome.outcome_version_id = exact_source_outcome_version_id
      AND outcome.organization_id = exact_organization_id
      AND safety_case.status = 'DECIDED'
      AND outcome.appeal_eligible
      AND outcome.appeal_eligibility_code = 'ELIGIBLE'
      AND outcome.appeal_deadline > evaluated_time
      AND outcome.policy_version = 'trust-case-outcome-v1'
    FOR SHARE OF safety_case, outcome;

    PERFORM set_config('app.membership_id', exact_membership_id::text, true);
    PERFORM set_config(
        'app.membership_role_grant_id',
        exact_membership_role_grant_id::text,
        true
    );
    PERFORM set_config(
        'app.membership_role_grant_version',
        exact_membership_role_grant_version::text,
        true
    );
    PERFORM set_config('app.demand_id', source_row.demand_id::text, true);
    PERFORM set_config(
        'app.demand_version_id', source_row.demand_version_id::text, true
    );
    SELECT resolved.applicant_party_marker_sha256
    INTO STRICT party_marker
    FROM demand_api.resolve_appeal_applicant_party_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        exact_membership_id,
        exact_membership_role_grant_id,
        exact_membership_role_grant_version,
        source_row.demand_id,
        source_row.demand_version_id,
        exact_authority_marker_sha256
    ) AS resolved
    WHERE octet_length(resolved.applicant_party_marker_sha256) = 32;

    RETURN QUERY SELECT
        source_row.case_id,
        source_row.demand_id,
        source_row.demand_version_id,
        source_row.outcome_code::text,
        source_row.reason_codes,
        source_row.action_codes,
        source_row.evidence_packet_version_id,
        source_row.evidence_packet_digest,
        source_row.policy_version::text,
        source_row.decided_at,
        source_row.appeal_deadline,
        source_row.content_sha256,
        source_row.decided_by_user_id,
        party_marker,
        evaluated_time,
        LEAST(source_row.appeal_deadline, evaluated_time + interval '5 minutes');
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '42501', MESSAGE = 'APPEAL_NOT_AVAILABLE';
END
$function$;

CREATE FUNCTION trust.resolve_appeal_reviewer_conflict_v1(
    exact_appeal_id uuid,
    exact_reviewer_user_id uuid,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint,
    exact_authority_marker_sha256 bytea
)
RETURNS TABLE (
    conflict_attestation_sha256 bytea,
    evaluated_at timestamptz,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    root trust.appeals%ROWTYPE;
    evaluated_time timestamptz := transaction_timestamp();
    expiry timestamptz := evaluated_time + interval '5 minutes';
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_duty_grant_version < 1
       OR octet_length(exact_authority_marker_sha256) <> 32
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    IF root.status <> 'SUBMITTED'
       OR root.current_assignment_id IS NOT NULL
       OR exact_reviewer_user_id IN (
            root.applicant_user_id, root.source_deciding_officer_user_id
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'CONFLICT_OF_INTEREST';
    END IF;
    RETURN QUERY SELECT
        sha256(convert_to(concat_ws(
            E'\x1f', 'desire:trust:appeal-reviewer-conflict:v1',
            root.appeal_id::text, root.source_outcome_version_id::text,
            root.source_case_id::text, root.source_content_sha256,
            exact_reviewer_user_id::text, exact_duty_grant_id::text,
            exact_duty_grant_version::text,
            encode(exact_authority_marker_sha256, 'hex'),
            trust.utc_timestamp_text_v1(evaluated_time),
            trust.utc_timestamp_text_v1(expiry)
        ), 'UTF8')),
        evaluated_time,
        expiry;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '42501', MESSAGE = 'CONFLICT_OF_INTEREST';
END
$function$;

CREATE FUNCTION trust.require_appeal_assignment_v1(
    exact_appeal_id uuid,
    exact_actor_user_id uuid,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint,
    allow_expired_other_reviewer boolean
)
RETURNS trust.appeal_review_assignments
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    root trust.appeals%ROWTYPE;
    assignment trust.appeal_review_assignments%ROWTYPE;
BEGIN
    SELECT row.* INTO STRICT root
    FROM trust.appeals AS row
    WHERE row.appeal_id = exact_appeal_id
    FOR UPDATE;
    SELECT row.* INTO STRICT assignment
    FROM trust.appeal_review_assignments AS row
    WHERE row.appeal_id = root.appeal_id
      AND row.assignment_id = root.current_assignment_id
      AND NOT EXISTS (
          SELECT 1 FROM trust.appeal_assignment_releases AS release
          WHERE release.assignment_id = row.assignment_id
      )
    FOR UPDATE;
    IF root.status <> 'IN_REVIEW'
       OR (
            allow_expired_other_reviewer
            AND transaction_timestamp() < assignment.expires_at
       )
       OR (
            NOT allow_expired_other_reviewer
            AND (
                assignment.reviewer_user_id <> exact_actor_user_id
                OR assignment.duty_grant_id <> exact_duty_grant_id
                OR assignment.duty_grant_version
                    <> exact_duty_grant_version
                OR transaction_timestamp() < assignment.assigned_at
                OR transaction_timestamp() >= assignment.expires_at
            )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'APPEAL_ASSIGNMENT_REQUIRED';
    END IF;
    RETURN assignment;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '42501', MESSAGE = 'APPEAL_ASSIGNMENT_REQUIRED';
END
$function$;

CREATE FUNCTION trust.guard_appeal_receipt_update_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE'
       OR OLD.status <> 'IN_PROGRESS'
       OR NEW.status <> 'COMPLETED'
       OR NEW.receipt_id <> OLD.receipt_id
       OR NEW.principal_id <> OLD.principal_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.command_name <> OLD.command_name
       OR NEW.idempotency_key_digest_key_id
            <> OLD.idempotency_key_digest_key_id
       OR NEW.idempotency_key_digest <> OLD.idempotency_key_digest
       OR NEW.payload_hash_key_id <> OLD.payload_hash_key_id
       OR NEW.payload_hash <> OLD.payload_hash
       OR NEW.canonicalization_version <> OLD.canonicalization_version
       OR NEW.http_method <> OLD.http_method
       OR NEW.canonical_path <> OLD.canonical_path
       OR NEW.if_match_version IS DISTINCT FROM OLD.if_match_version
       OR NEW.target_appeal_id <> OLD.target_appeal_id
       OR NEW.retain_until <> OLD.retain_until
       OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_appeal_receipt_guard',
            MESSAGE = 'APPEAL_RECEIPT_MUTATION_INVALID';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.guard_appeal_receipt_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF TG_OP = 'DELETE' OR NOT NEW.singleton_key THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_appeal_receipt_policy_exact_one',
            MESSAGE = 'APPEAL_RECEIPT_POLICY_REQUIRED';
    END IF;
    IF TG_OP = 'UPDATE' AND EXISTS (
        SELECT 1
        FROM trust.appeal_command_receipts AS receipt
        WHERE receipt.retain_until > transaction_timestamp()
          AND (
              NOT receipt.idempotency_key_digest_key_id
                    = ANY(NEW.retained_idempotency_key_ids)
              OR NOT receipt.payload_hash_key_id
                    = ANY(NEW.retained_payload_key_ids)
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_appeal_receipt_policy_retention',
            MESSAGE = 'APPEAL_RECEIPT_KEY_STILL_RETAINED';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.valid_appeal_assessments_v1(
    exact_assessments jsonb,
    exact_expected_grounds text[],
    exact_allowed_evidence uuid[]
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    item jsonb;
    assessment_grounds text[] := ARRAY[]::text[];
    finding_values text[];
    evidence_values text[];
BEGIN
    IF jsonb_typeof(exact_assessments) <> 'array'
       OR jsonb_array_length(exact_assessments) NOT BETWEEN 1 AND 3
       OR exact_expected_grounds IS NULL
       OR exact_allowed_evidence IS NULL THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(exact_assessments)
    LOOP
        IF jsonb_typeof(item) <> 'object'
           OR NOT trust.jsonb_has_exact_keys(item, ARRAY[
                'accepted_evidence_reference_ids', 'assessment_code',
                'finding_codes', 'ground'
           ]::text[])
           OR item->>'ground' NOT IN (
                'NEW_MATERIAL_EVIDENCE', 'PROCEDURAL_ERROR',
                'RULE_MISAPPLICATION'
           )
           OR item->>'assessment_code' NOT IN (
                'ACCEPTED', 'PARTIALLY_ACCEPTED', 'REJECTED'
           )
           OR jsonb_typeof(item->'finding_codes') <> 'array'
           OR jsonb_array_length(item->'finding_codes') NOT BETWEEN 1 AND 32
           OR jsonb_typeof(item->'accepted_evidence_reference_ids') <> 'array'
           OR jsonb_array_length(
                item->'accepted_evidence_reference_ids'
              ) > 32 THEN
            RETURN false;
        END IF;
        SELECT array_agg(value ORDER BY value COLLATE "C")
        INTO finding_values
        FROM jsonb_array_elements_text(item->'finding_codes') AS fact(value);
        IF finding_values IS NULL
           OR finding_values <> ARRAY(
                SELECT value
                FROM jsonb_array_elements_text(item->'finding_codes') AS fact(value)
           )
           OR cardinality(finding_values) <> (
                SELECT count(DISTINCT value)
                FROM unnest(finding_values) AS fact(value)
           )
           OR NOT finding_values <@ ARRAY[
                'APPEAL_NOT_SUBSTANTIATED', 'NEW_EVIDENCE_MATERIAL',
                'PROCEDURE_MATERIAL_ERROR', 'RULE_APPLICATION_ERROR',
                'RULE_APPLIED_CORRECTLY'
           ]::text[] THEN
            RETURN false;
        END IF;
        SELECT COALESCE(
            array_agg(value ORDER BY value COLLATE "C"), ARRAY[]::text[]
        ) INTO evidence_values
        FROM jsonb_array_elements_text(
            item->'accepted_evidence_reference_ids'
        ) AS evidence(value);
        IF evidence_values <> ARRAY(
                SELECT value
                FROM jsonb_array_elements_text(
                    item->'accepted_evidence_reference_ids'
                ) AS evidence(value)
           )
           OR cardinality(evidence_values) <> (
                SELECT count(DISTINCT value)
                FROM unnest(evidence_values) AS evidence(value)
           )
           OR EXISTS (
                SELECT 1
                FROM unnest(evidence_values) AS evidence(value)
                WHERE evidence.value
                    !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                   OR evidence.value::uuid
                        <> ALL(exact_allowed_evidence)
           ) THEN
            RETURN false;
        END IF;
        assessment_grounds := array_append(
            assessment_grounds, item->>'ground'
        );
    END LOOP;
    RETURN assessment_grounds = exact_expected_grounds
       AND cardinality(assessment_grounds) = (
            SELECT count(DISTINCT value)
            FROM unnest(assessment_grounds) AS ground(value)
       );
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
    RETURN false;
END
$function$;

CREATE TRIGGER appeal_guard
BEFORE UPDATE OR DELETE ON trust.appeals
FOR EACH ROW EXECUTE FUNCTION trust.guard_appeal_update_v1();
CREATE TRIGGER appeal_application_drafts_immutable
BEFORE UPDATE OR DELETE ON trust.appeal_application_drafts
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_appeal_application_drafts_immutable'
);
CREATE TRIGGER appeal_application_versions_immutable
BEFORE UPDATE OR DELETE ON trust.appeal_application_versions
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_appeal_application_versions_immutable'
);
CREATE TRIGGER appeal_review_assignments_immutable
BEFORE UPDATE OR DELETE ON trust.appeal_review_assignments
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_appeal_review_assignments_immutable'
);
CREATE TRIGGER appeal_assignment_releases_immutable
BEFORE UPDATE OR DELETE ON trust.appeal_assignment_releases
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_appeal_assignment_releases_immutable'
);
CREATE TRIGGER appeal_review_drafts_immutable
BEFORE UPDATE OR DELETE ON trust.appeal_review_drafts
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_appeal_review_drafts_immutable'
);
CREATE TRIGGER appeal_decisions_immutable
BEFORE UPDATE OR DELETE ON trust.appeal_decision_versions
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_appeal_decisions_immutable'
);
CREATE TRIGGER appeal_receipt_guard
BEFORE UPDATE OR DELETE ON trust.appeal_command_receipts
FOR EACH ROW EXECUTE FUNCTION trust.guard_appeal_receipt_update_v1();
CREATE TRIGGER appeal_receipt_policy_guard
BEFORE UPDATE OR DELETE ON trust.appeal_receipt_key_policy
FOR EACH ROW EXECUTE FUNCTION trust.guard_appeal_receipt_policy_v1();

ALTER TABLE trust.appeals ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeals FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_application_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_application_drafts FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_application_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_application_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_review_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_review_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_assignment_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_assignment_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_review_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_review_drafts FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_decision_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_decision_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_receipt_key_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_receipt_key_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_command_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_appeals_definer ON trust.appeals
FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(organization_id, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(organization_id, appeal_id));
CREATE POLICY rls_appeal_application_drafts_definer
ON trust.appeal_application_drafts FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(NULL, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(NULL, appeal_id));
CREATE POLICY rls_appeal_application_versions_definer
ON trust.appeal_application_versions FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(NULL, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(NULL, appeal_id));
CREATE POLICY rls_appeal_review_assignments_definer
ON trust.appeal_review_assignments FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(NULL, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(NULL, appeal_id));
CREATE POLICY rls_appeal_assignment_releases_definer
ON trust.appeal_assignment_releases FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(NULL, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(NULL, appeal_id));
CREATE POLICY rls_appeal_review_drafts_definer
ON trust.appeal_review_drafts FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(NULL, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(NULL, appeal_id));
CREATE POLICY rls_appeal_decisions_definer
ON trust.appeal_decision_versions FOR ALL TO trust_schema_owner
USING (trust.appeal_definer_scope_allows_v1(NULL, appeal_id))
WITH CHECK (trust.appeal_definer_scope_allows_v1(NULL, appeal_id));
CREATE POLICY rls_appeal_receipt_policy_definer
ON trust.appeal_receipt_key_policy FOR ALL TO trust_schema_owner
USING (
    singleton_key AND trust.appeal_definer_scope_allows_v1(NULL, NULL)
)
WITH CHECK (
    singleton_key AND trust.appeal_definer_scope_allows_v1(NULL, NULL)
);
CREATE POLICY rls_appeal_receipts_definer
ON trust.appeal_command_receipts FOR ALL TO trust_schema_owner
USING (
    principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND trust.appeal_definer_scope_allows_v1(
        organization_id, target_appeal_id
    )
)
WITH CHECK (
    principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND trust.appeal_definer_scope_allows_v1(
        organization_id, target_appeal_id
    )
);
CREATE POLICY rls_appeal_receipts_rotation_read
ON trust.appeal_command_receipts FOR SELECT TO trust_schema_owner
USING (trust.appeal_key_rotation_scope_v1());
CREATE POLICY rls_appeal_receipt_policy_rotation
ON trust.appeal_receipt_key_policy FOR ALL TO trust_schema_owner
USING (singleton_key AND trust.appeal_key_rotation_scope_v1())
WITH CHECK (singleton_key AND trust.appeal_key_rotation_scope_v1());
CREATE POLICY rls_appeal_sealed_policy_rotation
ON trust.sealed_text_key_policy FOR ALL TO trust_schema_owner
USING (singleton_key AND trust.appeal_key_rotation_scope_v1())
WITH CHECK (singleton_key AND trust.appeal_key_rotation_scope_v1());
CREATE POLICY rls_appeal_restricted_text_rotation_read
ON trust.restricted_text_blobs FOR SELECT TO trust_schema_owner
USING (trust.appeal_key_rotation_scope_v1());

SET LOCAL ROLE schema_owner;

CREATE POLICY rls_appeal_audit_insert
ON audit.audit_events FOR INSERT TO trust_schema_owner
WITH CHECK (
    session_user IN ('trust_self', 'trust_appeal')
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
        = 'APPEAL_COMMAND'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND target_kind = 'Appeal'
    AND target_id = NULLIF(
        current_setting('app.appeal_id', true), ''
    )::uuid
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NOT safe_attributes ?| ARRAY[
        'applicant_user_id', 'reviewer_user_id', 'organization_id',
        'assignment_id', 'duty_grant_id', 'authority_marker_sha256',
        'sealed_statement_reference', 'sealed_review_note_reference',
        'sealed_statement_sha256', 'sealed_review_note_sha256',
        'raw_text', 'ciphertext'
    ]::text[]
);

CREATE POLICY rls_appeal_outbox_insert
ON infra.outbox_events FOR INSERT TO trust_schema_owner
WITH CHECK (
    session_user IN ('trust_self', 'trust_appeal')
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
        = 'APPEAL_COMMAND'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND aggregate_type = 'Appeal'
    AND aggregate_id = NULLIF(
        current_setting('app.appeal_id', true), ''
    )::uuid
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NOT payload ?| ARRAY[
        'applicant_user_id', 'reviewer_user_id', 'organization_id',
        'assignment_id', 'duty_grant_id', 'authority_marker_sha256',
        'sealed_statement_reference', 'sealed_review_note_reference',
        'sealed_statement_sha256', 'sealed_review_note_sha256',
        'raw_text', 'ciphertext'
    ]::text[]
);

SET LOCAL ROLE trust_schema_owner;

CREATE FUNCTION trust.resolve_appeal_applicant_authority_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_operation text
)
RETURNS TABLE (
    membership_id uuid,
    membership_role_grant_id uuid,
    membership_role_grant_version bigint,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust, iam_api
AS $function$
DECLARE
    resolved record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_operation NOT IN (
            'OPEN_APPEAL', 'READ_OWN_APPEAL',
            'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.scope_kind', 'TRUST_REPORTER', true);
    PERFORM set_config('app.operation', exact_operation, true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.session_id', exact_session_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.membership_id', '', true);
    PERFORM set_config('app.membership_role_grant_id', '', true);
    PERFORM set_config('app.membership_role_grant_version', '', true);
    PERFORM set_config('app.duty_grant_id', '', true);
    PERFORM set_config('app.duty_grant_version', '', true);

    SELECT authority.* INTO STRICT resolved
    FROM iam_api.resolve_trust_reporter_authority_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id,
        exact_operation
    ) AS authority
    WHERE authority.actor_user_id = exact_actor_user_id
      AND authority.session_id = exact_session_id
      AND authority.organization_id = exact_organization_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.organization_status = 'ACTIVE'
      AND authority.membership_status = 'ACTIVE'
      AND authority.role_code = 'DEMAND_OWNER'
      AND authority.membership_role_grant_version >= 1
      AND authority.policy_requirements_satisfied
      AND octet_length(authority.authority_marker_sha256) = 32;
    PERFORM set_config('app.membership_id', resolved.membership_id::text, true);
    PERFORM set_config(
        'app.membership_role_grant_id',
        resolved.membership_role_grant_id::text,
        true
    );
    PERFORM set_config(
        'app.membership_role_grant_version',
        resolved.membership_role_grant_version::text,
        true
    );
    RETURN QUERY SELECT
        resolved.membership_id,
        resolved.membership_role_grant_id,
        resolved.membership_role_grant_version,
        resolved.authority_marker_sha256;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

CREATE FUNCTION trust.resolve_appeal_reviewer_authority_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text
)
RETURNS TABLE (
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust, iam_api
AS $function$
DECLARE
    resolved record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_operation NOT IN (
            'LIST_APPEAL_QUEUE', 'READ_ASSIGNED_APPEAL',
            'CLAIM_APPEAL', 'RELEASE_APPEAL_ASSIGNMENT',
            'SAVE_APPEAL_REVIEW_DRAFT', 'DECIDE_APPEAL'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.scope_kind', 'TRUST_APPEAL', true);
    PERFORM set_config('app.operation', exact_operation, true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.session_id', exact_session_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.membership_id', '', true);
    PERFORM set_config('app.membership_role_grant_id', '', true);
    PERFORM set_config('app.membership_role_grant_version', '', true);

    SELECT authority.* INTO STRICT resolved
    FROM iam_api.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id, exact_session_id, exact_operation
    ) AS authority
    WHERE authority.actor_user_id = exact_actor_user_id
      AND authority.session_id = exact_session_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.duty_code = 'APPEAL_REVIEWER'
      AND authority.duty_grant_version >= 1
      AND (
          authority.duty_expires_at IS NULL
          OR transaction_timestamp() < authority.duty_expires_at
      )
      AND octet_length(authority.authority_marker_sha256) = 32;
    PERFORM set_config('app.duty_grant_id', resolved.duty_grant_id::text, true);
    PERFORM set_config(
        'app.duty_grant_version', resolved.duty_grant_version::text, true
    );
    RETURN QUERY SELECT
        resolved.duty_grant_id,
        resolved.duty_grant_version,
        resolved.duty_expires_at,
        resolved.authority_marker_sha256;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

CREATE FUNCTION trust.claim_or_replay_appeal_receipt_v1(
    exact_receipt_id uuid,
    exact_actor_user_id uuid,
    exact_organization_id uuid,
    exact_command_name text,
    exact_target_appeal_id uuid,
    exact_if_match_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (
    replayed boolean,
    claimed_receipt_id uuid,
    replay_safe_response jsonb
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    policy trust.appeal_receipt_key_policy%ROWTYPE;
    existing trust.appeal_command_receipts%ROWTYPE;
    matching_count integer;
    expected_method text;
    expected_path text;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    expected_method := CASE exact_command_name
        WHEN 'OPEN_APPEAL' THEN 'POST'
        WHEN 'SAVE_APPEAL_DRAFT' THEN 'PUT'
        WHEN 'SUBMIT_APPEAL' THEN 'POST'
        WHEN 'CLAIM_APPEAL' THEN 'POST'
        WHEN 'RELEASE_APPEAL_ASSIGNMENT' THEN 'POST'
        WHEN 'SAVE_APPEAL_REVIEW_DRAFT' THEN 'PUT'
        WHEN 'DECIDE_APPEAL' THEN 'POST'
        ELSE NULL
    END;
    expected_path := CASE exact_command_name
        WHEN 'OPEN_APPEAL' THEN '/v1/app/appeals'
        WHEN 'SAVE_APPEAL_DRAFT' THEN '/v1/app/appeals/{appeal_id}/draft'
        WHEN 'SUBMIT_APPEAL' THEN '/v1/app/appeals/{appeal_id}/submit'
        WHEN 'CLAIM_APPEAL' THEN
            '/v1/app/appeal-review/queue/{appeal_id}/claim'
        WHEN 'RELEASE_APPEAL_ASSIGNMENT' THEN
            '/v1/app/appeal-review/appeals/{appeal_id}/assignment/release'
        WHEN 'SAVE_APPEAL_REVIEW_DRAFT' THEN
            '/v1/app/appeal-review/appeals/{appeal_id}/review-draft'
        WHEN 'DECIDE_APPEAL' THEN
            '/v1/app/appeal-review/appeals/{appeal_id}/decide'
        ELSE NULL
    END;
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user NOT IN ('trust_self', 'trust_appeal')
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_target_appeal_id IS NULL OR exact_target_appeal_id = zero_uuid
       OR expected_method IS NULL OR expected_path IS NULL
       OR (
            exact_command_name = 'OPEN_APPEAL'
            AND (
                session_user <> 'trust_self'
                OR exact_organization_id IS NULL
                OR exact_organization_id = zero_uuid
                OR exact_if_match_version IS NOT NULL
            )
       )
       OR (
            exact_command_name <> 'OPEN_APPEAL'
            AND (
                exact_if_match_version IS NULL
                OR exact_if_match_version < 1
                OR (
                    exact_command_name IN (
                        'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
                    ) AND (
                        exact_organization_id IS NULL
                        OR exact_organization_id = zero_uuid
                    )
                )
                OR (
                    exact_command_name IN (
                        'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
                    ) AND session_user <> 'trust_self'
                )
                OR (
                    exact_command_name NOT IN (
                        'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
                    ) AND (
                        session_user <> 'trust_appeal'
                        OR exact_organization_id IS NOT NULL
                    )
                )
            )
       )
       OR cardinality(exact_idempotency_key_digest_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR EXISTS (
            SELECT 1 FROM unnest(exact_idempotency_key_digests) AS value(digest)
            WHERE value.digest IS NULL OR octet_length(value.digest) <> 32
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_payload_hashes) AS value(digest)
            WHERE value.digest IS NULL OR octet_length(value.digest) <> 32
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS key(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_payload_hash_key_ids) AS key(value)
       )
       OR NULLIF(current_setting('app.appeal_scope_kind', true), '')
            IS DISTINCT FROM 'APPEAL_COMMAND'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR (
            exact_command_name = 'OPEN_APPEAL'
            AND NULLIF(current_setting('app.appeal_id', true), '') IS NOT NULL
       )
       OR (
            exact_command_name <> 'OPEN_APPEAL'
            AND NULLIF(current_setting('app.appeal_id', true), '')
                IS DISTINCT FROM exact_target_appeal_id::text
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'APPEAL_COMMAND_CONTEXT_INVALID';
    END IF;

    SELECT row.* INTO STRICT policy
    FROM trust.appeal_receipt_key_policy AS row
    WHERE row.singleton_key
    FOR SHARE;
    IF policy.canonicalization_version <> 'appeal-command-json-v1'
       OR exact_idempotency_key_digest_key_ids
            IS DISTINCT FROM policy.retained_idempotency_key_ids
       OR exact_payload_hash_key_ids
            IS DISTINCT FROM policy.retained_payload_key_ids
       OR exact_idempotency_key_digest_key_ids[1]
            <> policy.active_idempotency_key_id
       OR exact_payload_hash_key_ids[1] <> policy.active_payload_key_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'APPEAL_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(
        E'\x1f', 'desire:trust:appeal-receipt-lock:v1',
        exact_actor_user_id::text, exact_command_name,
        exact_idempotency_key_digest_key_ids[slot.index],
        encode(exact_idempotency_key_digests[slot.index], 'hex')
    ), 0))
    FROM generate_subscripts(exact_idempotency_key_digests, 1) AS slot(index)
    ORDER BY exact_idempotency_key_digest_key_ids[slot.index],
             encode(exact_idempotency_key_digests[slot.index], 'hex');

    SELECT count(*) INTO matching_count
    FROM trust.appeal_command_receipts AS receipt
    WHERE receipt.principal_id = exact_actor_user_id
      AND receipt.command_name = exact_command_name
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(
              exact_idempotency_key_digests, 1
          ) AS slot(index)
          WHERE receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_ids[slot.index]
            AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digests[slot.index]
      );
    IF matching_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'APPEAL_RECEIPT_AMBIGUOUS';
    ELSIF matching_count = 1 THEN
        SELECT receipt.* INTO STRICT existing
        FROM trust.appeal_command_receipts AS receipt
        WHERE receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = exact_command_name
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_key_digests, 1
              ) AS slot(index)
              WHERE receipt.idempotency_key_digest_key_id
                        = exact_idempotency_key_digest_key_ids[slot.index]
                AND receipt.idempotency_key_digest
                        = exact_idempotency_key_digests[slot.index]
          )
        FOR UPDATE;
        IF NOT EXISTS (
            SELECT 1
            FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
            WHERE exact_payload_hash_key_ids[slot.index]
                    = existing.payload_hash_key_id
              AND exact_payload_hashes[slot.index] = existing.payload_hash
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'uq_appeal_receipt_identity',
                MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.organization_id IS DISTINCT FROM exact_organization_id
           OR existing.http_method <> expected_method
           OR existing.canonical_path <> expected_path
           OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
           OR (
                exact_command_name <> 'OPEN_APPEAL'
                AND existing.target_appeal_id <> exact_target_appeal_id
           )
           OR existing.canonicalization_version <> 'appeal-command-json-v1'
           OR existing.retain_until <= evaluated_time
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'APPEAL_RECEIPT_REPLAY_INVALID';
        END IF;
        IF existing.status = 'IN_PROGRESS' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'COMMAND_IN_PROGRESS';
        ELSIF existing.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '40003', MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
        END IF;
        RETURN QUERY SELECT true, existing.receipt_id, existing.safe_response;
        RETURN;
    END IF;

    PERFORM set_config(
        'app.appeal_id', exact_target_appeal_id::text, true
    );
    INSERT INTO trust.appeal_command_receipts (
        receipt_id, principal_id, organization_id, command_name,
        idempotency_key_digest_key_id, idempotency_key_digest,
        payload_hash_key_id, payload_hash, canonicalization_version,
        http_method, canonical_path, if_match_version, target_appeal_id,
        status, retain_until, created_at
    ) VALUES (
        exact_receipt_id, exact_actor_user_id, exact_organization_id,
        exact_command_name, exact_idempotency_key_digest_key_ids[1],
        exact_idempotency_key_digests[1], exact_payload_hash_key_ids[1],
        exact_payload_hashes[1], 'appeal-command-json-v1', expected_method,
        expected_path, exact_if_match_version, exact_target_appeal_id,
        'IN_PROGRESS', evaluated_time + interval '90 days', evaluated_time
    );
    RETURN QUERY SELECT false, exact_receipt_id, NULL::jsonb;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION USING
        ERRCODE = '55000', MESSAGE = 'APPEAL_RECEIPT_KEY_POLICY_UNAVAILABLE';
END
$function$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA trust FROM PUBLIC;

REVOKE ALL ON FUNCTION trust_api.open_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
    text[], bytea[], text[], bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.save_appeal_draft_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[], text, bytea, text[], text, uuid[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.submit_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    integer, text[], bytea[], text[], bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.claim_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.release_appeal_assignment_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, text,
    text[], bytea[], text[], bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.save_appeal_review_draft_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[], text, bytea, jsonb, text[], text[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.decide_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    integer, text, text[], bytea[], text[], bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.read_completed_appeal_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint,
    text[], bytea[], text[], bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.store_appeal_restricted_text_v1(
    uuid, uuid, uuid, uuid, text, text[], text[], bytea[], bytea, text,
    bytea, bytea, bytea, text[], bytea[], text, timestamptz, uuid, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.find_own_appeal_by_source_v1(
    uuid, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.read_own_appeal_v1(
    uuid, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.list_appeal_queue_v1(
    uuid, uuid, integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION trust_api.read_assigned_appeal_v1(
    uuid, uuid, uuid
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION trust_api.open_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
    text[], bytea[], text[], bytea[]
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.save_appeal_draft_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[], text, bytea, text[], text, uuid[]
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.submit_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    integer, text[], bytea[], text[], bytea[]
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.claim_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[]
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.release_appeal_assignment_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, text,
    text[], bytea[], text[], bytea[]
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.save_appeal_review_draft_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[], text, bytea, jsonb, text[], text[]
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.decide_appeal_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint,
    integer, text, text[], bytea[], text[], bytea[]
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.read_completed_appeal_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint,
    text[], bytea[], text[], bytea[]
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.read_completed_appeal_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint,
    text[], bytea[], text[], bytea[]
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.store_appeal_restricted_text_v1(
    uuid, uuid, uuid, uuid, text, text[], text[], bytea[], bytea, text,
    bytea, bytea, bytea, text[], bytea[], text, timestamptz, uuid, bigint
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.store_appeal_restricted_text_v1(
    uuid, uuid, uuid, uuid, text, text[], text[], bytea[], bytea, text,
    bytea, bytea, bytea, text[], bytea[], text, timestamptz, uuid, bigint
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.find_own_appeal_by_source_v1(
    uuid, uuid, uuid, uuid
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.read_own_appeal_v1(
    uuid, uuid, uuid, uuid
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.list_appeal_queue_v1(
    uuid, uuid, integer
) TO trust_appeal;
GRANT EXECUTE ON FUNCTION trust_api.read_assigned_appeal_v1(
    uuid, uuid, uuid
) TO trust_appeal;
