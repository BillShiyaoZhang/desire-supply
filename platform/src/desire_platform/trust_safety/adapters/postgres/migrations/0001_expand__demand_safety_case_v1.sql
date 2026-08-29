-- Independent Trust PostgreSQL 18 storage boundary.
-- Runtime roles are deployment-owned.  They receive only fixed trust_api
-- function EXECUTE grants; all protected relations remain behind FORCE RLS.

DO $roles$
DECLARE
    required_role text;
BEGIN
    FOREACH required_role IN ARRAY ARRAY[
        'schema_owner',
        'trust_schema_owner',
        'trust_migration_runner',
        'trust_self',
        'trust_officer',
        'trust_appeal',
        'trust_decision'
    ]::text[]
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_roles
            WHERE rolname = required_role
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'TRUST_MIGRATION_ROLE_UNAVAILABLE';
        END IF;
    END LOOP;
END
$roles$;

CREATE SCHEMA trust AUTHORIZATION trust_schema_owner;
CREATE SCHEMA trust_meta AUTHORIZATION trust_schema_owner;
CREATE SCHEMA trust_api AUTHORIZATION trust_schema_owner;
REVOKE ALL ON SCHEMA trust, trust_meta, trust_api FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE trust_schema_owner IN SCHEMA trust
REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE trust_schema_owner IN SCHEMA trust
REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE trust_schema_owner IN SCHEMA trust_api
REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE trust_meta.schema_migrations (
    component varchar(32) NOT NULL,
    version integer NOT NULL,
    phase varchar(16) NOT NULL,
    name varchar(128) NOT NULL,
    checksum_sha256 bytea NOT NULL,
    manifest_sha256 bytea NOT NULL,
    runner_version varchar(96) NOT NULL,
    applied_at timestamptz NOT NULL,
    CONSTRAINT pk_trust_schema_migrations PRIMARY KEY (component, version),
    CONSTRAINT ck_trust_migration_component CHECK (component = 'trust'),
    CONSTRAINT ck_trust_migration_phase CHECK (
        phase IN ('expand', 'migrate', 'contract')
    ),
    CONSTRAINT ck_trust_migration_hashes CHECK (
        octet_length(checksum_sha256) = 32
        AND octet_length(manifest_sha256) = 32
    )
);

CREATE TABLE trust_meta.schema_contracts (
    singleton_key boolean PRIMARY KEY,
    schema_head_version integer NOT NULL,
    min_app_compatible_version integer NOT NULL,
    max_app_compatible_version integer NOT NULL,
    required_iam_schema_version integer NOT NULL,
    required_demand_schema_version integer NOT NULL,
    required_iam_contract_sha256 bytea NOT NULL,
    required_demand_contract_sha256 bytea NOT NULL,
    api_contract_sha256 bytea NOT NULL,
    event_contract_sha256 bytea NOT NULL,
    report_contract_sha256 bytea NOT NULL,
    triage_contract_sha256 bytea NOT NULL,
    combined_contract_sha256 bytea NOT NULL,
    migration_manifest_sha256 bytea NOT NULL,
    generated_at timestamptz NOT NULL,
    CONSTRAINT ck_trust_schema_contract_singleton CHECK (singleton_key),
    CONSTRAINT ck_trust_schema_contract_versions CHECK (
        schema_head_version = 1
        AND min_app_compatible_version = 1
        AND max_app_compatible_version = 1
        AND required_iam_schema_version = 36
        AND required_demand_schema_version = 8
    ),
    CONSTRAINT ck_trust_schema_contract_hashes CHECK (
        octet_length(required_iam_contract_sha256) = 32
        AND octet_length(required_demand_contract_sha256) = 32
        AND octet_length(api_contract_sha256) = 32
        AND octet_length(event_contract_sha256) = 32
        AND octet_length(report_contract_sha256) = 32
        AND octet_length(triage_contract_sha256) = 32
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
        AND combined_contract_sha256 = sha256(convert_to(concat_ws(
            E'\x1f',
            'desire:trust:combined-contract:v1',
            encode(required_iam_contract_sha256, 'hex'),
            encode(required_demand_contract_sha256, 'hex'),
            encode(api_contract_sha256, 'hex'),
            encode(event_contract_sha256, 'hex'),
            encode(report_contract_sha256, 'hex'),
            encode(triage_contract_sha256, 'hex'),
            encode(migration_manifest_sha256, 'hex')
        ), 'UTF8'))
    )
);

CREATE VIEW trust.schema_compatibility AS
SELECT
    'trust'::text AS component,
    COALESCE((
        SELECT max(version)
        FROM trust_meta.schema_migrations
        WHERE component = 'trust'
    ), 0)::integer AS current_schema_version,
    schema_head_version,
    min_app_compatible_version,
    max_app_compatible_version,
    required_iam_schema_version,
    required_demand_schema_version,
    required_iam_contract_sha256,
    required_demand_contract_sha256,
    combined_contract_sha256,
    migration_manifest_sha256
FROM trust_meta.schema_contracts
WHERE singleton_key;

CREATE FUNCTION trust.jsonb_has_exact_keys(
    document jsonb,
    expected_keys text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT
        jsonb_typeof(document) = 'object'
        AND expected_keys IS NOT NULL
        AND cardinality(expected_keys) > 0
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(expected_keys) AS expected(key)
            WHERE key IS NULL OR key = ''
        )
        AND (
            SELECT array_agg(key ORDER BY key COLLATE "C")
            FROM jsonb_object_keys(document) AS actual(key)
        ) = (
            SELECT array_agg(key ORDER BY key COLLATE "C")
            FROM unnest(expected_keys) AS expected(key)
        )
$function$;

CREATE FUNCTION trust.canonical_code_array_v1(
    values_to_check text[],
    minimum_count integer,
    maximum_count integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT
        values_to_check IS NOT NULL
        AND (
            cardinality(values_to_check) = 0
            OR array_ndims(values_to_check) = 1
        )
        AND cardinality(values_to_check) BETWEEN minimum_count AND maximum_count
        AND minimum_count >= 0
        AND maximum_count >= minimum_count
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(values_to_check) AS item(value)
            WHERE value IS NULL OR value !~ '^[A-Z][A-Z0-9_]{1,63}$'
        )
        AND (
            cardinality(values_to_check) = 0
            OR (
                SELECT array_agg(value ORDER BY value COLLATE "C")
                FROM unnest(values_to_check) AS item(value)
            ) = values_to_check
        )
        AND (
            SELECT count(DISTINCT value) = count(*)
            FROM unnest(values_to_check) AS item(value)
        )
$function$;

CREATE FUNCTION trust.canonical_key_array_v1(
    values_to_check text[],
    maximum_count integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT
        values_to_check IS NOT NULL
        AND array_ndims(values_to_check) = 1
        AND cardinality(values_to_check) BETWEEN 1 AND maximum_count
        AND maximum_count >= 1
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(values_to_check) AS item(value)
            WHERE value IS NULL
               OR length(value) NOT BETWEEN 3 AND 128
               OR value !~ '^[a-z0-9][a-z0-9-]*$'
        )
        AND (
            SELECT array_agg(value ORDER BY value COLLATE "C")
            FROM unnest(values_to_check) AS item(value)
        ) = values_to_check
        AND (
            SELECT count(DISTINCT value) = count(*)
            FROM unnest(values_to_check) AS item(value)
        )
$function$;

CREATE FUNCTION trust.canonical_uuid_array_v1(
    values_to_check uuid[],
    minimum_count integer,
    maximum_count integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT
        values_to_check IS NOT NULL
        AND array_ndims(values_to_check) = 1
        AND cardinality(values_to_check) BETWEEN minimum_count AND maximum_count
        AND minimum_count >= 0
        AND maximum_count >= minimum_count
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(values_to_check) AS item(value)
            WHERE value IS NULL OR value = '00000000-0000-0000-0000-000000000000'::uuid
        )
        AND (
            SELECT array_agg(value ORDER BY value)
            FROM unnest(values_to_check) AS item(value)
        ) = values_to_check
        AND (
            SELECT count(DISTINCT value) = count(*)
            FROM unnest(values_to_check) AS item(value)
        )
$function$;

CREATE FUNCTION trust.active_first_key_array_v1(
    values_to_check text[],
    active_value text,
    maximum_count integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT
        values_to_check IS NOT NULL
        AND array_ndims(values_to_check) = 1
        AND cardinality(values_to_check) BETWEEN 1 AND maximum_count
        AND maximum_count BETWEEN 1 AND 4
        AND values_to_check[1] = active_value
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(values_to_check) AS item(value)
            WHERE value IS NULL
               OR length(value) NOT BETWEEN 3 AND 128
               OR value !~ '^[a-z0-9][a-z0-9-]*$'
        )
        AND (
            SELECT count(DISTINCT value) = count(*)
            FROM unnest(values_to_check) AS item(value)
        )
$function$;

CREATE TABLE trust.reports (
    report_id uuid PRIMARY KEY,
    case_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    demand_version_no integer NOT NULL,
    demand_aggregate_version bigint NOT NULL,
    demand_status varchar(32) NOT NULL,
    demand_content_sha256 bytea NOT NULL,
    demand_owner_user_id uuid NOT NULL,
    reportable_until timestamptz NOT NULL,
    reporter_user_id uuid NOT NULL,
    reporter_membership_id uuid NOT NULL,
    reporter_role_grant_id uuid NOT NULL,
    reporter_role_grant_version bigint NOT NULL,
    reporter_authority_marker_sha256 bytea NOT NULL,
    reporter_party_marker_sha256 bytea NOT NULL,
    target_marker_sha256 bytea NOT NULL,
    category varchar(64) NOT NULL,
    incident_started_at timestamptz NOT NULL,
    incident_ended_at timestamptz NULL,
    impact_codes text[] NOT NULL,
    evidence_reference_ids uuid[] NOT NULL,
    requested_protection_codes text[] NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT uq_trust_report_org_id UNIQUE (organization_id, report_id),
    CONSTRAINT uq_trust_report_case UNIQUE (case_id),
    CONSTRAINT uq_trust_report_case_target UNIQUE (
        organization_id,
        report_id,
        case_id,
        demand_id,
        demand_version_id,
        reporter_user_id
    ),
    CONSTRAINT ck_trust_report_versions CHECK (
        demand_version_no >= 1
        AND demand_aggregate_version >= 1
        AND reporter_role_grant_version >= 1
    ),
    CONSTRAINT ck_trust_report_target_hashes CHECK (
        octet_length(demand_content_sha256) = 32
        AND octet_length(reporter_authority_marker_sha256) = 32
        AND octet_length(reporter_party_marker_sha256) = 32
        AND octet_length(target_marker_sha256) = 32
    ),
    CONSTRAINT ck_trust_report_category CHECK (
        category IN (
            'DATA_EXPOSURE',
            'FRAUD_RISK',
            'HARASSMENT',
            'RETALIATION',
            'WORKFLOW_INTEGRITY'
        )
    ),
    CONSTRAINT ck_trust_report_facts CHECK (
        trust.canonical_code_array_v1(impact_codes, 1, 16)
        AND impact_codes <@ ARRAY[
            'PARTICIPANT_SAFETY_RISK',
            'RETALIATION_RISK',
            'SYNTHETIC_DATA_DISCLOSED',
            'SYNTHETIC_FINANCIAL_RISK',
            'WORKFLOW_INTEGRITY_RISK'
        ]::text[]
        AND trust.canonical_uuid_array_v1(evidence_reference_ids, 1, 32)
        AND trust.canonical_code_array_v1(
            requested_protection_codes,
            1,
            3
        )
        AND requested_protection_codes <@ ARRAY[
            'PAUSE_MATCHING',
            'PAUSE_SUBMISSION',
            'PAUSE_VERIFICATION'
        ]::text[]
    ),
    CONSTRAINT ck_trust_report_time CHECK (
        incident_started_at <= created_at
        AND (
            incident_ended_at IS NULL
            OR (
                incident_ended_at >= incident_started_at
                AND incident_ended_at <= created_at
            )
        )
        AND reportable_until > created_at
    )
);

CREATE INDEX ix_trust_reports_reporter
ON trust.reports (organization_id, reporter_user_id, created_at DESC, report_id);

CREATE TABLE trust.cases (
    case_id uuid PRIMARY KEY,
    report_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    reporter_user_id uuid NOT NULL,
    status varchar(32) NOT NULL,
    aggregate_version bigint NOT NULL,
    assigned_officer_user_id uuid NULL,
    assignment_id uuid NULL,
    assignment_expires_at timestamptz NULL,
    current_triage_draft_version integer NULL,
    current_triage_version integer NULL,
    outcome_version_id uuid NULL,
    opened_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_trust_case_org_id UNIQUE (organization_id, case_id),
    CONSTRAINT uq_trust_case_report UNIQUE (report_id),
    CONSTRAINT fk_trust_case_report_exact FOREIGN KEY (
        organization_id,
        report_id,
        case_id,
        demand_id,
        demand_version_id,
        reporter_user_id
    ) REFERENCES trust.reports (
        organization_id,
        report_id,
        case_id,
        demand_id,
        demand_version_id,
        reporter_user_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_trust_case_status CHECK (
        status IN (
            'OPEN',
            'TRIAGING',
            'IN_REVIEW',
            'DECIDED',
            'APPEAL_PENDING',
            'RESOLVED',
            'DISMISSED'
        )
    ),
    CONSTRAINT ck_trust_case_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_trust_case_assignment_shape CHECK (
        (
            assigned_officer_user_id IS NULL
            AND assignment_id IS NULL
            AND assignment_expires_at IS NULL
        )
        OR (
            assigned_officer_user_id IS NOT NULL
            AND assignment_id IS NOT NULL
            AND assignment_expires_at IS NOT NULL
        )
    ),
    CONSTRAINT ck_trust_case_status_shape CHECK (
        (status = 'OPEN' AND assignment_id IS NULL)
        OR (status IN ('TRIAGING', 'IN_REVIEW') AND assignment_id IS NOT NULL)
        OR status IN ('DECIDED', 'APPEAL_PENDING', 'RESOLVED', 'DISMISSED')
    ),
    CONSTRAINT ck_trust_case_triage_shape CHECK (
        (current_triage_draft_version IS NULL OR current_triage_draft_version >= 1)
        AND (current_triage_version IS NULL OR current_triage_version >= 1)
        AND (
            current_triage_version IS NULL
            OR current_triage_draft_version IS NOT NULL
        )
    ),
    CONSTRAINT ck_trust_case_outcome_shape CHECK (
        (status = 'DECIDED' AND outcome_version_id IS NOT NULL)
        OR (status <> 'DECIDED')
    ),
    CONSTRAINT ck_trust_case_time CHECK (updated_at >= opened_at)
);

ALTER TABLE trust.reports
ADD CONSTRAINT fk_trust_report_case
FOREIGN KEY (organization_id, case_id)
REFERENCES trust.cases (organization_id, case_id)
DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX ix_trust_cases_queue
ON trust.cases (status, opened_at, case_id)
WHERE status = 'OPEN';

CREATE INDEX ix_trust_cases_target
ON trust.cases (organization_id, demand_id, demand_version_id, case_id);

CREATE TABLE trust.case_assignments (
    assignment_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    assignment_purpose_code varchar(32) NOT NULL,
    hold_id uuid NULL,
    officer_user_id uuid NOT NULL,
    excluded_officer_user_id uuid NULL,
    duty_grant_id uuid NOT NULL,
    duty_grant_version bigint NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    conflict_attestation_sha256 bytea NOT NULL,
    conflict_evaluated_at timestamptz NOT NULL,
    conflict_valid_until timestamptz NOT NULL,
    assigned_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT uq_trust_assignment_case_id UNIQUE (case_id, assignment_id),
    CONSTRAINT fk_trust_assignment_case FOREIGN KEY (organization_id, case_id)
        REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT ck_trust_assignment_purpose CHECK (
        (
            assignment_purpose_code = 'CASE_TRIAGE'
            AND hold_id IS NULL
            AND excluded_officer_user_id IS NULL
        )
        OR (
            assignment_purpose_code = 'HOLD_RELEASE'
            AND hold_id IS NOT NULL
            AND excluded_officer_user_id IS NOT NULL
            AND excluded_officer_user_id <> officer_user_id
        )
    ),
    CONSTRAINT ck_trust_assignment_facts CHECK (
        duty_grant_version >= 1
        AND octet_length(authority_marker_sha256) = 32
        AND octet_length(conflict_attestation_sha256) = 32
    ),
    CONSTRAINT ck_trust_assignment_time CHECK (
        conflict_evaluated_at <= assigned_at
        AND conflict_valid_until > assigned_at
        AND expires_at > assigned_at
    )
);

CREATE INDEX ix_trust_assignments_officer
ON trust.case_assignments (
    organization_id,
    officer_user_id,
    assignment_purpose_code,
    expires_at,
    assignment_id
);

CREATE TABLE trust.restricted_text_blobs (
    sealed_note_reference varchar(288) PRIMARY KEY,
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    purpose_code varchar(64) NOT NULL,
    plaintext_hmac_sha256 bytea NOT NULL,
    envelope_sha256 bytea NOT NULL,
    encryption_key_id varchar(128) NOT NULL,
    encryption_nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    aad_sha256 bytea NOT NULL,
    idempotency_key_digest_key_id varchar(128) NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    retention_class varchar(64) NOT NULL,
    sealed_at timestamptz NOT NULL,
    retain_until timestamptz NOT NULL,
    CONSTRAINT uq_trust_restricted_text_exact UNIQUE (
        organization_id,
        case_id,
        actor_user_id,
        sealed_note_reference,
        envelope_sha256
    ),
    CONSTRAINT uq_trust_restricted_text_idempotency UNIQUE (
        actor_user_id,
        case_id,
        purpose_code,
        idempotency_key_digest_key_id,
        idempotency_key_digest
    ),
    CONSTRAINT fk_trust_restricted_text_case FOREIGN KEY (
        organization_id,
        case_id
    ) REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT ck_trust_restricted_text_reference CHECK (
        sealed_note_reference
            ~ '^sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}$'
    ),
    CONSTRAINT ck_trust_restricted_text_codes CHECK (
        purpose_code = 'TRIAGE_NOTE'
        AND retention_class = 'TRUST_CASE_NOTE'
        AND encryption_key_id ~ '^[a-z0-9][a-z0-9-]{2,127}$'
        AND idempotency_key_digest_key_id
            ~ '^[a-z0-9][a-z0-9-]{2,127}$'
        AND encryption_key_id <> idempotency_key_digest_key_id
    ),
    CONSTRAINT ck_trust_restricted_text_crypto CHECK (
        octet_length(plaintext_hmac_sha256) = 32
        AND octet_length(envelope_sha256) = 32
        AND octet_length(encryption_nonce) = 12
        AND octet_length(ciphertext) BETWEEN 17 AND 16384
        AND octet_length(aad_sha256) = 32
        AND octet_length(idempotency_key_digest) = 32
    ),
    CONSTRAINT ck_trust_restricted_text_retention CHECK (
        retain_until > sealed_at
        AND retain_until <= sealed_at + interval '10 years'
    )
);

CREATE INDEX ix_trust_restricted_text_retention
ON trust.restricted_text_blobs (retain_until, sealed_note_reference);

CREATE TABLE trust.case_assignment_releases (
    assignment_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    released_by_user_id uuid NOT NULL,
    reason_code varchar(64) NOT NULL,
    released_at timestamptz NOT NULL,
    CONSTRAINT fk_trust_assignment_release_assignment FOREIGN KEY (
        case_id,
        assignment_id
    ) REFERENCES trust.case_assignments (case_id, assignment_id),
    CONSTRAINT fk_trust_assignment_release_case FOREIGN KEY (
        organization_id,
        case_id
    ) REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT ck_trust_assignment_release_reason CHECK (
        reason_code IN (
            'CONFLICT_DECLARED',
            'WORKLOAD_RELEASE',
            'ASSIGNMENT_EXPIRED',
            'HOLD_RELEASE_COMPLETED',
            'HOLD_RELEASE_REASSIGNED'
        )
    )
);

CREATE TABLE trust.triage_drafts (
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    draft_version integer NOT NULL,
    assignment_id uuid NOT NULL,
    priority_code varchar(16) NOT NULL,
    jurisdiction_code varchar(64) NOT NULL,
    severity_code varchar(16) NOT NULL,
    issue_codes text[] NOT NULL,
    investigation_step_codes text[] NOT NULL,
    proposed_hold_actions text[] NOT NULL,
    proposed_hold_ttl_minutes integer NOT NULL,
    sealed_note_reference varchar(288) NOT NULL,
    sealed_note_sha256 bytea NOT NULL,
    content_sha256 bytea NOT NULL,
    edited_by_user_id uuid NOT NULL,
    edited_at timestamptz NOT NULL,
    CONSTRAINT pk_trust_triage_drafts PRIMARY KEY (case_id, draft_version),
    CONSTRAINT fk_trust_triage_draft_case FOREIGN KEY (organization_id, case_id)
        REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT fk_trust_triage_draft_assignment FOREIGN KEY (
        case_id,
        assignment_id
    ) REFERENCES trust.case_assignments (case_id, assignment_id),
    CONSTRAINT fk_trust_triage_draft_restricted_text FOREIGN KEY (
        organization_id,
        case_id,
        edited_by_user_id,
        sealed_note_reference,
        sealed_note_sha256
    ) REFERENCES trust.restricted_text_blobs (
        organization_id,
        case_id,
        actor_user_id,
        sealed_note_reference,
        envelope_sha256
    ),
    CONSTRAINT ck_trust_triage_draft_version CHECK (draft_version >= 1),
    CONSTRAINT ck_trust_triage_draft_codes CHECK (
        priority_code IN ('P0', 'P1', 'P2', 'P3')
        AND jurisdiction_code IN (
            'PLATFORM_INTERNAL',
            'ORGANIZATION_POLICY',
            'LEGAL_REVIEW_REQUIRED'
        )
        AND severity_code IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        AND trust.canonical_code_array_v1(issue_codes, 1, 16)
        AND issue_codes <@ ARRAY[
            'DATA_HANDLING_GAP',
            'FRAUD_INDICATOR',
            'HARASSMENT_INDICATOR',
            'RETALIATION_INDICATOR',
            'SCOPE_DISCLOSURE_RISK',
            'WORKFLOW_INTEGRITY_GAP'
        ]::text[]
        AND trust.canonical_code_array_v1(investigation_step_codes, 1, 16)
        AND investigation_step_codes <@ ARRAY[
            'CHECK_ACCESS_SCOPE',
            'CHECK_DEMAND_VERSION',
            'CHECK_POLICY_REQUIREMENTS',
            'CHECK_SYNTHETIC_EVIDENCE',
            'REQUEST_PARTY_CLARIFICATION'
        ]::text[]
        AND trust.canonical_code_array_v1(proposed_hold_actions, 1, 3)
        AND proposed_hold_actions <@ ARRAY[
            'REQUEST_MATCHING',
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND'
        ]::text[]
    ),
    CONSTRAINT ck_trust_triage_draft_ttl CHECK (
        proposed_hold_ttl_minutes BETWEEN 15 AND 10080
    ),
    CONSTRAINT ck_trust_triage_draft_sealed CHECK (
        sealed_note_reference ~ '^sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}$'
        AND octet_length(sealed_note_sha256) = 32
        AND octet_length(content_sha256) = 32
    )
);

CREATE TABLE trust.triage_versions (
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    triage_version integer NOT NULL,
    source_draft_version integer NOT NULL,
    assignment_id uuid NOT NULL,
    priority_code varchar(16) NOT NULL,
    jurisdiction_code varchar(64) NOT NULL,
    severity_code varchar(16) NOT NULL,
    issue_codes text[] NOT NULL,
    investigation_step_codes text[] NOT NULL,
    proposed_hold_actions text[] NOT NULL,
    proposed_hold_ttl_minutes integer NOT NULL,
    sealed_note_reference varchar(288) NOT NULL,
    sealed_note_sha256 bytea NOT NULL,
    content_sha256 bytea NOT NULL,
    published_by_user_id uuid NOT NULL,
    published_at timestamptz NOT NULL,
    CONSTRAINT pk_trust_triage_versions PRIMARY KEY (case_id, triage_version),
    CONSTRAINT fk_trust_triage_version_case FOREIGN KEY (organization_id, case_id)
        REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT fk_trust_triage_version_source FOREIGN KEY (
        case_id,
        source_draft_version
    ) REFERENCES trust.triage_drafts (case_id, draft_version),
    CONSTRAINT fk_trust_triage_version_assignment FOREIGN KEY (
        case_id,
        assignment_id
    ) REFERENCES trust.case_assignments (case_id, assignment_id),
    CONSTRAINT ck_trust_triage_version_number CHECK (
        triage_version >= 1 AND source_draft_version >= 1
    ),
    CONSTRAINT ck_trust_triage_version_codes CHECK (
        priority_code IN ('P0', 'P1', 'P2', 'P3')
        AND jurisdiction_code IN (
            'PLATFORM_INTERNAL',
            'ORGANIZATION_POLICY',
            'LEGAL_REVIEW_REQUIRED'
        )
        AND severity_code IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        AND trust.canonical_code_array_v1(issue_codes, 1, 16)
        AND issue_codes <@ ARRAY[
            'DATA_HANDLING_GAP',
            'FRAUD_INDICATOR',
            'HARASSMENT_INDICATOR',
            'RETALIATION_INDICATOR',
            'SCOPE_DISCLOSURE_RISK',
            'WORKFLOW_INTEGRITY_GAP'
        ]::text[]
        AND trust.canonical_code_array_v1(investigation_step_codes, 1, 16)
        AND investigation_step_codes <@ ARRAY[
            'CHECK_ACCESS_SCOPE',
            'CHECK_DEMAND_VERSION',
            'CHECK_POLICY_REQUIREMENTS',
            'CHECK_SYNTHETIC_EVIDENCE',
            'REQUEST_PARTY_CLARIFICATION'
        ]::text[]
        AND trust.canonical_code_array_v1(proposed_hold_actions, 1, 3)
        AND proposed_hold_actions <@ ARRAY[
            'REQUEST_MATCHING',
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND'
        ]::text[]
    ),
    CONSTRAINT ck_trust_triage_version_ttl CHECK (
        proposed_hold_ttl_minutes BETWEEN 15 AND 10080
    ),
    CONSTRAINT ck_trust_triage_version_sealed CHECK (
        sealed_note_reference ~ '^sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}$'
        AND octet_length(sealed_note_sha256) = 32
        AND octet_length(content_sha256) = 32
    )
);

CREATE TABLE trust.safety_holds (
    hold_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    triage_version integer NOT NULL,
    action_codes text[] NOT NULL,
    reason_code varchar(64) NOT NULL,
    status varchar(16) NOT NULL,
    policy_version varchar(128) NOT NULL,
    issued_by_user_id uuid NOT NULL,
    issue_assignment_id uuid NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    aggregate_version bigint NOT NULL,
    requires_independent_release boolean NOT NULL,
    release_assignment_id uuid NULL,
    released_at timestamptz NULL,
    released_by_user_id uuid NULL,
    release_reason_code varchar(64) NULL,
    CONSTRAINT uq_trust_hold_case_id UNIQUE (case_id, hold_id),
    CONSTRAINT fk_trust_hold_case FOREIGN KEY (organization_id, case_id)
        REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT fk_trust_hold_triage FOREIGN KEY (case_id, triage_version)
        REFERENCES trust.triage_versions (case_id, triage_version),
    CONSTRAINT fk_trust_hold_issue_assignment FOREIGN KEY (
        case_id,
        issue_assignment_id
    ) REFERENCES trust.case_assignments (case_id, assignment_id),
    CONSTRAINT ck_trust_hold_codes CHECK (
        trust.canonical_code_array_v1(action_codes, 1, 3)
        AND action_codes <@ ARRAY[
            'REQUEST_MATCHING',
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND'
        ]::text[]
        AND reason_code IN (
            'PARTICIPANT_SAFETY_RISK',
            'RETALIATION_RISK',
            'SYNTHETIC_DATA_EXPOSURE_RISK',
            'WORKFLOW_INTEGRITY_RISK'
        )
        AND policy_version = 'trust-demand-hold-v1'
        AND requires_independent_release = (
            reason_code IN (
                'PARTICIPANT_SAFETY_RISK',
                'RETALIATION_RISK'
            )
        )
    ),
    CONSTRAINT ck_trust_hold_status CHECK (
        status IN ('ACTIVE', 'RELEASED', 'EXPIRED')
    ),
    CONSTRAINT ck_trust_hold_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_trust_hold_time CHECK (
        expires_at > effective_at
        AND expires_at <= effective_at + interval '365 days'
    ),
    CONSTRAINT ck_trust_hold_release_shape CHECK (
        (
            status = 'ACTIVE'
            AND released_at IS NULL
            AND released_by_user_id IS NULL
            AND release_reason_code IS NULL
            AND (
                release_assignment_id IS NULL
                OR requires_independent_release
            )
        )
        OR (
            status = 'RELEASED'
            AND released_at IS NOT NULL
            AND released_by_user_id IS NOT NULL
            AND release_reason_code IS NOT NULL
            AND released_at >= effective_at
            AND (
                NOT requires_independent_release
                OR (
                    release_assignment_id IS NOT NULL
                    AND released_by_user_id <> issued_by_user_id
                )
            )
        )
        OR (
            status = 'EXPIRED'
            AND release_assignment_id IS NULL
            AND released_at IS NULL
            AND released_by_user_id IS NULL
            AND release_reason_code IS NULL
        )
    )
);

ALTER TABLE trust.case_assignments
ADD CONSTRAINT fk_trust_assignment_hold
FOREIGN KEY (case_id, hold_id)
REFERENCES trust.safety_holds (case_id, hold_id)
DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE trust.safety_holds
ADD CONSTRAINT fk_trust_hold_release_assignment
FOREIGN KEY (case_id, release_assignment_id)
REFERENCES trust.case_assignments (case_id, assignment_id)
DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX ix_trust_active_hold_evaluation
ON trust.safety_holds (
    organization_id,
    demand_id,
    demand_version_id,
    expires_at,
    hold_id
)
WHERE status = 'ACTIVE';

CREATE INDEX ix_trust_hold_actions
ON trust.safety_holds USING gin (action_codes);

CREATE TABLE trust.case_outcome_versions (
    outcome_version_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    outcome_version integer NOT NULL,
    outcome_code varchar(64) NOT NULL,
    reason_codes text[] NOT NULL,
    action_codes text[] NOT NULL,
    evidence_packet_version_id uuid NOT NULL,
    evidence_packet_digest bytea NOT NULL,
    source_digest bytea NOT NULL,
    redaction_profile_code varchar(64) NOT NULL,
    appeal_eligible boolean NOT NULL,
    appeal_eligibility_code varchar(64) NOT NULL,
    appeal_deadline timestamptz NULL,
    policy_version varchar(128) NOT NULL,
    decided_by_user_id uuid NOT NULL,
    decision_assignment_id uuid NOT NULL,
    decided_at timestamptz NOT NULL,
    content_sha256 bytea NOT NULL,
    CONSTRAINT uq_trust_case_outcome_version UNIQUE (case_id, outcome_version),
    CONSTRAINT uq_trust_case_outcome_case_id UNIQUE (case_id, outcome_version_id),
    CONSTRAINT fk_trust_outcome_case FOREIGN KEY (organization_id, case_id)
        REFERENCES trust.cases (organization_id, case_id),
    CONSTRAINT fk_trust_outcome_assignment FOREIGN KEY (
        case_id,
        decision_assignment_id
    ) REFERENCES trust.case_assignments (case_id, assignment_id),
    CONSTRAINT ck_trust_outcome_version CHECK (outcome_version >= 1),
    CONSTRAINT ck_trust_outcome_codes CHECK (
        outcome_code IN (
            'NO_ACTION',
            'PROTECTION_LIFTED',
            'PROTECTION_MAINTAINED',
            'PROTECTION_MODIFIED',
            'REMEDIATION_REQUIRED'
        )
        AND trust.canonical_code_array_v1(reason_codes, 1, 8)
        AND reason_codes <@ ARRAY[
            'INSUFFICIENT_VERIFIED_EVIDENCE',
            'NO_POLICY_BREACH',
            'POLICY_REQUIREMENT_NOT_MET',
            'PRECAUTIONARY_ACTION_REQUIRED',
            'RISK_MITIGATED'
        ]::text[]
        AND trust.canonical_code_array_v1(action_codes, 0, 3)
        AND action_codes <@ ARRAY[
            'REQUEST_MATCHING',
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND'
        ]::text[]
        AND (
            (
                outcome_code IN ('NO_ACTION', 'PROTECTION_LIFTED')
                AND cardinality(action_codes) = 0
            )
            OR (
                outcome_code NOT IN ('NO_ACTION', 'PROTECTION_LIFTED')
                AND cardinality(action_codes) >= 1
            )
        )
        AND redaction_profile_code IN (
            'OFFICER_RESTRICTED_V1',
            'PARTY_SAFE_V1'
        )
        AND appeal_eligibility_code IN ('ELIGIBLE', 'NOT_ELIGIBLE')
        AND policy_version = 'trust-case-outcome-v1'
    ),
    CONSTRAINT ck_trust_outcome_hashes CHECK (
        octet_length(evidence_packet_digest) = 32
        AND octet_length(source_digest) = 32
        AND octet_length(content_sha256) = 32
    ),
    CONSTRAINT ck_trust_outcome_appeal CHECK (
        (
            appeal_eligible
            AND appeal_eligibility_code = 'ELIGIBLE'
            AND appeal_deadline IS NOT NULL
            AND appeal_deadline > decided_at
        )
        OR (
            NOT appeal_eligible
            AND appeal_eligibility_code = 'NOT_ELIGIBLE'
            AND appeal_deadline IS NULL
        )
    )
);

ALTER TABLE trust.cases
ADD CONSTRAINT fk_trust_case_assignment
FOREIGN KEY (case_id, assignment_id)
REFERENCES trust.case_assignments (case_id, assignment_id)
DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE trust.cases
ADD CONSTRAINT fk_trust_case_current_draft
FOREIGN KEY (case_id, current_triage_draft_version)
REFERENCES trust.triage_drafts (case_id, draft_version)
DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE trust.cases
ADD CONSTRAINT fk_trust_case_current_triage
FOREIGN KEY (case_id, current_triage_version)
REFERENCES trust.triage_versions (case_id, triage_version)
DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE trust.cases
ADD CONSTRAINT fk_trust_case_outcome
FOREIGN KEY (case_id, outcome_version_id)
REFERENCES trust.case_outcome_versions (case_id, outcome_version_id)
DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE trust.receipt_key_policy (
    singleton_key boolean PRIMARY KEY,
    active_idempotency_key_id varchar(128) NOT NULL,
    active_payload_key_id varchar(128) NOT NULL,
    active_canonicalization_version varchar(64) NOT NULL,
    retained_idempotency_key_ids text[] NOT NULL,
    retained_payload_key_ids text[] NOT NULL,
    retained_canonicalization_versions text[] NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_trust_receipt_policy_singleton CHECK (singleton_key),
    CONSTRAINT ck_trust_receipt_policy_keys CHECK (
        active_idempotency_key_id <> active_payload_key_id
        AND trust.active_first_key_array_v1(
            retained_idempotency_key_ids,
            active_idempotency_key_id,
            4
        )
        AND trust.active_first_key_array_v1(
            retained_payload_key_ids,
            active_payload_key_id,
            4
        )
        AND trust.active_first_key_array_v1(
            retained_canonicalization_versions,
            active_canonicalization_version,
            4
        )
        AND NOT retained_idempotency_key_ids && retained_payload_key_ids
    )
);

CREATE TABLE trust.sealed_text_key_policy (
    singleton_key boolean PRIMARY KEY,
    active_encryption_key_id varchar(128) NOT NULL,
    retained_encryption_key_ids text[] NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_trust_sealed_text_policy_singleton CHECK (singleton_key),
    CONSTRAINT ck_trust_sealed_text_policy_keys CHECK (
        trust.active_first_key_array_v1(
            retained_encryption_key_ids,
            active_encryption_key_id,
            4
        )
    )
);

CREATE TABLE trust.command_receipts (
    receipt_id uuid PRIMARY KEY,
    principal_kind varchar(16) NOT NULL,
    principal_id uuid NOT NULL,
    organization_id uuid NULL,
    command_domain varchar(32) NOT NULL,
    command_name varchar(64) NOT NULL,
    command_version integer NOT NULL,
    idempotency_key_digest_key_id varchar(128) NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    payload_hash bytea NOT NULL,
    http_method varchar(8) NOT NULL,
    canonical_path varchar(512) NOT NULL,
    if_match_version bigint NULL,
    status varchar(16) NOT NULL,
    response_http_status integer NULL,
    response_schema_name varchar(96) NULL,
    response_schema_version integer NULL,
    response_entity_tag varchar(128) NULL,
    safe_response jsonb NULL,
    target_case_id uuid NULL,
    target_version bigint NULL,
    result_status varchar(32) NULL,
    event_types text[] NULL,
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_trust_receipt_identity UNIQUE (
        principal_kind,
        principal_id,
        command_domain,
        command_name,
        command_version,
        idempotency_key_digest_key_id,
        idempotency_key_digest
    ),
    CONSTRAINT ck_trust_receipt_hashes CHECK (
        octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
        AND idempotency_key_digest_key_id <> payload_hash_key_id
    ),
    CONSTRAINT ck_trust_receipt_transport CHECK (
        principal_kind = 'USER'
        AND command_domain = 'TRUST_SAFETY'
        AND command_version = 1
        AND http_method IN ('POST', 'PUT')
        AND canonical_path LIKE '/v1/app/trust/%'
        AND canonicalization_version = 'trust-command-json-v1'
        AND (if_match_version IS NULL OR if_match_version >= 1)
    ),
    CONSTRAINT ck_trust_receipt_time CHECK (
        retain_until > created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    ),
    CONSTRAINT ck_trust_receipt_shape CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
        AND (
            (
                status = 'IN_PROGRESS'
                AND response_http_status IS NULL
                AND response_schema_name IS NULL
                AND response_schema_version IS NULL
                AND response_entity_tag IS NULL
                AND safe_response IS NULL
                AND target_case_id IS NULL
                AND target_version IS NULL
                AND result_status IS NULL
                AND event_types IS NULL
                AND completed_at IS NULL
            )
            OR (
                status = 'COMPLETED'
                AND response_http_status BETWEEN 200 AND 299
                AND response_schema_name IS NOT NULL
                AND response_schema_version = 1
                AND response_entity_tag IS NOT NULL
                AND jsonb_typeof(safe_response) = 'object'
                AND trust.jsonb_has_exact_keys(
                    safe_response,
                    ARRAY[
                        'aggregate_version',
                        'assignment_id',
                        'case_id',
                        'case_status',
                        'completed_at',
                        'event_types',
                        'hold_id',
                        'hold_version',
                        'outcome_version_id',
                        'report_id',
                        'triage_draft_version',
                        'triage_version'
                    ]::text[]
                )
                AND NOT safe_response ?| ARRAY[
                    'reporter_user_id',
                    'demand_owner_user_id',
                    'session_id',
                    'authority_marker_sha256',
                    'reporter_party_marker_sha256',
                    'target_marker_sha256',
                    'sealed_note_reference',
                    'sealed_note_sha256'
                ]::text[]
                AND target_case_id IS NOT NULL
                AND target_version >= 1
                AND result_status IS NOT NULL
                AND cardinality(event_types) = 1
                AND event_types <@ ARRAY[
                    'SafetyHoldPlaced',
                    'SafetyHoldReleased',
                    'TrustCaseAssignmentReleased',
                    'TrustCaseClaimed',
                    'TrustCaseOutcomePublished',
                    'TrustHoldReleaseClaimed',
                    'TrustReportSubmitted',
                    'TrustTriageDraftSaved',
                    'TrustTriagePublished'
                ]::text[]
                AND completed_at IS NOT NULL
            )
        )
    )
);

CREATE INDEX ix_trust_receipts_retention
ON trust.command_receipts (retain_until, receipt_id);

INSERT INTO trust.receipt_key_policy (
    singleton_key,
    active_idempotency_key_id,
    active_payload_key_id,
    active_canonicalization_version,
    retained_idempotency_key_ids,
    retained_payload_key_ids,
    retained_canonicalization_versions,
    updated_at
) VALUES (
    true,
    'trust-idempotency-2026-01',
    'trust-payload-2026-01',
    'trust-command-json-v1',
    ARRAY['trust-idempotency-2026-01']::text[],
    ARRAY['trust-payload-2026-01']::text[],
    ARRAY['trust-command-json-v1']::text[],
    transaction_timestamp()
);

INSERT INTO trust.sealed_text_key_policy (
    singleton_key,
    active_encryption_key_id,
    retained_encryption_key_ids,
    updated_at
) VALUES (
    true,
    'trust-sealed-note-v1',
    ARRAY['trust-sealed-note-v1']::text[],
    transaction_timestamp()
);

CREATE FUNCTION trust.reject_immutable_row_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = TG_ARGV[0],
        MESSAGE = 'TRUST_IMMUTABLE_FACT';
END
$function$;

CREATE FUNCTION trust.guard_case_update_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_case_guard',
            MESSAGE = 'TRUST_CASE_MUTATION_INVALID';
    END IF;
    IF NEW.case_id <> OLD.case_id
       OR NEW.report_id <> OLD.report_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.demand_id <> OLD.demand_id
       OR NEW.demand_version_id <> OLD.demand_version_id
       OR NEW.reporter_user_id <> OLD.reporter_user_id
       OR NEW.opened_at <> OLD.opened_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.updated_at < OLD.updated_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_case_guard',
            MESSAGE = 'TRUST_CASE_MUTATION_INVALID';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.guard_hold_update_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_hold_guard',
            MESSAGE = 'TRUST_HOLD_MUTATION_INVALID';
    END IF;
    IF NEW.hold_id <> OLD.hold_id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.case_id <> OLD.case_id
       OR NEW.demand_id <> OLD.demand_id
       OR NEW.demand_version_id <> OLD.demand_version_id
       OR NEW.triage_version <> OLD.triage_version
       OR NEW.action_codes <> OLD.action_codes
       OR NEW.reason_code <> OLD.reason_code
       OR NEW.policy_version <> OLD.policy_version
       OR NEW.issued_by_user_id <> OLD.issued_by_user_id
       OR NEW.issue_assignment_id <> OLD.issue_assignment_id
       OR NEW.effective_at <> OLD.effective_at
       OR NEW.expires_at <> OLD.expires_at
       OR NEW.requires_independent_release <> OLD.requires_independent_release
       OR OLD.status <> 'ACTIVE'
       OR NEW.status NOT IN ('ACTIVE', 'RELEASED', 'EXPIRED')
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (
            NEW.status = 'ACTIVE'
            AND (
                NOT NEW.requires_independent_release
                OR NEW.release_assignment_id IS NULL
                OR NEW.release_assignment_id
                    IS NOT DISTINCT FROM OLD.release_assignment_id
            )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_hold_guard',
            MESSAGE = 'TRUST_HOLD_MUTATION_INVALID';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.guard_receipt_update_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_receipt_guard',
            MESSAGE = 'TRUST_RECEIPT_MUTATION_INVALID';
    END IF;
    IF OLD.status <> 'IN_PROGRESS'
       OR NEW.status <> 'COMPLETED'
       OR NEW.receipt_id <> OLD.receipt_id
       OR NEW.principal_kind <> OLD.principal_kind
       OR NEW.principal_id <> OLD.principal_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.command_domain <> OLD.command_domain
       OR NEW.command_name <> OLD.command_name
       OR NEW.command_version <> OLD.command_version
       OR NEW.idempotency_key_digest_key_id
            <> OLD.idempotency_key_digest_key_id
       OR NEW.idempotency_key_digest <> OLD.idempotency_key_digest
       OR NEW.payload_hash_key_id <> OLD.payload_hash_key_id
       OR NEW.canonicalization_version <> OLD.canonicalization_version
       OR NEW.payload_hash <> OLD.payload_hash
       OR NEW.http_method <> OLD.http_method
       OR NEW.canonical_path <> OLD.canonical_path
       OR NEW.if_match_version IS DISTINCT FROM OLD.if_match_version
       OR NEW.retain_until <> OLD.retain_until
       OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_receipt_guard',
            MESSAGE = 'TRUST_RECEIPT_MUTATION_INVALID';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.guard_receipt_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF TG_OP = 'DELETE' OR NOT NEW.singleton_key THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_receipt_policy_exact_one',
            MESSAGE = 'TRUST_RECEIPT_POLICY_REQUIRED';
    END IF;
    IF TG_OP = 'UPDATE' AND EXISTS (
        SELECT 1
        FROM trust.command_receipts AS receipt
        WHERE receipt.retain_until > transaction_timestamp()
          AND (
              NOT receipt.idempotency_key_digest_key_id
                    = ANY(NEW.retained_idempotency_key_ids)
              OR NOT receipt.payload_hash_key_id
                    = ANY(NEW.retained_payload_key_ids)
              OR NOT receipt.canonicalization_version
                    = ANY(NEW.retained_canonicalization_versions)
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_receipt_policy_retention',
            MESSAGE = 'TRUST_RECEIPT_KEY_STILL_RETAINED';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION trust.guard_sealed_text_key_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF TG_OP = 'DELETE' OR NOT NEW.singleton_key THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_sealed_text_policy_exact_one',
            MESSAGE = 'TRUST_SEALED_TEXT_POLICY_REQUIRED';
    END IF;
    IF TG_OP = 'UPDATE' AND EXISTS (
        SELECT 1
        FROM trust.restricted_text_blobs AS blob
        WHERE blob.retain_until > transaction_timestamp()
          AND NOT blob.encryption_key_id
                = ANY(NEW.retained_encryption_key_ids)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_trust_sealed_text_policy_retention',
            MESSAGE = 'TRUST_SEALED_TEXT_KEY_STILL_RETAINED';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER reports_immutable
BEFORE UPDATE OR DELETE ON trust.reports
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_reports_immutable'
);

CREATE TRIGGER case_assignments_immutable
BEFORE UPDATE OR DELETE ON trust.case_assignments
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_case_assignments_immutable'
);

CREATE TRIGGER restricted_text_blobs_immutable
BEFORE UPDATE OR DELETE ON trust.restricted_text_blobs
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_restricted_text_blobs_immutable'
);

CREATE TRIGGER case_assignment_releases_immutable
BEFORE UPDATE OR DELETE ON trust.case_assignment_releases
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_case_assignment_releases_immutable'
);

CREATE TRIGGER triage_drafts_immutable
BEFORE UPDATE OR DELETE ON trust.triage_drafts
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_triage_drafts_immutable'
);

CREATE TRIGGER triage_versions_immutable
BEFORE UPDATE OR DELETE ON trust.triage_versions
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_triage_versions_immutable'
);

CREATE TRIGGER case_outcome_versions_immutable
BEFORE UPDATE OR DELETE ON trust.case_outcome_versions
FOR EACH ROW EXECUTE FUNCTION trust.reject_immutable_row_v1(
    'trg_trust_case_outcome_versions_immutable'
);

CREATE TRIGGER cases_guard
BEFORE UPDATE OR DELETE ON trust.cases
FOR EACH ROW EXECUTE FUNCTION trust.guard_case_update_v1();

CREATE TRIGGER safety_holds_guard
BEFORE UPDATE OR DELETE ON trust.safety_holds
FOR EACH ROW EXECUTE FUNCTION trust.guard_hold_update_v1();

CREATE TRIGGER command_receipts_guard
BEFORE UPDATE OR DELETE ON trust.command_receipts
FOR EACH ROW EXECUTE FUNCTION trust.guard_receipt_update_v1();

CREATE TRIGGER receipt_key_policy_exact_one
BEFORE UPDATE OR DELETE ON trust.receipt_key_policy
FOR EACH ROW EXECUTE FUNCTION trust.guard_receipt_policy_v1();

CREATE TRIGGER sealed_text_key_policy_exact_one
BEFORE UPDATE OR DELETE ON trust.sealed_text_key_policy
FOR EACH ROW EXECUTE FUNCTION trust.guard_sealed_text_key_policy_v1();

CREATE FUNCTION trust.definer_scope_allows_v1(
    row_organization_id uuid,
    row_case_id uuid,
    row_demand_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog
AS $function$
    SELECT
        current_user = 'trust_schema_owner'
        AND session_user IN (
            'trust_self',
            'trust_officer',
            'trust_appeal',
            'trust_decision',
            'demand_self',
            'demand_review',
            'demand_finance',
            'demand_matching',
            'demand_system'
        )
        AND NULLIF(current_setting('app.trust_scope_kind', true), '') IN (
            'TRUST_COMMAND',
            'TRUST_RUNTIME_READINESS',
            'TRUST_REPORT_READ',
            'TRUST_QUEUE_READ',
            'TRUST_HOLD_RELEASE_QUEUE_READ',
            'TRUST_CASE_READ',
            'TRUST_HOLD_EVALUATION',
            'TRUST_APPEAL'
        )
        AND (
            (
                session_user = 'trust_officer'
                AND NULLIF(
                    current_setting('app.trust_scope_kind', true),
                    ''
                ) IN (
                    'TRUST_COMMAND',
                    'TRUST_RUNTIME_READINESS',
                    'TRUST_QUEUE_READ',
                    'TRUST_HOLD_RELEASE_QUEUE_READ',
                    'TRUST_CASE_READ'
                )
            )
            OR row_organization_id IS NULL
            OR row_organization_id = NULLIF(
                current_setting('app.organization_id', true),
                ''
            )::uuid
        )
        AND (
            NULLIF(current_setting('app.case_id', true), '') IS NULL
            OR row_case_id IS NULL
            OR row_case_id = NULLIF(
                current_setting('app.case_id', true),
                ''
            )::uuid
        )
        AND (
            NULLIF(current_setting('app.demand_id', true), '') IS NULL
            OR row_demand_id IS NULL
            OR row_demand_id = NULLIF(
                current_setting('app.demand_id', true),
                ''
            )::uuid
        )
$function$;

CREATE FUNCTION trust.entity_tag_v1(
    aggregate_kind text,
    aggregate_id uuid,
    aggregate_version bigint,
    aggregate_status text,
    changed_at timestamptz
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT format(
        '"trust-%s-%s"',
        aggregate_version,
        left(encode(sha256(convert_to(concat_ws(
            E'\x1f',
            'desire:trust:entity-tag:v1',
            aggregate_kind,
            aggregate_id::text,
            aggregate_version::text,
            aggregate_status,
            to_char(
                changed_at AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            )
        ), 'UTF8')), 'hex'), 24)
    )
$function$;

ALTER TABLE trust.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.reports FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.cases FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.restricted_text_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.restricted_text_blobs FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignment_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignment_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.triage_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.triage_drafts FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.triage_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.triage_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.safety_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.safety_holds FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.case_outcome_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.case_outcome_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.receipt_key_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.receipt_key_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.sealed_text_key_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.sealed_text_key_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.command_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_trust_reports_definer ON trust.reports
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, demand_id))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, demand_id));

CREATE POLICY rls_trust_cases_definer ON trust.cases
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, demand_id))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, demand_id));

CREATE POLICY rls_trust_assignments_definer ON trust.case_assignments
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, NULL))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, NULL));

CREATE POLICY rls_trust_restricted_text_definer
ON trust.restricted_text_blobs
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, NULL))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, NULL));

CREATE POLICY rls_trust_assignment_releases_definer
ON trust.case_assignment_releases
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, NULL))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, NULL));

CREATE POLICY rls_trust_triage_drafts_definer ON trust.triage_drafts
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, NULL))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, NULL));

CREATE POLICY rls_trust_triage_versions_definer ON trust.triage_versions
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, NULL))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, NULL));

CREATE POLICY rls_trust_holds_definer ON trust.safety_holds
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, demand_id))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, demand_id));

CREATE POLICY rls_trust_outcomes_definer ON trust.case_outcome_versions
FOR ALL TO trust_schema_owner
USING (trust.definer_scope_allows_v1(organization_id, case_id, NULL))
WITH CHECK (trust.definer_scope_allows_v1(organization_id, case_id, NULL));

CREATE POLICY rls_trust_receipt_policy_definer ON trust.receipt_key_policy
FOR SELECT TO trust_schema_owner
USING (
    singleton_key
    AND trust.definer_scope_allows_v1(NULL, NULL, NULL)
);

CREATE POLICY rls_trust_receipt_policy_lock_definer
ON trust.receipt_key_policy
FOR UPDATE TO trust_schema_owner
USING (
    singleton_key
    AND trust.definer_scope_allows_v1(NULL, NULL, NULL)
)
WITH CHECK (
    singleton_key
    AND trust.definer_scope_allows_v1(NULL, NULL, NULL)
);

CREATE POLICY rls_trust_sealed_text_policy_definer
ON trust.sealed_text_key_policy
FOR SELECT TO trust_schema_owner
USING (
    singleton_key
    AND trust.definer_scope_allows_v1(NULL, NULL, NULL)
);

CREATE POLICY rls_trust_sealed_text_policy_lock_definer
ON trust.sealed_text_key_policy
FOR UPDATE TO trust_schema_owner
USING (
    singleton_key
    AND trust.definer_scope_allows_v1(NULL, NULL, NULL)
)
WITH CHECK (
    singleton_key
    AND trust.definer_scope_allows_v1(NULL, NULL, NULL)
);

CREATE POLICY rls_trust_receipts_definer ON trust.command_receipts
FOR ALL TO trust_schema_owner
USING (
    principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND trust.definer_scope_allows_v1(
        organization_id,
        target_case_id,
        NULL
    )
)
WITH CHECK (
    principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND trust.definer_scope_allows_v1(
        organization_id,
        target_case_id,
        NULL
    )
);

GRANT USAGE ON SCHEMA trust_api TO
    trust_self,
    trust_officer,
    trust_appeal,
    trust_decision;
GRANT USAGE ON SCHEMA trust TO
    trust_migration_runner,
    trust_self,
    trust_officer,
    trust_appeal,
    trust_decision;
GRANT SELECT ON trust.schema_compatibility TO
    trust_migration_runner,
    trust_self,
    trust_officer,
    trust_appeal,
    trust_decision;

CREATE FUNCTION trust.utc_timestamp_text_v1(value timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT regexp_replace(
        to_char(
            value AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US'
        ),
        '(\\.0+|0+)$',
        ''
    ) || 'Z'
$function$;

CREATE FUNCTION trust_api.read_runtime_key_policy_v1()
RETURNS TABLE (
    active_idempotency_key_id text,
    retained_idempotency_key_ids text[],
    active_payload_key_id text,
    retained_payload_key_ids text[],
    active_canonicalization_version text,
    retained_canonicalization_versions text[],
    active_sealed_text_key_id text,
    retained_sealed_text_key_ids text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL RESTRICTED
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user NOT IN (
            'trust_self',
            'trust_officer',
            'trust_appeal',
            'trust_decision'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_RUNTIME_READINESS', true);
    PERFORM set_config('app.actor_id', '', true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    RETURN QUERY
    SELECT
        receipt.active_idempotency_key_id::text,
        receipt.retained_idempotency_key_ids,
        receipt.active_payload_key_id::text,
        receipt.retained_payload_key_ids,
        receipt.active_canonicalization_version::text,
        receipt.retained_canonicalization_versions,
        sealed.active_encryption_key_id::text,
        sealed.retained_encryption_key_ids
    FROM trust.receipt_key_policy AS receipt
    CROSS JOIN trust.sealed_text_key_policy AS sealed
    WHERE receipt.singleton_key
      AND sealed.singleton_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RUNTIME_KEY_POLICY_UNAVAILABLE';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.read_runtime_key_policy_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_runtime_key_policy_v1() TO
    trust_self,
    trust_officer,
    trust_appeal,
    trust_decision;

CREATE FUNCTION trust.claim_or_replay_receipt_v1(
    exact_receipt_id uuid,
    exact_actor_user_id uuid,
    exact_organization_id uuid,
    exact_command_name text,
    exact_http_method text,
    exact_canonical_path text,
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
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    key_policy trust.receipt_key_policy%ROWTYPE;
    existing trust.command_receipts%ROWTYPE;
    matching_count integer;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user NOT IN ('trust_self', 'trust_officer')
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_command_name NOT IN (
            'SUBMIT_REPORT',
            'CLAIM_CASE',
            'RELEASE_CASE_ASSIGNMENT',
            'SAVE_TRIAGE_DRAFT',
            'PUBLISH_TRIAGE',
            'PLACE_HOLD',
            'CLAIM_HOLD_RELEASE',
            'RELEASE_HOLD',
            'PUBLISH_OUTCOME'
       )
       OR exact_http_method NOT IN ('POST', 'PUT')
       OR exact_canonical_path IS NULL
       OR exact_canonical_path NOT LIKE '/v1/app/trust/%'
       OR (exact_if_match_version IS NOT NULL AND exact_if_match_version < 1)
       OR cardinality(exact_idempotency_key_digest_key_ids)
            NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_key_digests) AS digest(value)
            WHERE digest.value IS NULL OR octet_length(digest.value) <> 32
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hashes) AS digest(value)
            WHERE digest.value IS NULL OR octet_length(digest.value) <> 32
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS item(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
       )
       OR NULLIF(current_setting('app.trust_scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_COMMAND'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'TRUST_COMMAND_CONTEXT_INVALID';
    END IF;

    SELECT policy.*
    INTO STRICT key_policy
    FROM trust.receipt_key_policy AS policy
    WHERE policy.singleton_key
    FOR SHARE;

    IF key_policy.active_canonicalization_version
            <> 'trust-command-json-v1'
       OR exact_idempotency_key_digest_key_ids
            IS DISTINCT FROM key_policy.retained_idempotency_key_ids
       OR exact_payload_hash_key_ids
            IS DISTINCT FROM key_policy.retained_payload_key_ids
       OR exact_idempotency_key_digest_key_ids[1]
            <> key_policy.active_idempotency_key_id
       OR exact_payload_hash_key_ids[1]
            <> key_policy.active_payload_key_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            concat_ws(
                E'\x1f',
                'desire:trust:receipt-lock:v1',
                exact_actor_user_id::text,
                exact_command_name,
                exact_idempotency_key_digest_key_ids[slot.index],
                encode(exact_idempotency_key_digests[slot.index], 'hex')
            ),
            0
        )
    )
    FROM generate_subscripts(
        exact_idempotency_key_digests,
        1
    ) AS slot(index)
    ORDER BY
        exact_idempotency_key_digest_key_ids[slot.index],
        encode(exact_idempotency_key_digests[slot.index], 'hex');

    SELECT count(*)
    INTO matching_count
    FROM trust.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_domain = 'TRUST_SAFETY'
      AND receipt.command_name = exact_command_name
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(
              exact_idempotency_key_digests,
              1
          ) AS slot(index)
          WHERE receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_ids[slot.index]
            AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digests[slot.index]
      );

    IF matching_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_AMBIGUOUS';
    ELSIF matching_count = 1 THEN
        SELECT receipt.*
        INTO STRICT existing
        FROM trust.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_domain = 'TRUST_SAFETY'
          AND receipt.command_name = exact_command_name
          AND receipt.command_version = 1
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_key_digests,
                  1
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
                CONSTRAINT = 'uq_trust_receipt_identity',
                MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.organization_id IS DISTINCT FROM exact_organization_id
           OR existing.http_method <> exact_http_method
           OR existing.canonical_path <> exact_canonical_path
           OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
           OR existing.canonicalization_version <> 'trust-command-json-v1'
           OR existing.retain_until <= evaluated_time
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'TRUST_RECEIPT_REPLAY_INVALID';
        END IF;
        IF existing.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '40003',
                MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
        END IF;
        RETURN QUERY SELECT true, existing.receipt_id, existing.safe_response;
        RETURN;
    END IF;

    INSERT INTO trust.command_receipts (
        receipt_id,
        principal_kind,
        principal_id,
        organization_id,
        command_domain,
        command_name,
        command_version,
        idempotency_key_digest_key_id,
        idempotency_key_digest,
        payload_hash_key_id,
        canonicalization_version,
        payload_hash,
        http_method,
        canonical_path,
        if_match_version,
        status,
        retain_until,
        created_at
    ) VALUES (
        exact_receipt_id,
        'USER',
        exact_actor_user_id,
        exact_organization_id,
        'TRUST_SAFETY',
        exact_command_name,
        1,
        exact_idempotency_key_digest_key_ids[1],
        exact_idempotency_key_digests[1],
        exact_payload_hash_key_ids[1],
        'trust-command-json-v1',
        exact_payload_hashes[1],
        exact_http_method,
        exact_canonical_path,
        exact_if_match_version,
        'IN_PROGRESS',
        evaluated_time + interval '90 days',
        evaluated_time
    );
    RETURN QUERY SELECT false, exact_receipt_id, NULL::jsonb;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_KEY_POLICY_UNAVAILABLE';
END
$function$;

CREATE FUNCTION trust.resolve_officer_authority_v1(
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
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    resolved record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_operation NOT IN (
            'CLAIM_CASE',
            'RELEASE_CASE_ASSIGNMENT',
            'SAVE_TRIAGE_DRAFT',
            'PUBLISH_TRIAGE',
            'PLACE_HOLD',
            'CLAIM_HOLD_RELEASE',
            'RELEASE_HOLD',
            'PUBLISH_OUTCOME'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.scope_kind', 'TRUST_OFFICER', true);
    PERFORM set_config('app.operation', exact_operation, true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.session_id', exact_session_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.membership_id', '', true);
    PERFORM set_config('app.membership_role_grant_id', '', true);
    PERFORM set_config('app.membership_role_grant_version', '', true);

    SELECT authority.*
    INTO STRICT resolved
    FROM iam_api.resolve_trust_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_operation
    ) AS authority
    WHERE authority.actor_user_id = exact_actor_user_id
      AND authority.session_id = exact_session_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.duty_code = 'TRUST_OFFICER'
      AND authority.duty_grant_version >= 1
      AND (
          authority.duty_expires_at IS NULL
          OR transaction_timestamp() < authority.duty_expires_at
      )
      AND octet_length(authority.authority_marker_sha256) = 32;

    PERFORM set_config('app.duty_grant_id', resolved.duty_grant_id::text, true);
    PERFORM set_config(
        'app.duty_grant_version',
        resolved.duty_grant_version::text,
        true
    );
    RETURN QUERY SELECT
        resolved.duty_grant_id,
        resolved.duty_grant_version,
        resolved.duty_expires_at,
        resolved.authority_marker_sha256;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

CREATE FUNCTION trust.resolve_officer_conflict_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint,
    exact_authority_marker_sha256 bytea,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_demand_version_id uuid
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
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    resolved record;
BEGIN
    IF exact_operation NOT IN ('CLAIM_CASE', 'CLAIM_HOLD_RELEASE') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.demand_id', exact_demand_id::text, true);
    PERFORM set_config(
        'app.demand_version_id',
        exact_demand_version_id::text,
        true
    );
    SELECT conflict.*
    INTO STRICT resolved
    FROM demand_api.resolve_trust_officer_conflict_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_operation,
        exact_duty_grant_id,
        exact_duty_grant_version,
        exact_organization_id,
        exact_demand_id,
        exact_demand_version_id,
        exact_authority_marker_sha256
    ) AS conflict
    WHERE conflict.officer_user_id = exact_actor_user_id
      AND conflict.organization_id = exact_organization_id
      AND conflict.demand_id = exact_demand_id
      AND conflict.demand_version_id = exact_demand_version_id
      AND conflict.conflict_free
      AND conflict.evaluated_at <= transaction_timestamp()
      AND transaction_timestamp() < conflict.valid_until
      AND octet_length(conflict.conflict_attestation_sha256) = 32;
    RETURN QUERY SELECT
        resolved.conflict_attestation_sha256,
        resolved.evaluated_at,
        resolved.valid_until;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'CONFLICT_OF_INTEREST';
END
$function$;

CREATE FUNCTION trust.require_case_assignment_v1(
    exact_case_id uuid,
    exact_actor_user_id uuid,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint,
    allow_expired_assignment boolean
)
RETURNS trust.case_assignments
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
BEGIN
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    SELECT assignment_row.* INTO STRICT assignment
    FROM trust.case_assignments AS assignment_row
    WHERE assignment_row.case_id = safety_case.case_id
      AND assignment_row.assignment_id = safety_case.assignment_id
      AND assignment_row.assignment_purpose_code = 'CASE_TRIAGE'
      AND NOT EXISTS (
          SELECT 1
          FROM trust.case_assignment_releases AS release_row
          WHERE release_row.assignment_id = assignment_row.assignment_id
      )
    FOR UPDATE;
    IF assignment.officer_user_id <> safety_case.assigned_officer_user_id
       OR assignment.expires_at <> safety_case.assignment_expires_at
       OR (
            NOT allow_expired_assignment
            AND (
                assignment.officer_user_id <> exact_actor_user_id
                OR assignment.duty_grant_id <> exact_duty_grant_id
                OR assignment.duty_grant_version <> exact_duty_grant_version
                OR transaction_timestamp() < assignment.assigned_at
                OR transaction_timestamp() >= assignment.expires_at
            )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'CASE_ASSIGNMENT_REQUIRED';
    END IF;
    RETURN assignment;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'CASE_ASSIGNMENT_REQUIRED';
END
$function$;

CREATE FUNCTION trust_api.store_restricted_text_blob_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_case_id uuid,
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
    exact_retain_until timestamptz
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
    authority record;
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    key_policy trust.receipt_key_policy%ROWTYPE;
    sealed_key_policy trust.sealed_text_key_policy%ROWTYPE;
    existing trust.restricted_text_blobs%ROWTYPE;
    matching_count integer;
    expected_aad_sha256 bytea;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_case_id IS NULL
       OR exact_purpose_code <> 'TRIAGE_NOTE'
       OR exact_retention_class <> 'TRUST_CASE_NOTE'
       OR cardinality(exact_encryption_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_encryption_key_ids)
            <> cardinality(exact_candidate_references)
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_encryption_key_ids) AS candidate(value)
            WHERE candidate.value IS NULL
               OR candidate.value !~ '^[a-z0-9][a-z0-9-]{2,127}$'
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_encryption_key_ids) AS candidate(value)
       )
       OR cardinality(exact_candidate_references) NOT BETWEEN 1 AND 4
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_candidate_references) AS candidate(value)
            WHERE candidate.value IS NULL
               OR candidate.value
                    !~ '^sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}$'
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_candidate_references) AS candidate(value)
       )
       OR cardinality(exact_plaintext_hmac_sha256s)
            <> cardinality(exact_encryption_key_ids)
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_plaintext_hmac_sha256s) AS digest(value)
            WHERE digest.value IS NULL OR octet_length(digest.value) <> 32
       )
       OR exact_envelope_sha256 IS NULL
       OR octet_length(exact_envelope_sha256) <> 32
       OR exact_encryption_key_id IS NULL
       OR exact_encryption_key_id !~ '^[a-z0-9][a-z0-9-]{2,127}$'
       OR exact_encryption_nonce IS NULL
       OR octet_length(exact_encryption_nonce) <> 12
       OR exact_ciphertext IS NULL
       OR octet_length(exact_ciphertext) NOT BETWEEN 17 AND 16384
       OR exact_aad_sha256 IS NULL
       OR octet_length(exact_aad_sha256) <> 32
       OR cardinality(exact_idempotency_key_digest_key_ids)
            NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_key_digests) AS digest(value)
            WHERE digest.value IS NULL OR octet_length(digest.value) <> 32
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(
                exact_idempotency_key_digest_key_ids
            ) AS candidate(value)
       )
       OR exact_retain_until IS NULL
       OR exact_retain_until <= evaluated_time
       OR exact_retain_until > evaluated_time + interval '10 years'
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'SAVE_TRIAGE_DRAFT'
    ) AS officer;

    SELECT policy.* INTO STRICT key_policy
    FROM trust.receipt_key_policy AS policy
    WHERE policy.singleton_key
    FOR SHARE;
    IF exact_idempotency_key_digest_key_ids
            IS DISTINCT FROM key_policy.retained_idempotency_key_ids
       OR exact_idempotency_key_digest_key_ids[1]
            <> key_policy.active_idempotency_key_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;
    SELECT policy.* INTO STRICT sealed_key_policy
    FROM trust.sealed_text_key_policy AS policy
    WHERE policy.singleton_key
    FOR SHARE;
    IF exact_encryption_key_ids
            IS DISTINCT FROM sealed_key_policy.retained_encryption_key_ids
       OR exact_encryption_key_ids[1]
            <> sealed_key_policy.active_encryption_key_id
       OR exact_encryption_key_id
            <> sealed_key_policy.active_encryption_key_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_SEALED_TEXT_KEY_POLICY_UNAVAILABLE';
    END IF;

    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        false
    );
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            concat_ws(
                E'\x1f',
                'desire:trust:restricted-text-lock:v1',
                exact_actor_user_id::text,
                exact_case_id::text,
                exact_purpose_code,
                candidate.value
            ),
            0
        )
    )
    FROM unnest(exact_candidate_references) AS candidate(value)
    ORDER BY candidate.value;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            concat_ws(
                E'\x1f',
                'desire:trust:restricted-text-idempotency-lock:v1',
                exact_actor_user_id::text,
                exact_case_id::text,
                exact_purpose_code,
                exact_idempotency_key_digest_key_ids[slot.index],
                encode(exact_idempotency_key_digests[slot.index], 'hex')
            ),
            0
        )
    )
    FROM generate_subscripts(
        exact_idempotency_key_digests,
        1
    ) AS slot(index)
    ORDER BY
        exact_idempotency_key_digest_key_ids[slot.index],
        encode(exact_idempotency_key_digests[slot.index], 'hex');

    SELECT count(*) INTO matching_count
    FROM trust.restricted_text_blobs AS blob
    WHERE blob.actor_user_id = exact_actor_user_id
      AND blob.case_id = exact_case_id
      AND blob.purpose_code = exact_purpose_code
      AND (
          blob.sealed_note_reference = ANY(exact_candidate_references)
          OR EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_key_digests,
                  1
              ) AS slot(index)
              WHERE blob.idempotency_key_digest_key_id
                        = exact_idempotency_key_digest_key_ids[slot.index]
                AND blob.idempotency_key_digest
                        = exact_idempotency_key_digests[slot.index]
          )
      );
    IF matching_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_SEALED_TEXT_AMBIGUOUS';
    ELSIF matching_count = 1 THEN
        SELECT blob.* INTO STRICT existing
        FROM trust.restricted_text_blobs AS blob
        WHERE blob.actor_user_id = exact_actor_user_id
          AND blob.case_id = exact_case_id
          AND blob.purpose_code = exact_purpose_code
          AND (
              blob.sealed_note_reference = ANY(exact_candidate_references)
              OR EXISTS (
                  SELECT 1
                  FROM generate_subscripts(
                      exact_idempotency_key_digests,
                      1
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
                exact_plaintext_hmac_sha256s,
                1
            ) AS slot(index)
            WHERE exact_encryption_key_ids[slot.index]
                    = existing.encryption_key_id
              AND exact_plaintext_hmac_sha256s[slot.index]
                    = existing.plaintext_hmac_sha256
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'uq_trust_restricted_text_idempotency',
                MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.organization_id <> safety_case.organization_id
           OR existing.retain_until <= evaluated_time
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'TRUST_SEALED_TEXT_REPLAY_INVALID';
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
        E'\x1f',
        'desire:trust:restricted-text-aad:v1',
        exact_candidate_references[1],
        exact_case_id::text,
        exact_actor_user_id::text,
        exact_purpose_code,
        encode(exact_plaintext_hmac_sha256s[1], 'hex'),
        exact_encryption_key_id
    ), 'UTF8'));
    IF exact_aad_sha256 <> expected_aad_sha256
       OR exact_envelope_sha256 <> sha256(convert_to(concat_ws(
            E'\x1f',
            'desire:trust:restricted-text-envelope:v1',
            exact_encryption_key_id,
            encode(exact_encryption_nonce, 'hex'),
            encode(exact_ciphertext, 'hex'),
            encode(exact_aad_sha256, 'hex')
       ), 'UTF8'))
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    INSERT INTO trust.restricted_text_blobs (
        sealed_note_reference,
        organization_id,
        case_id,
        actor_user_id,
        purpose_code,
        plaintext_hmac_sha256,
        envelope_sha256,
        encryption_key_id,
        encryption_nonce,
        ciphertext,
        aad_sha256,
        idempotency_key_digest_key_id,
        idempotency_key_digest,
        retention_class,
        sealed_at,
        retain_until
    ) VALUES (
        exact_candidate_references[1],
        safety_case.organization_id,
        exact_case_id,
        exact_actor_user_id,
        exact_purpose_code,
        exact_plaintext_hmac_sha256s[1],
        exact_envelope_sha256,
        exact_encryption_key_id,
        exact_encryption_nonce,
        exact_ciphertext,
        exact_aad_sha256,
        exact_idempotency_key_digest_key_ids[1],
        exact_idempotency_key_digests[1],
        exact_retention_class,
        evaluated_time,
        exact_retain_until
    );
    RETURN QUERY SELECT
        exact_candidate_references[1],
        exact_envelope_sha256,
        exact_retention_class,
        evaluated_time,
        false;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

REVOKE ALL ON FUNCTION trust_api.store_restricted_text_blob_v1(
    uuid, uuid, uuid, text, text[], text[], bytea[], bytea, text, bytea, bytea,
    bytea,
    text[], bytea[], text, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.store_restricted_text_blob_v1(
    uuid, uuid, uuid, text, text[], text[], bytea[], bytea, text, bytea, bytea,
    bytea,
    text[], bytea[], text, timestamptz
) TO trust_officer;

CREATE FUNCTION trust.triage_content_sha256_v1(
    exact_priority_code text,
    exact_jurisdiction_code text,
    exact_severity_code text,
    exact_issue_codes text[],
    exact_investigation_step_codes text[],
    exact_proposed_hold_actions text[],
    exact_proposed_hold_ttl_minutes integer,
    exact_sealed_note_reference text,
    exact_sealed_note_sha256 bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:triage-content:v1',
        exact_priority_code,
        exact_jurisdiction_code,
        exact_severity_code,
        array_to_string(exact_issue_codes, E'\x1e'),
        array_to_string(exact_investigation_step_codes, E'\x1e'),
        array_to_string(exact_proposed_hold_actions, E'\x1e'),
        exact_proposed_hold_ttl_minutes::text,
        exact_sealed_note_reference,
        encode(exact_sealed_note_sha256, 'hex')
    ), 'UTF8'))
$function$;

CREATE FUNCTION trust.outcome_content_sha256_v1(
    exact_case_id uuid,
    exact_outcome_code text,
    exact_reason_codes text[],
    exact_action_codes text[],
    exact_evidence_packet_version_id uuid,
    exact_evidence_packet_digest bytea,
    exact_source_digest bytea,
    exact_redaction_profile_code text,
    exact_appeal_eligible boolean,
    exact_appeal_eligibility_code text,
    exact_appeal_deadline timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, trust
AS $function$
    SELECT sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:case-outcome-content:v1',
        exact_case_id::text,
        exact_outcome_code,
        array_to_string(exact_reason_codes, E'\x1e'),
        array_to_string(exact_action_codes, E'\x1e'),
        exact_evidence_packet_version_id::text,
        encode(exact_evidence_packet_digest, 'hex'),
        encode(exact_source_digest, 'hex'),
        exact_redaction_profile_code,
        exact_appeal_eligible::text,
        exact_appeal_eligibility_code,
        COALESCE(trust.utc_timestamp_text_v1(exact_appeal_deadline), 'null'),
        'trust-case-outcome-v1'
    ), 'UTF8'))
$function$;

CREATE FUNCTION trust.report_outcome_safe_sha256_v1(
    exact_report trust.reports
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, trust
AS $function$
    SELECT sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:outcome-report-safe-content:v1',
        exact_report.report_id::text,
        exact_report.organization_id::text,
        exact_report.demand_id::text,
        exact_report.demand_version_id::text,
        exact_report.demand_version_no::text,
        exact_report.demand_aggregate_version::text,
        exact_report.demand_status,
        encode(exact_report.demand_content_sha256, 'hex'),
        exact_report.category,
        trust.utc_timestamp_text_v1(exact_report.incident_started_at),
        COALESCE(
            trust.utc_timestamp_text_v1(exact_report.incident_ended_at),
            'null'
        ),
        array_to_string(exact_report.impact_codes, E'\x1e'),
        array_to_string(exact_report.evidence_reference_ids, E'\x1e'),
        array_to_string(exact_report.requested_protection_codes, E'\x1e'),
        trust.utc_timestamp_text_v1(exact_report.created_at)
    ), 'UTF8'))
$function$;

CREATE FUNCTION trust.outcome_source_document_v1(
    exact_case_id uuid,
    exact_outcome_code text,
    exact_reason_codes text[],
    exact_action_codes text[],
    evaluated_at timestamptz
)
RETURNS text
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog, trust
AS $function$
    SELECT jsonb_build_object(
        'action_codes', to_jsonb(exact_action_codes),
        'active_holds', COALESCE((
            SELECT jsonb_agg(
                jsonb_build_object(
                    'action_codes', to_jsonb(hold.action_codes),
                    'hold_id', hold.hold_id,
                    'hold_version', hold.aggregate_version,
                    'status', hold.status
                )
                ORDER BY hold.hold_id
            )
            FROM trust.safety_holds AS hold
            WHERE hold.case_id = safety_case.case_id
              AND hold.status = 'ACTIVE'
              AND hold.effective_at <= evaluated_at
              AND evaluated_at < hold.expires_at
        ), '[]'::jsonb),
        'case_aggregate_version', safety_case.aggregate_version,
        'case_id', safety_case.case_id,
        'case_status', safety_case.status,
        'demand_aggregate_version', report.demand_aggregate_version,
        'demand_content_sha256', encode(report.demand_content_sha256, 'hex'),
        'demand_id', safety_case.demand_id,
        'demand_version_id', safety_case.demand_version_id,
        'demand_version_no', report.demand_version_no,
        'organization_id', safety_case.organization_id,
        'outcome_code', exact_outcome_code,
        'reason_codes', to_jsonb(exact_reason_codes),
        'report_content_sha256', encode(
            trust.report_outcome_safe_sha256_v1(report),
            'hex'
        ),
        'report_id', report.report_id,
        'triage_version', triage.triage_version
    )::text
    FROM trust.cases AS safety_case
    JOIN trust.reports AS report
      ON report.case_id = safety_case.case_id
     AND report.report_id = safety_case.report_id
    JOIN trust.triage_versions AS triage
      ON triage.case_id = safety_case.case_id
     AND triage.triage_version = safety_case.current_triage_version
    WHERE safety_case.case_id = exact_case_id
$function$;

CREATE FUNCTION trust.outcome_source_sha256_v1(
    exact_source_document text
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:outcome-source:v1',
        exact_source_document
    ), 'UTF8'))
$function$;

CREATE FUNCTION trust.outcome_evidence_packet_sha256_v1(
    exact_evidence_packet_version_id uuid,
    exact_source_digest bytea,
    exact_outcome_code text,
    exact_reason_codes text[],
    exact_action_codes text[],
    exact_appeal_eligibility_code text,
    exact_appeal_deadline timestamptz,
    exact_policy_version text,
    exact_redaction_profile_code text,
    exact_evaluated_at timestamptz,
    exact_valid_until timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, trust
AS $function$
    SELECT sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:outcome-evidence-packet:v1',
        'trust-evidence-redaction-v1',
        exact_evidence_packet_version_id::text,
        encode(exact_source_digest, 'hex'),
        exact_outcome_code,
        array_to_string(exact_reason_codes, E'\x1e'),
        array_to_string(exact_action_codes, E'\x1e'),
        exact_appeal_eligibility_code,
        trust.utc_timestamp_text_v1(exact_appeal_deadline),
        exact_policy_version,
        exact_redaction_profile_code,
        trust.utc_timestamp_text_v1(exact_evaluated_at),
        trust.utc_timestamp_text_v1(exact_valid_until)
    ), 'UTF8'))
$function$;

CREATE FUNCTION trust.validate_event_v1(
    exact_event_type text,
    exact_case_id uuid,
    exact_case_status text,
    exact_payload jsonb
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    expected_keys text[];
    expected_status text;
BEGIN
    expected_keys := CASE exact_event_type
        WHEN 'TrustReportSubmitted' THEN ARRAY[
            'case_id', 'case_status', 'demand_id', 'demand_version_id',
            'organization_id', 'report_id'
        ]::text[]
        WHEN 'TrustCaseClaimed' THEN ARRAY[
            'assignment_expires_at', 'assignment_id', 'case_id', 'case_status'
        ]::text[]
        WHEN 'TrustCaseAssignmentReleased' THEN ARRAY[
            'assignment_id', 'case_id', 'case_status'
        ]::text[]
        WHEN 'TrustTriageDraftSaved' THEN ARRAY[
            'case_id', 'case_status', 'triage_draft_version'
        ]::text[]
        WHEN 'TrustTriagePublished' THEN ARRAY[
            'case_id', 'case_status', 'triage_version'
        ]::text[]
        WHEN 'SafetyHoldPlaced' THEN ARRAY[
            'action_codes', 'case_id', 'case_status', 'expires_at', 'hold_id',
            'hold_status', 'hold_version'
        ]::text[]
        WHEN 'TrustHoldReleaseClaimed' THEN ARRAY[
            'action_codes', 'assignment_expires_at', 'assignment_id',
            'case_id', 'case_status', 'expires_at', 'hold_id', 'hold_status',
            'hold_version'
        ]::text[]
        WHEN 'SafetyHoldReleased' THEN ARRAY[
            'action_codes', 'case_id', 'case_status', 'expires_at', 'hold_id',
            'hold_status', 'hold_version'
        ]::text[]
        WHEN 'TrustCaseOutcomePublished' THEN ARRAY[
            'action_codes', 'appeal_deadline', 'appeal_eligibility_code',
            'appeal_eligible', 'case_id', 'case_status', 'content_sha256',
            'outcome_code', 'outcome_version', 'outcome_version_id'
        ]::text[]
        ELSE NULL
    END;
    expected_status := CASE exact_event_type
        WHEN 'TrustReportSubmitted' THEN 'OPEN'
        WHEN 'TrustCaseClaimed' THEN 'TRIAGING'
        WHEN 'TrustCaseAssignmentReleased' THEN 'OPEN'
        WHEN 'TrustTriageDraftSaved' THEN 'TRIAGING'
        WHEN 'TrustTriagePublished' THEN 'IN_REVIEW'
        WHEN 'SafetyHoldPlaced' THEN 'IN_REVIEW'
        WHEN 'TrustHoldReleaseClaimed' THEN 'IN_REVIEW'
        WHEN 'SafetyHoldReleased' THEN 'IN_REVIEW'
        WHEN 'TrustCaseOutcomePublished' THEN 'DECIDED'
        ELSE NULL
    END;
    IF expected_keys IS NULL
       OR exact_case_status IS DISTINCT FROM expected_status
       OR NOT trust.jsonb_has_exact_keys(exact_payload, expected_keys)
       OR exact_payload->>'case_id' IS DISTINCT FROM exact_case_id::text
       OR exact_payload->>'case_status' IS DISTINCT FROM exact_case_status
       OR exact_payload ?| ARRAY[
            'reporter_user_id',
            'demand_owner_user_id',
            'session_id',
            'authority_marker_sha256',
            'reporter_party_marker_sha256',
            'target_marker_sha256',
            'sealed_note_reference',
            'sealed_note_sha256'
       ]::text[]
    THEN
        RETURN false;
    END IF;
    IF exact_event_type IN ('SafetyHoldPlaced', 'SafetyHoldReleased')
       OR exact_event_type = 'TrustHoldReleaseClaimed'
    THEN
        IF jsonb_typeof(exact_payload->'action_codes') <> 'array'
           OR NOT trust.canonical_code_array_v1(
                ARRAY(
                    SELECT jsonb_array_elements_text(
                        exact_payload->'action_codes'
                    )
                ),
                1,
                3
           )
           OR NOT ARRAY(
                SELECT jsonb_array_elements_text(
                    exact_payload->'action_codes'
                )
           ) <@ ARRAY[
                'REQUEST_MATCHING', 'SUBMIT_DEMAND', 'VERIFY_DEMAND'
           ]::text[]
           OR exact_payload->>'expires_at' !~ 'Z$'
        THEN
            RETURN false;
        END IF;
    END IF;
    IF exact_event_type = 'TrustCaseOutcomePublished'
       AND (
           jsonb_typeof(exact_payload->'action_codes') <> 'array'
           OR NOT trust.canonical_code_array_v1(
                ARRAY(
                    SELECT jsonb_array_elements_text(
                        exact_payload->'action_codes'
                    )
                ),
                0,
                3
           )
           OR NOT ARRAY(
                SELECT jsonb_array_elements_text(
                    exact_payload->'action_codes'
                )
           ) <@ ARRAY[
                'REQUEST_MATCHING', 'SUBMIT_DEMAND', 'VERIFY_DEMAND'
           ]::text[]
           OR exact_payload->>'content_sha256' !~ '^[0-9a-f]{64}$'
           OR exact_payload->>'outcome_code' NOT IN (
                'NO_ACTION',
                'PROTECTION_LIFTED',
                'PROTECTION_MAINTAINED',
                'PROTECTION_MODIFIED',
                'REMEDIATION_REQUIRED'
           )
           OR exact_payload->>'appeal_eligibility_code'
                NOT IN ('ELIGIBLE', 'NOT_ELIGIBLE')
           OR (exact_payload->>'appeal_eligible')::boolean
                <> (
                    exact_payload->>'appeal_eligibility_code' = 'ELIGIBLE'
                )
           OR (
                (exact_payload->>'appeal_eligible')::boolean
                AND (
                    jsonb_typeof(exact_payload->'appeal_deadline') <> 'string'
                    OR exact_payload->>'appeal_deadline' !~ 'Z$'
                )
           )
           OR (
                NOT (exact_payload->>'appeal_eligible')::boolean
                AND exact_payload->'appeal_deadline' <> 'null'::jsonb
           )
       )
    THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION
    WHEN data_exception OR invalid_text_representation THEN RETURN false;
END
$function$;

CREATE FUNCTION trust.complete_command_v1(
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_actor_user_id uuid,
    exact_organization_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_case_id uuid,
    exact_before_status text,
    exact_before_version bigint,
    exact_after_status text,
    exact_after_version bigint,
    exact_event_type text,
    exact_event_payload jsonb,
    exact_report_id uuid,
    exact_assignment_id uuid,
    exact_triage_draft_version integer,
    exact_triage_version integer,
    exact_hold_id uuid,
    exact_hold_version bigint,
    exact_outcome_version_id uuid
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
    completed_time timestamptz := transaction_timestamp();
    safe_result jsonb;
    response_status integer;
    audit_action text;
    affected integer;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_audit_event_id IS NULL OR exact_audit_event_id = zero_uuid
       OR exact_outbox_event_id IS NULL OR exact_outbox_event_id = zero_uuid
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_case_id IS NULL OR exact_case_id = zero_uuid
       OR exact_after_version IS NULL OR exact_after_version < 1
       OR NOT trust.validate_event_v1(
            exact_event_type,
            exact_case_id,
            exact_after_status,
            exact_event_payload
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'TRUST_EVENT_CONTRACT_INVALID';
    END IF;
    audit_action := CASE exact_event_type
        WHEN 'TrustReportSubmitted' THEN 'trust.report_submitted'
        WHEN 'TrustCaseClaimed' THEN 'trust.case_claimed'
        WHEN 'TrustCaseAssignmentReleased' THEN
            'trust.case_assignment_released'
        WHEN 'TrustTriageDraftSaved' THEN 'trust.triage_draft_saved'
        WHEN 'TrustTriagePublished' THEN 'trust.triage_published'
        WHEN 'SafetyHoldPlaced' THEN 'trust.hold_placed'
        WHEN 'TrustHoldReleaseClaimed' THEN 'trust.hold_release_claimed'
        WHEN 'SafetyHoldReleased' THEN 'trust.hold_released'
        WHEN 'TrustCaseOutcomePublished' THEN 'trust.outcome_published'
        ELSE NULL
    END;
    IF audit_action IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'TRUST_EVENT_CONTRACT_INVALID';
    END IF;

    safe_result := jsonb_build_object(
        'aggregate_version', exact_after_version,
        'assignment_id', exact_assignment_id,
        'case_id', exact_case_id,
        'case_status', exact_after_status,
        'completed_at', trust.utc_timestamp_text_v1(completed_time),
        'event_types', jsonb_build_array(exact_event_type),
        'hold_id', exact_hold_id,
        'hold_version', exact_hold_version,
        'outcome_version_id', exact_outcome_version_id,
        'report_id', exact_report_id,
        'triage_draft_version', exact_triage_draft_version,
        'triage_version', exact_triage_version
    );

    INSERT INTO audit.audit_events (
        event_id,
        occurred_at,
        actor_kind,
        actor_id,
        original_actor_id,
        action_code,
        target_kind,
        target_id,
        organization_id,
        before_status,
        after_status,
        before_version,
        after_version,
        role_code,
        purpose_code,
        reason_code,
        auth_strength_code,
        result_code,
        command_id,
        correlation_id,
        causation_id,
        trace_id,
        safe_attributes
    ) VALUES (
        exact_audit_event_id,
        completed_time,
        'USER',
        exact_actor_user_id,
        NULL,
        audit_action,
        'SafetyCase',
        exact_case_id,
        exact_organization_id,
        exact_before_status,
        exact_after_status,
        exact_before_version,
        exact_after_version,
        CASE WHEN session_user = 'trust_officer'
            THEN 'TRUST_OFFICER' ELSE 'DEMAND_OWNER' END,
        'TRUST_SAFETY',
        NULL,
        NULL,
        'SUCCESS',
        exact_receipt_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        jsonb_build_object(
            'case_id', exact_case_id,
            'event_type', exact_event_type
        )
    );

    INSERT INTO infra.outbox_events (
        event_id,
        event_type,
        schema_version,
        occurred_at,
        aggregate_type,
        aggregate_id,
        aggregate_version,
        actor_kind,
        actor_id,
        original_actor_id,
        correlation_id,
        causation_id,
        trace_id,
        organization_id,
        payload,
        delivery_status,
        attempt_count,
        available_at,
        lease_owner,
        lease_until,
        published_at,
        last_error_code,
        created_at
    ) VALUES (
        exact_outbox_event_id,
        exact_event_type,
        1,
        completed_time,
        'SafetyCase',
        exact_case_id,
        exact_after_version,
        'USER',
        exact_actor_user_id,
        NULL,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        exact_organization_id,
        exact_event_payload,
        'PENDING',
        0,
        completed_time,
        NULL,
        NULL,
        NULL,
        NULL,
        completed_time
    );

    response_status := CASE
        WHEN exact_event_type IN (
            'TrustReportSubmitted',
            'SafetyHoldPlaced',
            'TrustCaseOutcomePublished'
        ) THEN 201
        ELSE 200
    END;
    UPDATE trust.command_receipts AS receipt
    SET status = 'COMPLETED',
        response_http_status = response_status,
        response_schema_name = 'TrustCommandResult',
        response_schema_version = 1,
        response_entity_tag = trust.entity_tag_v1(
            'SafetyCase',
            exact_case_id,
            exact_after_version,
            exact_after_status,
            completed_time
        ),
        safe_response = safe_result,
        target_case_id = exact_case_id,
        target_version = exact_after_version,
        result_status = exact_after_status,
        event_types = ARRAY[exact_event_type]::text[],
        completed_at = completed_time
    WHERE receipt.receipt_id = exact_receipt_id
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.status = 'IN_PROGRESS';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    RETURN safe_result;
END
$function$;

CREATE FUNCTION trust_api.read_completed_command_receipt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_command_name text,
    exact_target_id uuid,
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
    key_policy trust.receipt_key_policy%ROWTYPE;
    existing trust.command_receipts%ROWTYPE;
    reporter_authority record;
    officer_authority record;
    expected_method text;
    expected_path text;
    expected_event_type text;
    expected_status text;
    expected_http_status integer;
    target_is_hold boolean;
    matching_count integer;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    expected_method := CASE exact_command_name
        WHEN 'SAVE_TRIAGE_DRAFT' THEN 'PUT'
        WHEN 'SUBMIT_REPORT' THEN 'POST'
        WHEN 'CLAIM_CASE' THEN 'POST'
        WHEN 'RELEASE_CASE_ASSIGNMENT' THEN 'POST'
        WHEN 'PUBLISH_TRIAGE' THEN 'POST'
        WHEN 'PLACE_HOLD' THEN 'POST'
        WHEN 'CLAIM_HOLD_RELEASE' THEN 'POST'
        WHEN 'RELEASE_HOLD' THEN 'POST'
        WHEN 'PUBLISH_OUTCOME' THEN 'POST'
        ELSE NULL
    END;
    expected_path := CASE exact_command_name
        WHEN 'SUBMIT_REPORT' THEN '/v1/app/trust/reports'
        WHEN 'CLAIM_CASE' THEN '/v1/app/trust/queue/{case_id}/claim'
        WHEN 'RELEASE_CASE_ASSIGNMENT' THEN
            '/v1/app/trust/cases/{case_id}/assignment/release'
        WHEN 'SAVE_TRIAGE_DRAFT' THEN
            '/v1/app/trust/cases/{case_id}/triage-draft'
        WHEN 'PUBLISH_TRIAGE' THEN
            '/v1/app/trust/cases/{case_id}/triage-publish'
        WHEN 'PLACE_HOLD' THEN '/v1/app/trust/cases/{case_id}/holds'
        WHEN 'CLAIM_HOLD_RELEASE' THEN
            '/v1/app/trust/hold-release-queue/{hold_id}/claim'
        WHEN 'RELEASE_HOLD' THEN
            '/v1/app/trust/holds/{hold_id}/release'
        WHEN 'PUBLISH_OUTCOME' THEN
            '/v1/app/trust/cases/{case_id}/decisions'
        ELSE NULL
    END;
    expected_event_type := CASE exact_command_name
        WHEN 'SUBMIT_REPORT' THEN 'TrustReportSubmitted'
        WHEN 'CLAIM_CASE' THEN 'TrustCaseClaimed'
        WHEN 'RELEASE_CASE_ASSIGNMENT' THEN 'TrustCaseAssignmentReleased'
        WHEN 'SAVE_TRIAGE_DRAFT' THEN 'TrustTriageDraftSaved'
        WHEN 'PUBLISH_TRIAGE' THEN 'TrustTriagePublished'
        WHEN 'PLACE_HOLD' THEN 'SafetyHoldPlaced'
        WHEN 'CLAIM_HOLD_RELEASE' THEN 'TrustHoldReleaseClaimed'
        WHEN 'RELEASE_HOLD' THEN 'SafetyHoldReleased'
        WHEN 'PUBLISH_OUTCOME' THEN 'TrustCaseOutcomePublished'
        ELSE NULL
    END;
    expected_status := CASE exact_command_name
        WHEN 'SUBMIT_REPORT' THEN 'OPEN'
        WHEN 'CLAIM_CASE' THEN 'TRIAGING'
        WHEN 'RELEASE_CASE_ASSIGNMENT' THEN 'OPEN'
        WHEN 'SAVE_TRIAGE_DRAFT' THEN 'TRIAGING'
        WHEN 'PUBLISH_TRIAGE' THEN 'IN_REVIEW'
        WHEN 'PLACE_HOLD' THEN 'IN_REVIEW'
        WHEN 'CLAIM_HOLD_RELEASE' THEN 'IN_REVIEW'
        WHEN 'RELEASE_HOLD' THEN 'IN_REVIEW'
        WHEN 'PUBLISH_OUTCOME' THEN 'DECIDED'
        ELSE NULL
    END;
    expected_http_status := CASE
        WHEN exact_command_name IN (
            'SUBMIT_REPORT',
            'PLACE_HOLD',
            'PUBLISH_OUTCOME'
        ) THEN 201
        ELSE 200
    END;
    target_is_hold := exact_command_name IN (
        'CLAIM_HOLD_RELEASE',
        'RELEASE_HOLD'
    );

    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR expected_method IS NULL
       OR (
            exact_command_name = 'SUBMIT_REPORT'
            AND (
                session_user IS DISTINCT FROM 'trust_self'
                OR exact_organization_id IS NULL
                OR exact_target_id IS NOT NULL
                OR exact_if_match_version IS NOT NULL
            )
       )
       OR (
            exact_command_name <> 'SUBMIT_REPORT'
            AND (
                session_user IS DISTINCT FROM 'trust_officer'
                OR exact_organization_id IS NOT NULL
                OR exact_target_id IS NULL
                OR exact_if_match_version IS NULL
                OR exact_if_match_version < 1
            )
       )
       OR cardinality(exact_idempotency_key_digest_key_ids)
            NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_key_digests) AS digest(value)
            WHERE digest.value IS NULL OR octet_length(digest.value) <> 32
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hashes) AS digest(value)
            WHERE digest.value IS NULL OR octet_length(digest.value) <> 32
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS item(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config(
        'app.organization_id',
        COALESCE(exact_organization_id::text, ''),
        true
    );
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    IF exact_command_name = 'SUBMIT_REPORT' THEN
        PERFORM set_config('app.scope_kind', 'TRUST_REPORTER', true);
        PERFORM set_config('app.operation', 'SUBMIT_REPORT', true);
        PERFORM set_config('app.session_id', exact_session_id::text, true);
        SELECT authority.* INTO STRICT reporter_authority
        FROM iam_api.resolve_trust_reporter_authority_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_organization_id,
            'SUBMIT_REPORT'
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
    ELSE
        SELECT authority.* INTO STRICT officer_authority
        FROM trust.resolve_officer_authority_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_command_name
        ) AS authority;
    END IF;

    SELECT policy.* INTO STRICT key_policy
    FROM trust.receipt_key_policy AS policy
    WHERE policy.singleton_key
    FOR SHARE;
    IF key_policy.active_canonicalization_version
            <> 'trust-command-json-v1'
       OR exact_idempotency_key_digest_key_ids
            IS DISTINCT FROM key_policy.retained_idempotency_key_ids
       OR exact_payload_hash_key_ids
            IS DISTINCT FROM key_policy.retained_payload_key_ids
       OR exact_idempotency_key_digest_key_ids[1]
            <> key_policy.active_idempotency_key_id
       OR exact_payload_hash_key_ids[1]
            <> key_policy.active_payload_key_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            concat_ws(
                E'\x1f',
                'desire:trust:receipt-lock:v1',
                exact_actor_user_id::text,
                exact_command_name,
                exact_idempotency_key_digest_key_ids[slot.index],
                encode(exact_idempotency_key_digests[slot.index], 'hex')
            ),
            0
        )
    )
    FROM generate_subscripts(
        exact_idempotency_key_digests,
        1
    ) AS slot(index)
    ORDER BY
        exact_idempotency_key_digest_key_ids[slot.index],
        encode(exact_idempotency_key_digests[slot.index], 'hex');

    SELECT count(*) INTO matching_count
    FROM trust.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_domain = 'TRUST_SAFETY'
      AND receipt.command_name = exact_command_name
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(
              exact_idempotency_key_digests,
              1
          ) AS slot(index)
          WHERE receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_ids[slot.index]
            AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digests[slot.index]
      );
    IF matching_count = 0 THEN
        RETURN;
    ELSIF matching_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_AMBIGUOUS';
    END IF;

    SELECT receipt.* INTO STRICT existing
    FROM trust.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_domain = 'TRUST_SAFETY'
      AND receipt.command_name = exact_command_name
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(
              exact_idempotency_key_digests,
              1
          ) AS slot(index)
          WHERE receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_ids[slot.index]
            AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digests[slot.index]
      )
    FOR SHARE;

    IF NOT EXISTS (
        SELECT 1
        FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
        WHERE exact_payload_hash_key_ids[slot.index]
                = existing.payload_hash_key_id
          AND exact_payload_hashes[slot.index] = existing.payload_hash
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'uq_trust_receipt_identity',
            MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
    END IF;
    IF existing.organization_id IS DISTINCT FROM exact_organization_id
       OR existing.http_method <> expected_method
       OR existing.canonical_path <> expected_path
       OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
       OR existing.canonicalization_version <> 'trust-command-json-v1'
       OR existing.retain_until <= evaluated_time
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_REPLAY_INVALID';
    END IF;
    IF existing.status <> 'COMPLETED' THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    IF existing.response_http_status <> expected_http_status
       OR existing.response_schema_name <> 'TrustCommandResult'
       OR existing.response_schema_version <> 1
       OR existing.target_case_id IS NULL
       OR existing.target_version IS NULL
       OR existing.target_version < 1
       OR existing.result_status <> expected_status
       OR existing.event_types <> ARRAY[expected_event_type]::text[]
       OR existing.completed_at IS NULL
       OR NOT trust.jsonb_has_exact_keys(
            existing.safe_response,
            ARRAY[
                'aggregate_version',
                'assignment_id',
                'case_id',
                'case_status',
                'completed_at',
                'event_types',
                'hold_id',
                'hold_version',
                'outcome_version_id',
                'report_id',
                'triage_draft_version',
                'triage_version'
            ]::text[]
       )
       OR existing.safe_response->>'case_id'
            <> existing.target_case_id::text
       OR (existing.safe_response->>'aggregate_version')::bigint
            <> existing.target_version
       OR existing.safe_response->>'case_status' <> expected_status
       OR existing.safe_response->'event_types'
            <> jsonb_build_array(expected_event_type)
       OR existing.safe_response->>'completed_at'
            <> trust.utc_timestamp_text_v1(existing.completed_at)
       OR existing.response_entity_tag <> trust.entity_tag_v1(
            'SafetyCase',
            existing.target_case_id,
            existing.target_version,
            existing.result_status,
            existing.completed_at
       )
       OR (
            exact_command_name <> 'SUBMIT_REPORT'
            AND NOT target_is_hold
            AND existing.target_case_id <> exact_target_id
       )
       OR (
            target_is_hold
            AND existing.safe_response->>'hold_id' <> exact_target_id::text
       )
       OR (
            exact_command_name = 'SUBMIT_REPORT'
            AND (
                jsonb_typeof(existing.safe_response->'report_id') <> 'string'
                OR existing.safe_response->'assignment_id' <> 'null'::jsonb
                OR existing.safe_response->'hold_id' <> 'null'::jsonb
                OR existing.safe_response->'outcome_version_id' <> 'null'::jsonb
            )
       )
       OR (
            exact_command_name IN (
                'CLAIM_CASE',
                'RELEASE_CASE_ASSIGNMENT',
                'CLAIM_HOLD_RELEASE'
            )
            AND jsonb_typeof(existing.safe_response->'assignment_id')
                <> 'string'
       )
       OR (
            exact_command_name = 'SAVE_TRIAGE_DRAFT'
            AND jsonb_typeof(existing.safe_response->'triage_draft_version')
                <> 'number'
       )
       OR (
            exact_command_name = 'PUBLISH_TRIAGE'
            AND jsonb_typeof(existing.safe_response->'triage_version')
                <> 'number'
       )
       OR (
            exact_command_name IN (
                'PLACE_HOLD',
                'CLAIM_HOLD_RELEASE',
                'RELEASE_HOLD'
            )
            AND (
                jsonb_typeof(existing.safe_response->'hold_id') <> 'string'
                OR jsonb_typeof(existing.safe_response->'hold_version')
                    <> 'number'
            )
       )
       OR (
            exact_command_name = 'PUBLISH_OUTCOME'
            AND jsonb_typeof(existing.safe_response->'outcome_version_id')
                <> 'string'
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    RETURN QUERY SELECT existing.safe_response, true;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

REVOKE ALL ON FUNCTION trust_api.read_completed_command_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint, text[], bytea[], text[], bytea[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_completed_command_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint, text[], bytea[], text[], bytea[]
) TO trust_self, trust_officer;

CREATE FUNCTION trust_api.submit_report_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_report_id uuid,
    exact_case_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_demand_id uuid,
    exact_demand_version_id uuid,
    exact_category text,
    exact_incident_started_at timestamptz,
    exact_incident_ended_at timestamptz,
    exact_impact_codes text[],
    exact_evidence_reference_ids uuid[],
    exact_requested_protection_codes text[]
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
    receipt_result record;
    authority record;
    target record;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_self'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_report_id IS NULL OR exact_report_id = zero_uuid
       OR exact_case_id IS NULL OR exact_case_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_demand_version_id IS NULL OR exact_demand_version_id = zero_uuid
       OR exact_incident_started_at IS NULL
       OR exact_incident_started_at > evaluated_time
       OR exact_incident_ended_at > evaluated_time
       OR exact_incident_ended_at < exact_incident_started_at
       OR cardinality(ARRAY[
            exact_actor_user_id,
            exact_organization_id,
            exact_report_id,
            exact_case_id,
            exact_demand_id,
            exact_demand_version_id
       ]::uuid[]) <> cardinality(ARRAY(
            SELECT DISTINCT value
            FROM unnest(ARRAY[
                exact_actor_user_id,
                exact_organization_id,
                exact_report_id,
                exact_case_id,
                exact_demand_id,
                exact_demand_version_id
            ]::uuid[]) AS item(value)
       ))
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', exact_organization_id::text, true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    -- Authentication/authority is re-proved before receipt replay.  A new
    -- active Session for the same actor may recover an unknown commit, while
    -- a revoked principal cannot use an old receipt as an authorization
    -- bypass.  Demand target resolution remains after the receipt gate.
    PERFORM set_config('app.scope_kind', 'TRUST_REPORTER', true);
    PERFORM set_config('app.operation', 'SUBMIT_REPORT', true);
    PERFORM set_config('app.session_id', exact_session_id::text, true);
    SELECT reporter.* INTO STRICT authority
    FROM iam_api.resolve_trust_reporter_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        'SUBMIT_REPORT'
    ) AS reporter
    WHERE reporter.actor_user_id = exact_actor_user_id
      AND reporter.session_id = exact_session_id
      AND reporter.organization_id = exact_organization_id
      AND reporter.user_status = 'ACTIVE'
      AND reporter.session_status = 'ACTIVE'
      AND reporter.session_family_status = 'ACTIVE'
      AND reporter.organization_status = 'ACTIVE'
      AND reporter.membership_status = 'ACTIVE'
      AND reporter.role_code = 'DEMAND_OWNER'
      AND reporter.membership_role_grant_version >= 1
      AND reporter.policy_requirements_satisfied
      AND octet_length(reporter.authority_marker_sha256) = 32;

    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        exact_organization_id,
        'SUBMIT_REPORT',
        'POST',
        '/v1/app/trust/reports',
        NULL,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;

    PERFORM set_config('app.membership_id', authority.membership_id::text, true);
    PERFORM set_config(
        'app.membership_role_grant_id',
        authority.membership_role_grant_id::text,
        true
    );
    PERFORM set_config(
        'app.membership_role_grant_version',
        authority.membership_role_grant_version::text,
        true
    );
    PERFORM set_config('app.demand_id', exact_demand_id::text, true);
    PERFORM set_config(
        'app.demand_version_id',
        exact_demand_version_id::text,
        true
    );
    PERFORM set_config('app.duty_grant_id', '', true);
    PERFORM set_config('app.duty_grant_version', '', true);
    SELECT demand_target.* INTO STRICT target
    FROM demand_api.resolve_trust_report_target_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        authority.membership_id,
        authority.membership_role_grant_id,
        authority.membership_role_grant_version,
        exact_demand_id,
        exact_demand_version_id,
        authority.authority_marker_sha256
    ) AS demand_target
    WHERE demand_target.organization_id = exact_organization_id
      AND demand_target.demand_id = exact_demand_id
      AND demand_target.demand_version_id = exact_demand_version_id
      AND demand_target.owner_user_id = exact_actor_user_id
      AND demand_target.demand_version_no >= 1
      AND demand_target.demand_aggregate_version >= 1
      AND demand_target.demand_status IN (
          'SUBMITTED',
          'NEEDS_CHANGES',
          'VERIFIED',
          'FUNDING_PENDING',
          'FUNDED',
          'MATCHING',
          'MATCHED',
          'NO_MATCH'
      )
      AND demand_target.reportable_until > evaluated_time
      AND octet_length(demand_target.content_sha256) = 32
      AND octet_length(demand_target.reporter_party_marker_sha256) = 32
      AND octet_length(demand_target.target_marker_sha256) = 32;

    PERFORM set_config('app.case_id', exact_case_id::text, true);
    INSERT INTO trust.reports (
        report_id,
        case_id,
        organization_id,
        demand_id,
        demand_version_id,
        demand_version_no,
        demand_aggregate_version,
        demand_status,
        demand_content_sha256,
        demand_owner_user_id,
        reportable_until,
        reporter_user_id,
        reporter_membership_id,
        reporter_role_grant_id,
        reporter_role_grant_version,
        reporter_authority_marker_sha256,
        reporter_party_marker_sha256,
        target_marker_sha256,
        category,
        incident_started_at,
        incident_ended_at,
        impact_codes,
        evidence_reference_ids,
        requested_protection_codes,
        created_at
    ) VALUES (
        exact_report_id,
        exact_case_id,
        target.organization_id,
        target.demand_id,
        target.demand_version_id,
        target.demand_version_no,
        target.demand_aggregate_version,
        target.demand_status,
        target.content_sha256,
        target.owner_user_id,
        target.reportable_until,
        exact_actor_user_id,
        authority.membership_id,
        authority.membership_role_grant_id,
        authority.membership_role_grant_version,
        authority.authority_marker_sha256,
        target.reporter_party_marker_sha256,
        target.target_marker_sha256,
        exact_category,
        exact_incident_started_at,
        exact_incident_ended_at,
        exact_impact_codes,
        exact_evidence_reference_ids,
        exact_requested_protection_codes,
        evaluated_time
    );
    INSERT INTO trust.cases (
        case_id,
        report_id,
        organization_id,
        demand_id,
        demand_version_id,
        reporter_user_id,
        status,
        aggregate_version,
        assigned_officer_user_id,
        assignment_id,
        assignment_expires_at,
        current_triage_draft_version,
        current_triage_version,
        outcome_version_id,
        opened_at,
        updated_at
    ) VALUES (
        exact_case_id,
        exact_report_id,
        target.organization_id,
        target.demand_id,
        target.demand_version_id,
        exact_actor_user_id,
        'OPEN',
        1,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        evaluated_time,
        evaluated_time
    );

    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        target.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        exact_case_id,
        NULL,
        NULL,
        'OPEN',
        1,
        'TrustReportSubmitted',
        jsonb_build_object(
            'case_id', exact_case_id,
            'case_status', 'OPEN',
            'demand_id', target.demand_id,
            'demand_version_id', target.demand_version_id,
            'organization_id', target.organization_id,
            'report_id', exact_report_id
        ),
        exact_report_id,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'RESOURCE_NOT_FOUND';
END
$function$;

REVOKE ALL ON FUNCTION trust_api.submit_report_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
    text[], bytea[], text[], bytea[], uuid, uuid, text, timestamptz,
    timestamptz, text[], uuid[], text[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.submit_report_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid,
    text[], bytea[], text[], bytea[], uuid, uuid, text, timestamptz,
    timestamptz, text[], uuid[], text[]
) TO trust_self;

CREATE FUNCTION trust_api.claim_case_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_assignment_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_case_id uuid,
    exact_expected_case_version bigint
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
    receipt_result record;
    authority record;
    conflict record;
    safety_case trust.cases%ROWTYPE;
    new_assignment_expires_at timestamptz;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_assignment_id IS NULL OR exact_assignment_id = zero_uuid
       OR exact_case_id IS NULL OR exact_case_id = zero_uuid
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'CLAIM_CASE'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'CLAIM_CASE',
        'POST',
        '/v1/app/trust/queue/{case_id}/claim',
        exact_expected_case_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    IF safety_case.aggregate_version <> exact_expected_case_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'OPEN' OR safety_case.assignment_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_ALREADY_ASSIGNED';
    END IF;
    SELECT checked.* INTO STRICT conflict
    FROM trust.resolve_officer_conflict_v1(
        exact_actor_user_id,
        exact_session_id,
        'CLAIM_CASE',
        authority.duty_grant_id,
        authority.duty_grant_version,
        authority.authority_marker_sha256,
        safety_case.organization_id,
        safety_case.demand_id,
        safety_case.demand_version_id
    ) AS checked;
    new_assignment_expires_at := evaluated_time + interval '4 hours';
    IF authority.duty_expires_at IS NOT NULL THEN
        new_assignment_expires_at := LEAST(
            new_assignment_expires_at,
            authority.duty_expires_at
        );
    END IF;
    IF new_assignment_expires_at <= evaluated_time THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    INSERT INTO trust.case_assignments (
        assignment_id,
        organization_id,
        case_id,
        assignment_purpose_code,
        hold_id,
        officer_user_id,
        excluded_officer_user_id,
        duty_grant_id,
        duty_grant_version,
        authority_marker_sha256,
        conflict_attestation_sha256,
        conflict_evaluated_at,
        conflict_valid_until,
        assigned_at,
        expires_at
    ) VALUES (
        exact_assignment_id,
        safety_case.organization_id,
        safety_case.case_id,
        'CASE_TRIAGE',
        NULL,
        exact_actor_user_id,
        NULL,
        authority.duty_grant_id,
        authority.duty_grant_version,
        authority.authority_marker_sha256,
        conflict.conflict_attestation_sha256,
        conflict.evaluated_at,
        conflict.valid_until,
        evaluated_time,
        new_assignment_expires_at
    );
    UPDATE trust.cases
    SET status = 'TRIAGING',
        aggregate_version = aggregate_version + 1,
        assigned_officer_user_id = exact_actor_user_id,
        assignment_id = exact_assignment_id,
        assignment_expires_at = new_assignment_expires_at,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;

    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        safety_case.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        'TRIAGING',
        safety_case.aggregate_version + 1,
        'TrustCaseClaimed',
        jsonb_build_object(
            'assignment_expires_at',
                trust.utc_timestamp_text_v1(new_assignment_expires_at),
            'assignment_id', exact_assignment_id,
            'case_id', safety_case.case_id,
            'case_status', 'TRIAGING'
        ),
        NULL,
        exact_assignment_id,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.claim_case_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.claim_case_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint
) TO trust_officer;

CREATE FUNCTION trust_api.release_case_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_case_id uuid,
    exact_expected_case_version bigint,
    exact_reason_code text
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
    receipt_result record;
    authority record;
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_case_id IS NULL
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
       OR exact_reason_code NOT IN (
            'CONFLICT_DECLARED',
            'WORKLOAD_RELEASE',
            'ASSIGNMENT_EXPIRED'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'RELEASE_CASE_ASSIGNMENT'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'RELEASE_CASE_ASSIGNMENT',
        'POST',
        '/v1/app/trust/cases/{case_id}/assignment/release',
        exact_expected_case_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    IF safety_case.aggregate_version <> exact_expected_case_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'TRIAGING' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_ASSIGNMENT_REQUIRED';
    END IF;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        exact_reason_code = 'ASSIGNMENT_EXPIRED'
    );
    IF exact_reason_code = 'ASSIGNMENT_EXPIRED'
       AND evaluated_time < assignment.expires_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'ASSIGNMENT_NOT_EXPIRED';
    END IF;
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );
    INSERT INTO trust.case_assignment_releases (
        assignment_id,
        organization_id,
        case_id,
        released_by_user_id,
        reason_code,
        released_at
    ) VALUES (
        assignment.assignment_id,
        safety_case.organization_id,
        safety_case.case_id,
        exact_actor_user_id,
        exact_reason_code,
        evaluated_time
    );
    UPDATE trust.cases
    SET status = 'OPEN',
        aggregate_version = aggregate_version + 1,
        assigned_officer_user_id = NULL,
        assignment_id = NULL,
        assignment_expires_at = NULL,
        current_triage_draft_version = NULL,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        safety_case.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        'OPEN',
        safety_case.aggregate_version + 1,
        'TrustCaseAssignmentReleased',
        jsonb_build_object(
            'assignment_id', assignment.assignment_id,
            'case_id', safety_case.case_id,
            'case_status', 'OPEN'
        ),
        NULL,
        assignment.assignment_id,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.release_case_assignment_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.release_case_assignment_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text
) TO trust_officer;

CREATE FUNCTION trust_api.save_triage_draft_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_case_id uuid,
    exact_expected_case_version bigint,
    exact_priority_code text,
    exact_jurisdiction_code text,
    exact_severity_code text,
    exact_issue_codes text[],
    exact_investigation_step_codes text[],
    exact_proposed_hold_actions text[],
    exact_proposed_hold_ttl_minutes integer,
    exact_sealed_note_reference text,
    exact_sealed_note_sha256 bytea
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
    receipt_result record;
    authority record;
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    next_draft_version integer;
    content_digest bytea;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_case_id IS NULL
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
       OR exact_sealed_note_reference IS NULL
       OR exact_sealed_note_reference
            !~ '^sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}$'
       OR exact_sealed_note_sha256 IS NULL
       OR octet_length(exact_sealed_note_sha256) <> 32
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'SAVE_TRIAGE_DRAFT'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'SAVE_TRIAGE_DRAFT',
        'PUT',
        '/v1/app/trust/cases/{case_id}/triage-draft',
        exact_expected_case_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    IF safety_case.aggregate_version <> exact_expected_case_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'TRIAGING' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_STATE_CONFLICT';
    END IF;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        false
    );
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );
    next_draft_version := COALESCE(
        safety_case.current_triage_draft_version,
        0
    ) + 1;
    content_digest := trust.triage_content_sha256_v1(
        exact_priority_code,
        exact_jurisdiction_code,
        exact_severity_code,
        exact_issue_codes,
        exact_investigation_step_codes,
        exact_proposed_hold_actions,
        exact_proposed_hold_ttl_minutes,
        exact_sealed_note_reference,
        exact_sealed_note_sha256
    );
    INSERT INTO trust.triage_drafts (
        organization_id,
        case_id,
        draft_version,
        assignment_id,
        priority_code,
        jurisdiction_code,
        severity_code,
        issue_codes,
        investigation_step_codes,
        proposed_hold_actions,
        proposed_hold_ttl_minutes,
        sealed_note_reference,
        sealed_note_sha256,
        content_sha256,
        edited_by_user_id,
        edited_at
    ) VALUES (
        safety_case.organization_id,
        safety_case.case_id,
        next_draft_version,
        assignment.assignment_id,
        exact_priority_code,
        exact_jurisdiction_code,
        exact_severity_code,
        exact_issue_codes,
        exact_investigation_step_codes,
        exact_proposed_hold_actions,
        exact_proposed_hold_ttl_minutes,
        exact_sealed_note_reference,
        exact_sealed_note_sha256,
        content_digest,
        exact_actor_user_id,
        evaluated_time
    );
    UPDATE trust.cases
    SET aggregate_version = aggregate_version + 1,
        current_triage_draft_version = next_draft_version,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        safety_case.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        'TRIAGING',
        safety_case.aggregate_version + 1,
        'TrustTriageDraftSaved',
        jsonb_build_object(
            'case_id', safety_case.case_id,
            'case_status', 'TRIAGING',
            'triage_draft_version', next_draft_version
        ),
        NULL,
        NULL,
        next_draft_version,
        NULL,
        NULL,
        NULL,
        NULL
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.save_triage_draft_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text, text, text, text[], text[], text[],
    integer, text, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.save_triage_draft_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text, text, text, text[], text[], text[],
    integer, text, bytea
) TO trust_officer;

CREATE FUNCTION trust_api.publish_triage_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_case_id uuid,
    exact_expected_case_version bigint,
    exact_expected_draft_version integer
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
    receipt_result record;
    authority record;
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    draft trust.triage_drafts%ROWTYPE;
    next_triage_version integer;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_case_id IS NULL
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
       OR exact_expected_draft_version IS NULL
       OR exact_expected_draft_version < 1
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'PUBLISH_TRIAGE'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'PUBLISH_TRIAGE',
        'POST',
        '/v1/app/trust/cases/{case_id}/triage-publish',
        exact_expected_case_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    IF safety_case.aggregate_version <> exact_expected_case_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'TRIAGING'
       OR safety_case.current_triage_draft_version
            IS DISTINCT FROM exact_expected_draft_version
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRIAGE_VERSION_CONFLICT';
    END IF;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        false
    );
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );
    SELECT draft_row.* INTO STRICT draft
    FROM trust.triage_drafts AS draft_row
    WHERE draft_row.case_id = safety_case.case_id
      AND draft_row.draft_version = exact_expected_draft_version;
    next_triage_version := COALESCE(safety_case.current_triage_version, 0) + 1;
    INSERT INTO trust.triage_versions (
        organization_id,
        case_id,
        triage_version,
        source_draft_version,
        assignment_id,
        priority_code,
        jurisdiction_code,
        severity_code,
        issue_codes,
        investigation_step_codes,
        proposed_hold_actions,
        proposed_hold_ttl_minutes,
        sealed_note_reference,
        sealed_note_sha256,
        content_sha256,
        published_by_user_id,
        published_at
    ) VALUES (
        safety_case.organization_id,
        safety_case.case_id,
        next_triage_version,
        draft.draft_version,
        assignment.assignment_id,
        draft.priority_code,
        draft.jurisdiction_code,
        draft.severity_code,
        draft.issue_codes,
        draft.investigation_step_codes,
        draft.proposed_hold_actions,
        draft.proposed_hold_ttl_minutes,
        draft.sealed_note_reference,
        draft.sealed_note_sha256,
        draft.content_sha256,
        exact_actor_user_id,
        evaluated_time
    );
    UPDATE trust.cases
    SET status = 'IN_REVIEW',
        aggregate_version = aggregate_version + 1,
        current_triage_version = next_triage_version,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        safety_case.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        'IN_REVIEW',
        safety_case.aggregate_version + 1,
        'TrustTriagePublished',
        jsonb_build_object(
            'case_id', safety_case.case_id,
            'case_status', 'IN_REVIEW',
            'triage_version', next_triage_version
        ),
        NULL,
        NULL,
        NULL,
        next_triage_version,
        NULL,
        NULL,
        NULL
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.publish_triage_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.publish_triage_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, integer
) TO trust_officer;

CREATE FUNCTION trust_api.place_hold_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_hold_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_case_id uuid,
    exact_expected_case_version bigint,
    exact_action_codes text[],
    exact_reason_code text,
    exact_hold_ttl_minutes integer
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
    receipt_result record;
    authority record;
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    triage trust.triage_versions%ROWTYPE;
    hold_expires_at timestamptz;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_hold_id IS NULL OR exact_hold_id = zero_uuid
       OR exact_case_id IS NULL OR exact_case_id = zero_uuid
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
       OR exact_hold_ttl_minutes IS NULL
       OR exact_hold_ttl_minutes NOT BETWEEN 15 AND 10080
       OR exact_reason_code NOT IN (
            'PARTICIPANT_SAFETY_RISK',
            'RETALIATION_RISK',
            'SYNTHETIC_DATA_EXPOSURE_RISK',
            'WORKFLOW_INTEGRITY_RISK'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'PLACE_HOLD'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'PLACE_HOLD',
        'POST',
        '/v1/app/trust/cases/{case_id}/holds',
        exact_expected_case_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    IF safety_case.aggregate_version <> exact_expected_case_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'IN_REVIEW'
       OR safety_case.current_triage_version IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_STATE_CONFLICT';
    END IF;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        false
    );
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );
    PERFORM set_config('app.demand_id', safety_case.demand_id::text, true);
    SELECT triage_row.* INTO STRICT triage
    FROM trust.triage_versions AS triage_row
    WHERE triage_row.case_id = safety_case.case_id
      AND triage_row.triage_version = safety_case.current_triage_version;
    IF NOT trust.canonical_code_array_v1(exact_action_codes, 1, 3)
       OR NOT exact_action_codes <@ triage.proposed_hold_actions
       OR exact_hold_ttl_minutes > triage.proposed_hold_ttl_minutes
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'HOLD_VALIDATION_FAILED';
    END IF;
    hold_expires_at := evaluated_time
        + make_interval(mins => exact_hold_ttl_minutes);
    INSERT INTO trust.safety_holds (
        hold_id,
        organization_id,
        case_id,
        demand_id,
        demand_version_id,
        triage_version,
        action_codes,
        reason_code,
        status,
        policy_version,
        issued_by_user_id,
        issue_assignment_id,
        effective_at,
        expires_at,
        aggregate_version,
        requires_independent_release,
        release_assignment_id,
        released_at,
        released_by_user_id,
        release_reason_code
    ) VALUES (
        exact_hold_id,
        safety_case.organization_id,
        safety_case.case_id,
        safety_case.demand_id,
        safety_case.demand_version_id,
        triage.triage_version,
        exact_action_codes,
        exact_reason_code,
        'ACTIVE',
        'trust-demand-hold-v1',
        exact_actor_user_id,
        assignment.assignment_id,
        evaluated_time,
        hold_expires_at,
        1,
        exact_reason_code IN (
            'PARTICIPANT_SAFETY_RISK',
            'RETALIATION_RISK'
        ),
        NULL,
        NULL,
        NULL,
        NULL
    );
    UPDATE trust.cases
    SET aggregate_version = aggregate_version + 1,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        safety_case.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        'IN_REVIEW',
        safety_case.aggregate_version + 1,
        'SafetyHoldPlaced',
        jsonb_build_object(
            'action_codes', to_jsonb(exact_action_codes),
            'case_id', safety_case.case_id,
            'case_status', 'IN_REVIEW',
            'expires_at', trust.utc_timestamp_text_v1(hold_expires_at),
            'hold_id', exact_hold_id,
            'hold_status', 'ACTIVE',
            'hold_version', 1
        ),
        NULL,
        NULL,
        NULL,
        NULL,
        exact_hold_id,
        1,
        NULL
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.place_hold_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text[], text, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.place_hold_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text[], text, integer
) TO trust_officer;

CREATE FUNCTION trust_api.claim_hold_release_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_assignment_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_hold_id uuid,
    exact_expected_hold_version bigint
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
    receipt_result record;
    authority record;
    conflict record;
    hold trust.safety_holds%ROWTYPE;
    safety_case trust.cases%ROWTYPE;
    prior_assignment trust.case_assignments%ROWTYPE;
    assignment_expires_at timestamptz;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_assignment_id IS NULL OR exact_assignment_id = zero_uuid
       OR exact_hold_id IS NULL OR exact_hold_id = zero_uuid
       OR exact_expected_hold_version IS NULL
       OR exact_expected_hold_version < 1
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'CLAIM_HOLD_RELEASE'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'CLAIM_HOLD_RELEASE',
        'POST',
        '/v1/app/trust/hold-release-queue/{hold_id}/claim',
        exact_expected_hold_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT hold_row.* INTO STRICT hold
    FROM trust.safety_holds AS hold_row
    WHERE hold_row.hold_id = exact_hold_id
    FOR UPDATE;
    PERFORM set_config('app.case_id', hold.case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = hold.case_id
    FOR UPDATE;
    IF hold.aggregate_version <> exact_expected_hold_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'IN_REVIEW'
       OR hold.status <> 'ACTIVE'
       OR hold.effective_at > evaluated_time
       OR evaluated_time >= hold.expires_at
       OR NOT hold.requires_independent_release
       OR hold.reason_code NOT IN (
            'PARTICIPANT_SAFETY_RISK',
            'RETALIATION_RISK'
       )
       OR exact_actor_user_id = hold.issued_by_user_id
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'INDEPENDENT_REVIEW_REQUIRED';
    END IF;
    IF hold.release_assignment_id IS NOT NULL THEN
        SELECT assignment_row.* INTO STRICT prior_assignment
        FROM trust.case_assignments AS assignment_row
        WHERE assignment_row.case_id = hold.case_id
          AND assignment_row.assignment_id = hold.release_assignment_id
          AND assignment_row.assignment_purpose_code = 'HOLD_RELEASE';
        IF prior_assignment.expires_at > evaluated_time
           AND NOT EXISTS (
               SELECT 1
               FROM trust.case_assignment_releases AS release_row
               WHERE release_row.assignment_id = prior_assignment.assignment_id
           )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'HOLD_RELEASE_ALREADY_ASSIGNED';
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM trust.case_assignment_releases AS release_row
            WHERE release_row.assignment_id = prior_assignment.assignment_id
        ) THEN
            INSERT INTO trust.case_assignment_releases (
                assignment_id,
                organization_id,
                case_id,
                released_by_user_id,
                reason_code,
                released_at
            ) VALUES (
                prior_assignment.assignment_id,
                hold.organization_id,
                hold.case_id,
                exact_actor_user_id,
                'HOLD_RELEASE_REASSIGNED',
                evaluated_time
            );
        END IF;
    END IF;
    SELECT checked.* INTO STRICT conflict
    FROM trust.resolve_officer_conflict_v1(
        exact_actor_user_id,
        exact_session_id,
        'CLAIM_HOLD_RELEASE',
        authority.duty_grant_id,
        authority.duty_grant_version,
        authority.authority_marker_sha256,
        hold.organization_id,
        hold.demand_id,
        hold.demand_version_id
    ) AS checked;
    assignment_expires_at := LEAST(
        evaluated_time + interval '4 hours',
        hold.expires_at
    );
    IF authority.duty_expires_at IS NOT NULL THEN
        assignment_expires_at := LEAST(
            assignment_expires_at,
            authority.duty_expires_at
        );
    END IF;
    IF assignment_expires_at <= evaluated_time THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.organization_id', hold.organization_id::text, true);
    PERFORM set_config('app.demand_id', hold.demand_id::text, true);
    INSERT INTO trust.case_assignments (
        assignment_id,
        organization_id,
        case_id,
        assignment_purpose_code,
        hold_id,
        officer_user_id,
        excluded_officer_user_id,
        duty_grant_id,
        duty_grant_version,
        authority_marker_sha256,
        conflict_attestation_sha256,
        conflict_evaluated_at,
        conflict_valid_until,
        assigned_at,
        expires_at
    ) VALUES (
        exact_assignment_id,
        hold.organization_id,
        hold.case_id,
        'HOLD_RELEASE',
        hold.hold_id,
        exact_actor_user_id,
        hold.issued_by_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        authority.authority_marker_sha256,
        conflict.conflict_attestation_sha256,
        conflict.evaluated_at,
        conflict.valid_until,
        evaluated_time,
        assignment_expires_at
    );
    UPDATE trust.safety_holds
    SET aggregate_version = aggregate_version + 1,
        release_assignment_id = exact_assignment_id
    WHERE hold_id = hold.hold_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        hold.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        safety_case.status,
        safety_case.aggregate_version,
        'TrustHoldReleaseClaimed',
        jsonb_build_object(
            'action_codes', to_jsonb(hold.action_codes),
            'assignment_expires_at',
                trust.utc_timestamp_text_v1(assignment_expires_at),
            'assignment_id', exact_assignment_id,
            'case_id', safety_case.case_id,
            'case_status', safety_case.status,
            'expires_at', trust.utc_timestamp_text_v1(hold.expires_at),
            'hold_id', hold.hold_id,
            'hold_status', 'ACTIVE',
            'hold_version', hold.aggregate_version + 1
        ),
        NULL,
        exact_assignment_id,
        NULL,
        NULL,
        hold.hold_id,
        hold.aggregate_version + 1,
        NULL
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.claim_hold_release_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.claim_hold_release_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint
) TO trust_officer;

CREATE FUNCTION trust_api.release_hold_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_hold_id uuid,
    exact_expected_hold_version bigint,
    exact_release_reason_code text
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
    receipt_result record;
    authority record;
    hold trust.safety_holds%ROWTYPE;
    safety_case trust.cases%ROWTYPE;
    case_assignment trust.case_assignments%ROWTYPE;
    release_assignment trust.case_assignments%ROWTYPE;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_hold_id IS NULL
       OR exact_expected_hold_version IS NULL
       OR exact_expected_hold_version < 1
       OR exact_release_reason_code NOT IN (
            'CASE_DECIDED',
            'RISK_MITIGATED',
            'SUPERSEDED',
            'TTL_CORRECTION'
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'RELEASE_HOLD'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'RELEASE_HOLD',
        'POST',
        '/v1/app/trust/holds/{hold_id}/release',
        exact_expected_hold_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    SELECT hold_row.* INTO STRICT hold
    FROM trust.safety_holds AS hold_row
    WHERE hold_row.hold_id = exact_hold_id
    FOR UPDATE;
    PERFORM set_config('app.case_id', hold.case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = hold.case_id
    FOR UPDATE;
    IF hold.aggregate_version <> exact_expected_hold_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'IN_REVIEW'
       OR hold.status <> 'ACTIVE'
       OR hold.effective_at > evaluated_time
       OR evaluated_time >= hold.expires_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'HOLD_STATE_CONFLICT';
    END IF;
    PERFORM set_config('app.organization_id', hold.organization_id::text, true);
    PERFORM set_config('app.demand_id', hold.demand_id::text, true);
    IF hold.requires_independent_release THEN
        IF hold.release_assignment_id IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'INDEPENDENT_REVIEW_REQUIRED';
        END IF;
        SELECT assignment_row.* INTO STRICT release_assignment
        FROM trust.case_assignments AS assignment_row
        WHERE assignment_row.case_id = hold.case_id
          AND assignment_row.assignment_id = hold.release_assignment_id
          AND assignment_row.assignment_purpose_code = 'HOLD_RELEASE'
          AND assignment_row.hold_id = hold.hold_id
          AND assignment_row.officer_user_id = exact_actor_user_id
          AND assignment_row.excluded_officer_user_id = hold.issued_by_user_id
          AND assignment_row.officer_user_id <> hold.issued_by_user_id
          AND assignment_row.duty_grant_id = authority.duty_grant_id
          AND assignment_row.duty_grant_version
                = authority.duty_grant_version
          AND assignment_row.assigned_at <= evaluated_time
          AND evaluated_time < assignment_row.expires_at
          AND assignment_row.expires_at <= hold.expires_at
          AND octet_length(assignment_row.conflict_attestation_sha256) = 32
          AND NOT EXISTS (
              SELECT 1
              FROM trust.case_assignment_releases AS release_row
              WHERE release_row.assignment_id = assignment_row.assignment_id
          );
        INSERT INTO trust.case_assignment_releases (
            assignment_id,
            organization_id,
            case_id,
            released_by_user_id,
            reason_code,
            released_at
        ) VALUES (
            release_assignment.assignment_id,
            hold.organization_id,
            hold.case_id,
            exact_actor_user_id,
            'HOLD_RELEASE_COMPLETED',
            evaluated_time
        );
    ELSE
        case_assignment := trust.require_case_assignment_v1(
            safety_case.case_id,
            exact_actor_user_id,
            authority.duty_grant_id,
            authority.duty_grant_version,
            false
        );
    END IF;
    UPDATE trust.safety_holds
    SET status = 'RELEASED',
        aggregate_version = aggregate_version + 1,
        released_at = evaluated_time,
        released_by_user_id = exact_actor_user_id,
        release_reason_code = exact_release_reason_code
    WHERE hold_id = hold.hold_id;
    UPDATE trust.cases
    SET aggregate_version = aggregate_version + 1,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        hold.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        safety_case.status,
        safety_case.aggregate_version + 1,
        'SafetyHoldReleased',
        jsonb_build_object(
            'action_codes', to_jsonb(hold.action_codes),
            'case_id', safety_case.case_id,
            'case_status', safety_case.status,
            'expires_at', trust.utc_timestamp_text_v1(hold.expires_at),
            'hold_id', hold.hold_id,
            'hold_status', 'RELEASED',
            'hold_version', hold.aggregate_version + 1
        ),
        NULL,
        NULL,
        NULL,
        NULL,
        hold.hold_id,
        hold.aggregate_version + 1,
        NULL
    );
    RETURN QUERY SELECT completed, false;
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'INDEPENDENT_REVIEW_REQUIRED';
END
$function$;

REVOKE ALL ON FUNCTION trust_api.release_hold_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.release_hold_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text
) TO trust_officer;

CREATE FUNCTION trust_api.read_outcome_evidence_source_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_case_id uuid,
    exact_expected_case_version bigint,
    exact_outcome_code text,
    exact_reason_codes text[],
    exact_action_codes text[]
)
RETURNS TABLE (
    canonical_source_document text,
    evaluated_at timestamptz,
    valid_until timestamptz
)
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
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    source_document text;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_case_id IS NULL
       OR exact_case_id = zero_uuid
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
       OR exact_outcome_code NOT IN (
            'NO_ACTION',
            'PROTECTION_LIFTED',
            'PROTECTION_MAINTAINED',
            'PROTECTION_MODIFIED',
            'REMEDIATION_REQUIRED'
       )
       OR NOT trust.canonical_code_array_v1(exact_reason_codes, 1, 8)
       OR NOT exact_reason_codes <@ ARRAY[
            'INSUFFICIENT_VERIFIED_EVIDENCE',
            'NO_POLICY_BREACH',
            'POLICY_REQUIREMENT_NOT_MET',
            'PRECAUTIONARY_ACTION_REQUIRED',
            'RISK_MITIGATED'
       ]::text[]
       OR NOT trust.canonical_code_array_v1(exact_action_codes, 0, 3)
       OR NOT exact_action_codes <@ ARRAY[
            'REQUEST_MATCHING',
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND'
       ]::text[]
       OR (
            exact_outcome_code IN ('NO_ACTION', 'PROTECTION_LIFTED')
            AND cardinality(exact_action_codes) <> 0
       )
       OR (
            exact_outcome_code NOT IN ('NO_ACTION', 'PROTECTION_LIFTED')
            AND cardinality(exact_action_codes) = 0
       )
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'PUBLISH_OUTCOME'
    ) AS officer;
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id;
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );
    PERFORM set_config('app.demand_id', safety_case.demand_id::text, true);
    IF safety_case.aggregate_version <> exact_expected_case_version
       OR safety_case.status <> 'IN_REVIEW'
       OR safety_case.outcome_version_id IS NOT NULL
       OR safety_case.current_triage_version IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        false
    );
    source_document := trust.outcome_source_document_v1(
        exact_case_id,
        exact_outcome_code,
        exact_reason_codes,
        exact_action_codes,
        evaluated_time
    );
    IF source_document IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_STATE_CONFLICT';
    END IF;
    RETURN QUERY SELECT
        source_document,
        evaluated_time,
        evaluated_time + interval '5 minutes';
EXCEPTION
    WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ACCESS_DENIED';
END
$function$;

REVOKE ALL ON FUNCTION trust_api.read_outcome_evidence_source_v1(
    uuid, uuid, uuid, bigint, text, text[], text[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_outcome_evidence_source_v1(
    uuid, uuid, uuid, bigint, text, text[], text[]
) TO trust_officer;

CREATE FUNCTION trust_api.publish_outcome_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_outcome_version_id uuid,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[],
    exact_case_id uuid,
    exact_expected_case_version bigint,
    exact_outcome_code text,
    exact_reason_codes text[],
    exact_action_codes text[],
    evidence_case_id uuid,
    evidence_case_aggregate_version bigint,
    evidence_triage_version integer,
    evidence_outcome_code text,
    evidence_reason_codes text[],
    evidence_action_codes text[],
    evidence_packet_version_id uuid,
    evidence_packet_digest bytea,
    evidence_source_digest bytea,
    evidence_appeal_eligible boolean,
    evidence_appeal_eligibility_code text,
    evidence_appeal_deadline timestamptz,
    evidence_policy_version text,
    evidence_redaction_profile_code text,
    evidence_evaluated_at timestamptz,
    evidence_valid_until timestamptz
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
    receipt_result record;
    authority record;
    safety_case trust.cases%ROWTYPE;
    assignment trust.case_assignments%ROWTYPE;
    triage trust.triage_versions%ROWTYPE;
    expected_source_document text;
    expected_source_digest bytea;
    expected_evidence_packet_digest bytea;
    content_digest bytea;
    completed jsonb;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_outcome_version_id IS NULL
       OR exact_outcome_version_id = zero_uuid
       OR exact_case_id IS NULL OR exact_case_id = zero_uuid
       OR exact_expected_case_version IS NULL
       OR exact_expected_case_version < 1
       OR evidence_case_id IS DISTINCT FROM exact_case_id
       OR evidence_case_aggregate_version
            IS DISTINCT FROM exact_expected_case_version
       OR evidence_outcome_code IS DISTINCT FROM exact_outcome_code
       OR evidence_reason_codes IS DISTINCT FROM exact_reason_codes
       OR evidence_action_codes IS DISTINCT FROM exact_action_codes
       OR evidence_packet_version_id IS NULL
       OR evidence_packet_version_id = zero_uuid
       OR evidence_packet_digest IS NULL
       OR octet_length(evidence_packet_digest) <> 32
       OR evidence_source_digest IS NULL
       OR octet_length(evidence_source_digest) <> 32
       OR evidence_appeal_eligible IS DISTINCT FROM true
       OR evidence_appeal_eligibility_code <> 'ELIGIBLE'
       OR evidence_appeal_deadline IS DISTINCT FROM
            evidence_evaluated_at + interval '7 days'
       OR evidence_policy_version <> 'trust-case-outcome-v1'
       OR evidence_redaction_profile_code <> 'PARTY_SAFE_V1'
       OR evidence_evaluated_at IS NULL
       OR evidence_valid_until IS NULL
       OR evidence_evaluated_at > evaluated_time
       OR evidence_valid_until IS DISTINCT FROM
            evidence_evaluated_at + interval '5 minutes'
       OR evidence_valid_until <= evaluated_time
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;
    PERFORM set_config('app.trust_scope_kind', 'TRUST_COMMAND', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    SELECT officer.* INTO STRICT authority
    FROM trust.resolve_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'PUBLISH_OUTCOME'
    ) AS officer;
    SELECT receipt.* INTO STRICT receipt_result
    FROM trust.claim_or_replay_receipt_v1(
        exact_receipt_id,
        exact_actor_user_id,
        NULL,
        'PUBLISH_OUTCOME',
        'POST',
        '/v1/app/trust/cases/{case_id}/decisions',
        exact_expected_case_version,
        exact_idempotency_key_digest_key_ids,
        exact_idempotency_key_digests,
        exact_payload_hash_key_ids,
        exact_payload_hashes
    ) AS receipt;
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.replay_safe_response, true;
        RETURN;
    END IF;
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    SELECT case_row.* INTO STRICT safety_case
    FROM trust.cases AS case_row
    WHERE case_row.case_id = exact_case_id
    FOR UPDATE;
    IF safety_case.aggregate_version <> exact_expected_case_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'PRECONDITION_FAILED';
    END IF;
    IF safety_case.status <> 'IN_REVIEW'
       OR safety_case.outcome_version_id IS NOT NULL
       OR safety_case.current_triage_version IS NULL
       OR evidence_triage_version
            IS DISTINCT FROM safety_case.current_triage_version
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_STATE_CONFLICT';
    END IF;
    assignment := trust.require_case_assignment_v1(
        exact_case_id,
        exact_actor_user_id,
        authority.duty_grant_id,
        authority.duty_grant_version,
        false
    );
    PERFORM set_config(
        'app.organization_id',
        safety_case.organization_id::text,
        true
    );
    SELECT triage_row.* INTO STRICT triage
    FROM trust.triage_versions AS triage_row
    WHERE triage_row.case_id = safety_case.case_id
      AND triage_row.triage_version = evidence_triage_version;
    PERFORM 1
    FROM trust.safety_holds AS hold_row
    WHERE hold_row.case_id = safety_case.case_id
    FOR SHARE;
    IF exact_outcome_code NOT IN (
            'NO_ACTION',
            'PROTECTION_LIFTED',
            'PROTECTION_MAINTAINED',
            'PROTECTION_MODIFIED',
            'REMEDIATION_REQUIRED'
       )
       OR NOT trust.canonical_code_array_v1(exact_reason_codes, 1, 8)
       OR NOT exact_reason_codes <@ ARRAY[
            'INSUFFICIENT_VERIFIED_EVIDENCE',
            'NO_POLICY_BREACH',
            'POLICY_REQUIREMENT_NOT_MET',
            'PRECAUTIONARY_ACTION_REQUIRED',
            'RISK_MITIGATED'
       ]::text[]
       OR NOT trust.canonical_code_array_v1(exact_action_codes, 0, 3)
       OR NOT exact_action_codes <@ ARRAY[
            'REQUEST_MATCHING',
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND'
       ]::text[]
       OR (
            exact_outcome_code IN ('NO_ACTION', 'PROTECTION_LIFTED')
            AND cardinality(exact_action_codes) <> 0
       )
       OR (
            exact_outcome_code NOT IN ('NO_ACTION', 'PROTECTION_LIFTED')
            AND cardinality(exact_action_codes) = 0
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'CASE_DECISION_VALIDATION_FAILED';
    END IF;
    expected_source_document := trust.outcome_source_document_v1(
        safety_case.case_id,
        exact_outcome_code,
        exact_reason_codes,
        exact_action_codes,
        evaluated_time
    );
    expected_source_digest := trust.outcome_source_sha256_v1(
        expected_source_document
    );
    expected_evidence_packet_digest :=
        trust.outcome_evidence_packet_sha256_v1(
            evidence_packet_version_id,
            expected_source_digest,
            exact_outcome_code,
            exact_reason_codes,
            exact_action_codes,
            evidence_appeal_eligibility_code,
            evidence_appeal_deadline,
            evidence_policy_version,
            evidence_redaction_profile_code,
            evidence_evaluated_at,
            evidence_valid_until
        );
    IF expected_source_document IS NULL
       OR evidence_source_digest IS DISTINCT FROM expected_source_digest
       OR evidence_packet_digest
            IS DISTINCT FROM expected_evidence_packet_digest
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'CASE_STATE_CONFLICT';
    END IF;
    content_digest := trust.outcome_content_sha256_v1(
        safety_case.case_id,
        exact_outcome_code,
        exact_reason_codes,
        exact_action_codes,
        evidence_packet_version_id,
        evidence_packet_digest,
        evidence_source_digest,
        evidence_redaction_profile_code,
        evidence_appeal_eligible,
        evidence_appeal_eligibility_code,
        evidence_appeal_deadline
    );
    INSERT INTO trust.case_outcome_versions (
        outcome_version_id,
        organization_id,
        case_id,
        outcome_version,
        outcome_code,
        reason_codes,
        action_codes,
        evidence_packet_version_id,
        evidence_packet_digest,
        source_digest,
        redaction_profile_code,
        appeal_eligible,
        appeal_eligibility_code,
        appeal_deadline,
        policy_version,
        decided_by_user_id,
        decision_assignment_id,
        decided_at,
        content_sha256
    ) VALUES (
        exact_outcome_version_id,
        safety_case.organization_id,
        safety_case.case_id,
        1,
        exact_outcome_code,
        exact_reason_codes,
        exact_action_codes,
        evidence_packet_version_id,
        evidence_packet_digest,
        evidence_source_digest,
        evidence_redaction_profile_code,
        evidence_appeal_eligible,
        evidence_appeal_eligibility_code,
        evidence_appeal_deadline,
        'trust-case-outcome-v1',
        exact_actor_user_id,
        assignment.assignment_id,
        evaluated_time,
        content_digest
    );
    UPDATE trust.cases
    SET status = 'DECIDED',
        aggregate_version = aggregate_version + 1,
        outcome_version_id = exact_outcome_version_id,
        updated_at = evaluated_time
    WHERE case_id = safety_case.case_id;
    completed := trust.complete_command_v1(
        receipt_result.claimed_receipt_id,
        exact_audit_event_id,
        exact_outbox_event_id,
        exact_actor_user_id,
        safety_case.organization_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        safety_case.case_id,
        safety_case.status,
        safety_case.aggregate_version,
        'DECIDED',
        safety_case.aggregate_version + 1,
        'TrustCaseOutcomePublished',
        jsonb_build_object(
            'action_codes', to_jsonb(exact_action_codes),
            'appeal_deadline', CASE
                WHEN evidence_appeal_deadline IS NULL THEN NULL::text
                ELSE trust.utc_timestamp_text_v1(evidence_appeal_deadline)
            END,
            'appeal_eligibility_code', evidence_appeal_eligibility_code,
            'appeal_eligible', evidence_appeal_eligible,
            'case_id', safety_case.case_id,
            'case_status', 'DECIDED',
            'content_sha256', encode(content_digest, 'hex'),
            'outcome_code', exact_outcome_code,
            'outcome_version', 1,
            'outcome_version_id', exact_outcome_version_id
        ),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        exact_outcome_version_id
    );
    RETURN QUERY SELECT completed, false;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.publish_outcome_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text, text[], text[], uuid, bigint,
    integer, text, text[], text[], uuid, bytea, bytea, boolean, text,
    timestamptz, text, text, timestamptz, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.publish_outcome_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, text[], bytea[],
    text[], bytea[], uuid, bigint, text, text[], text[], uuid, bigint,
    integer, text, text[], text[], uuid, bytea, bytea, boolean, text,
    timestamptz, text, text, timestamptz, timestamptz
) TO trust_officer;

CREATE FUNCTION trust_api.read_own_report_v1(
    query_actor_user_id uuid,
    query_session_id uuid,
    query_organization_id uuid,
    query_report_id uuid
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
    authority_count integer;
BEGIN
    IF current_user <> 'trust_schema_owner'
       OR session_user <> 'trust_self'
       OR query_actor_user_id IS NULL
       OR query_session_id IS NULL
       OR query_organization_id IS NULL
       OR query_report_id IS NULL
       OR query_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_report_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind', 'TRUST_REPORTER', true);
    PERFORM set_config('app.operation', 'READ_OWN_REPORT', true);
    PERFORM set_config('app.actor_id', query_actor_user_id::text, true);
    PERFORM set_config('app.session_id', query_session_id::text, true);
    PERFORM set_config('app.organization_id', query_organization_id::text, true);

    SELECT count(*)
    INTO authority_count
    FROM iam_api.resolve_trust_reporter_authority_v1(
        query_actor_user_id,
        query_session_id,
        query_organization_id,
        'READ_OWN_REPORT'
    ) AS authority
    WHERE authority.actor_user_id = query_actor_user_id
      AND authority.session_id = query_session_id
      AND authority.organization_id = query_organization_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.organization_status = 'ACTIVE'
      AND authority.membership_status = 'ACTIVE'
      AND authority.role_code = 'DEMAND_OWNER'
      AND authority.membership_role_grant_version >= 1
      AND authority.policy_requirements_satisfied
      AND octet_length(authority.authority_marker_sha256) = 32;
    IF authority_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_REPORT_READ', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    SELECT jsonb_build_object(
        'demand_id', report.demand_id,
        'demand_version_id', report.demand_version_id,
        'entity_tag', trust.entity_tag_v1(
            'SafetyCase',
            safety_case.case_id,
            safety_case.aggregate_version,
            safety_case.status,
            safety_case.updated_at
        ),
        'outcome', CASE
            WHEN outcome.outcome_version_id IS NULL THEN 'null'::jsonb
            ELSE jsonb_build_object(
                'action_codes', to_jsonb(outcome.action_codes),
                'appeal_deadline', to_jsonb(outcome.appeal_deadline),
                'appeal_eligibility_code', outcome.appeal_eligibility_code,
                'content_sha256', encode(outcome.content_sha256, 'hex'),
                'decided_at', outcome.decided_at,
                'evidence_packet_digest',
                    encode(outcome.evidence_packet_digest, 'hex'),
                'evidence_packet_version_id', outcome.evidence_packet_version_id,
                'outcome_code', outcome.outcome_code,
                'outcome_version_id', outcome.outcome_version_id,
                'policy_version', outcome.policy_version,
                'reason_codes', to_jsonb(outcome.reason_codes),
                'redaction_profile_code', outcome.redaction_profile_code,
                'source_digest', encode(outcome.source_digest, 'hex')
            )
        END,
        'report', jsonb_build_object(
            'category', report.category,
            'evidence_reference_ids', to_jsonb(report.evidence_reference_ids),
            'impact_codes', to_jsonb(report.impact_codes),
            'incident_ended_at', to_jsonb(report.incident_ended_at),
            'incident_started_at', to_jsonb(report.incident_started_at),
            'requested_protection_codes',
                to_jsonb(report.requested_protection_codes)
        ),
        'report_id', report.report_id,
        'status', safety_case.status,
        'submitted_at', report.created_at
    )
    FROM trust.reports AS report
    JOIN trust.cases AS safety_case
      ON safety_case.case_id = report.case_id
     AND safety_case.organization_id = report.organization_id
    LEFT JOIN trust.case_outcome_versions AS outcome
      ON outcome.case_id = safety_case.case_id
     AND outcome.outcome_version_id = safety_case.outcome_version_id
    WHERE report.organization_id = query_organization_id
      AND report.report_id = query_report_id
      AND report.reporter_user_id = query_actor_user_id;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.read_own_report_v1(
    uuid, uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_own_report_v1(
    uuid, uuid, uuid, uuid
) TO trust_self;

CREATE FUNCTION trust_api.list_safety_case_queue_v1(
    query_actor_user_id uuid,
    query_session_id uuid,
    query_limit integer
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
    authority_count integer;
BEGIN
    IF current_user <> 'trust_schema_owner'
       OR session_user <> 'trust_officer'
       OR query_actor_user_id IS NULL
       OR query_session_id IS NULL
       OR query_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_limit IS NULL
       OR query_limit NOT BETWEEN 1 AND 100
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind', 'TRUST_OFFICER', true);
    PERFORM set_config('app.operation', 'LIST_CASE_QUEUE', true);
    PERFORM set_config('app.actor_id', query_actor_user_id::text, true);
    PERFORM set_config('app.session_id', query_session_id::text, true);
    PERFORM set_config('app.organization_id', '', true);

    SELECT count(*)
    INTO authority_count
    FROM iam_api.resolve_trust_officer_authority_v1(
        query_actor_user_id,
        query_session_id,
        'LIST_CASE_QUEUE'
    ) AS authority
    WHERE authority.actor_user_id = query_actor_user_id
      AND authority.session_id = query_session_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.duty_code = 'TRUST_OFFICER'
      AND authority.duty_grant_version >= 1
      AND (
          authority.duty_expires_at IS NULL
          OR transaction_timestamp() < authority.duty_expires_at
      )
      AND octet_length(authority.authority_marker_sha256) = 32;
    IF authority_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_QUEUE_READ', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    WITH queue_rows AS MATERIALIZED (
        SELECT
            safety_case.case_id,
            safety_case.aggregate_version,
            safety_case.opened_at,
            jsonb_build_object(
                'case_id', safety_case.case_id,
                'category', report.category,
                'demand_id', safety_case.demand_id,
                'demand_version_id', safety_case.demand_version_id,
                'entity_tag', trust.entity_tag_v1(
                    'SafetyCase',
                    safety_case.case_id,
                    safety_case.aggregate_version,
                    safety_case.status,
                    safety_case.updated_at
                ),
                'impact_codes', to_jsonb(report.impact_codes),
                'report_id', report.report_id,
                'submitted_at', report.created_at
            ) AS item
        FROM trust.cases AS safety_case
        JOIN trust.reports AS report
          ON report.case_id = safety_case.case_id
         AND report.organization_id = safety_case.organization_id
        WHERE safety_case.status = 'OPEN'
          AND safety_case.assignment_id IS NULL
        ORDER BY safety_case.opened_at, safety_case.case_id
        LIMIT query_limit
    ), queue_document AS (
        SELECT
            COALESCE(
                jsonb_agg(item ORDER BY opened_at, case_id),
                '[]'::jsonb
            ) AS items,
            COALESCE(max(aggregate_version), 1)::bigint AS collection_version
        FROM queue_rows
    )
    SELECT jsonb_build_object(
        'entity_tag', format(
            '"trust-%s-%s"',
            queue_document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:case-queue:v1' || E'\x1f'
                    || queue_document.items::text,
                'UTF8'
            )), 'hex'), 24)
        ),
        'items', queue_document.items
    )
    FROM queue_document;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.list_safety_case_queue_v1(
    uuid, uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_safety_case_queue_v1(
    uuid, uuid, integer
) TO trust_officer;

CREATE FUNCTION trust_api.list_hold_release_queue_v1(
    query_actor_user_id uuid,
    query_session_id uuid,
    query_limit integer
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
    authority_count integer;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user <> 'trust_schema_owner'
       OR session_user <> 'trust_officer'
       OR query_actor_user_id IS NULL
       OR query_session_id IS NULL
       OR query_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_limit IS NULL
       OR query_limit NOT BETWEEN 1 AND 100
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind', 'TRUST_OFFICER', true);
    PERFORM set_config('app.operation', 'LIST_HOLD_RELEASE_QUEUE', true);
    PERFORM set_config('app.actor_id', query_actor_user_id::text, true);
    PERFORM set_config('app.session_id', query_session_id::text, true);
    PERFORM set_config('app.organization_id', '', true);

    SELECT count(*)
    INTO authority_count
    FROM iam_api.resolve_trust_officer_authority_v1(
        query_actor_user_id,
        query_session_id,
        'LIST_HOLD_RELEASE_QUEUE'
    ) AS authority
    WHERE authority.actor_user_id = query_actor_user_id
      AND authority.session_id = query_session_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.duty_code = 'TRUST_OFFICER'
      AND authority.duty_grant_version >= 1
      AND (
          authority.duty_expires_at IS NULL
          OR evaluated_time < authority.duty_expires_at
      )
      AND octet_length(authority.authority_marker_sha256) = 32;
    IF authority_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM set_config(
        'app.trust_scope_kind',
        'TRUST_HOLD_RELEASE_QUEUE_READ',
        true
    );
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    WITH queue_rows AS MATERIALIZED (
        SELECT
            hold.hold_id,
            hold.aggregate_version,
            hold.effective_at,
            jsonb_build_object(
                'action_codes', to_jsonb(hold.action_codes),
                'case_id', hold.case_id,
                'demand_id', hold.demand_id,
                'demand_version_id', hold.demand_version_id,
                'entity_tag', trust.entity_tag_v1(
                    'SafetyHold',
                    hold.hold_id,
                    hold.aggregate_version,
                    hold.status,
                    hold.effective_at
                ),
                'expires_at', hold.expires_at,
                'hold_id', hold.hold_id,
                'reason_code', hold.reason_code
            ) AS item
        FROM trust.safety_holds AS hold
        JOIN trust.cases AS safety_case
          ON safety_case.case_id = hold.case_id
         AND safety_case.organization_id = hold.organization_id
        LEFT JOIN trust.case_assignments AS release_assignment
          ON release_assignment.assignment_id = hold.release_assignment_id
         AND release_assignment.case_id = hold.case_id
        LEFT JOIN trust.case_assignment_releases AS release_record
          ON release_record.assignment_id = release_assignment.assignment_id
        WHERE safety_case.status = 'IN_REVIEW'
          AND hold.status = 'ACTIVE'
          AND hold.requires_independent_release
          AND hold.reason_code IN (
              'PARTICIPANT_SAFETY_RISK',
              'RETALIATION_RISK'
          )
          AND hold.effective_at <= evaluated_time
          AND evaluated_time < hold.expires_at
          AND (
              hold.release_assignment_id IS NULL
              OR release_assignment.expires_at <= evaluated_time
              OR release_record.assignment_id IS NOT NULL
          )
        ORDER BY hold.expires_at, hold.hold_id
        LIMIT query_limit
    ), queue_document AS (
        SELECT
            COALESCE(
                jsonb_agg(item ORDER BY effective_at, hold_id),
                '[]'::jsonb
            ) AS items,
            COALESCE(max(aggregate_version), 1)::bigint AS collection_version
        FROM queue_rows
    )
    SELECT jsonb_build_object(
        'entity_tag', format(
            '"trust-%s-%s"',
            queue_document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:hold-release-queue:v1' || E'\x1f'
                    || queue_document.items::text,
                'UTF8'
            )), 'hex'), 24)
        ),
        'items', queue_document.items
    )
    FROM queue_document;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.list_hold_release_queue_v1(
    uuid, uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_hold_release_queue_v1(
    uuid, uuid, integer
) TO trust_officer;

CREATE FUNCTION trust_api.read_assigned_case_v1(
    query_actor_user_id uuid,
    query_session_id uuid,
    query_case_id uuid
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
    authority_count integer;
    resolved_duty_grant_id uuid;
    resolved_duty_grant_version bigint;
    evaluated_time timestamptz := transaction_timestamp();
BEGIN
    IF current_user <> 'trust_schema_owner'
       OR session_user <> 'trust_officer'
       OR query_actor_user_id IS NULL
       OR query_session_id IS NULL
       OR query_case_id IS NULL
       OR query_actor_user_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_session_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_case_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind', 'TRUST_OFFICER', true);
    PERFORM set_config('app.operation', 'READ_ASSIGNED_CASE', true);
    PERFORM set_config('app.actor_id', query_actor_user_id::text, true);
    PERFORM set_config('app.session_id', query_session_id::text, true);
    PERFORM set_config('app.organization_id', '', true);

    SELECT
        count(*),
        (array_agg(authority.duty_grant_id))[1],
        (array_agg(authority.duty_grant_version))[1]
    INTO
        authority_count,
        resolved_duty_grant_id,
        resolved_duty_grant_version
    FROM iam_api.resolve_trust_officer_authority_v1(
        query_actor_user_id,
        query_session_id,
        'READ_ASSIGNED_CASE'
    ) AS authority
    WHERE authority.actor_user_id = query_actor_user_id
      AND authority.session_id = query_session_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.duty_code = 'TRUST_OFFICER'
      AND authority.duty_grant_version >= 1
      AND (
          authority.duty_expires_at IS NULL
          OR evaluated_time < authority.duty_expires_at
      )
      AND octet_length(authority.authority_marker_sha256) = 32;
    IF authority_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_CASE_READ', true);
    PERFORM set_config('app.case_id', query_case_id::text, true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    SELECT jsonb_build_object(
        'active_hold', CASE
            WHEN active_hold.hold_id IS NULL THEN 'null'::jsonb
            ELSE jsonb_build_object(
                'action_codes', to_jsonb(active_hold.action_codes),
                'effective_at', active_hold.effective_at,
                'entity_tag', trust.entity_tag_v1(
                    'SafetyHold',
                    active_hold.hold_id,
                    active_hold.aggregate_version,
                    active_hold.status,
                    active_hold.effective_at
                ),
                'expires_at', active_hold.expires_at,
                'hold_id', active_hold.hold_id,
                'status', active_hold.status
            )
        END,
        'aggregate_version', safety_case.aggregate_version,
        'case_id', safety_case.case_id,
        'demand_id', safety_case.demand_id,
        'demand_version_id', safety_case.demand_version_id,
        'entity_tag', trust.entity_tag_v1(
            'SafetyCase',
            safety_case.case_id,
            safety_case.aggregate_version,
            safety_case.status,
            safety_case.updated_at
        ),
        'outcome', CASE
            WHEN outcome.outcome_version_id IS NULL THEN 'null'::jsonb
            ELSE jsonb_build_object(
                'action_codes', to_jsonb(outcome.action_codes),
                'appeal_deadline', to_jsonb(outcome.appeal_deadline),
                'appeal_eligibility_code', outcome.appeal_eligibility_code,
                'content_sha256', encode(outcome.content_sha256, 'hex'),
                'decided_at', outcome.decided_at,
                'evidence_packet_digest',
                    encode(outcome.evidence_packet_digest, 'hex'),
                'evidence_packet_version_id', outcome.evidence_packet_version_id,
                'outcome_code', outcome.outcome_code,
                'outcome_version_id', outcome.outcome_version_id,
                'policy_version', outcome.policy_version,
                'reason_codes', to_jsonb(outcome.reason_codes),
                'redaction_profile_code', outcome.redaction_profile_code,
                'source_digest', encode(outcome.source_digest, 'hex')
            )
        END,
        'report', jsonb_build_object(
            'category', report.category,
            'evidence_reference_ids', to_jsonb(report.evidence_reference_ids),
            'impact_codes', to_jsonb(report.impact_codes),
            'incident_ended_at', to_jsonb(report.incident_ended_at),
            'incident_started_at', to_jsonb(report.incident_started_at),
            'requested_protection_codes',
                to_jsonb(report.requested_protection_codes)
        ),
        'report_id', report.report_id,
        'status', safety_case.status,
        'triage_draft', CASE
            WHEN draft.draft_version IS NULL THEN 'null'::jsonb
            ELSE jsonb_build_object(
                'content', jsonb_build_object(
                    'investigation_step_codes',
                        to_jsonb(draft.investigation_step_codes),
                    'issue_codes', to_jsonb(draft.issue_codes),
                    'jurisdiction_code', draft.jurisdiction_code,
                    'priority_code', draft.priority_code,
                    'proposed_hold_actions',
                        to_jsonb(draft.proposed_hold_actions),
                    'proposed_hold_ttl_minutes',
                        draft.proposed_hold_ttl_minutes,
                    'sealed_note_reference', draft.sealed_note_reference,
                    'sealed_note_sha256', encode(draft.sealed_note_sha256, 'hex'),
                    'severity_code', draft.severity_code
                ),
                'content_sha256', encode(draft.content_sha256, 'hex'),
                'saved_at', draft.edited_at,
                'triage_version', draft.draft_version
            )
        END
    )
    FROM trust.cases AS safety_case
    JOIN trust.reports AS report
      ON report.case_id = safety_case.case_id
     AND report.organization_id = safety_case.organization_id
    LEFT JOIN trust.triage_drafts AS draft
      ON draft.case_id = safety_case.case_id
     AND draft.draft_version = safety_case.current_triage_draft_version
    LEFT JOIN trust.case_outcome_versions AS outcome
      ON outcome.case_id = safety_case.case_id
     AND outcome.outcome_version_id = safety_case.outcome_version_id
    LEFT JOIN LATERAL (
        SELECT hold.*
        FROM trust.safety_holds AS hold
        WHERE hold.case_id = safety_case.case_id
          AND hold.status = 'ACTIVE'
          AND hold.effective_at <= evaluated_time
          AND evaluated_time < hold.expires_at
        ORDER BY hold.effective_at DESC, hold.hold_id
        LIMIT 1
    ) AS active_hold ON true
    WHERE safety_case.case_id = query_case_id
      AND safety_case.status IN ('TRIAGING', 'IN_REVIEW', 'DECIDED')
      AND (
          EXISTS (
              SELECT 1
              FROM trust.case_assignments AS assignment
              WHERE assignment.assignment_id = safety_case.assignment_id
                AND assignment.case_id = safety_case.case_id
                AND assignment.assignment_purpose_code = 'CASE_TRIAGE'
                AND assignment.officer_user_id = query_actor_user_id
                AND assignment.duty_grant_id = resolved_duty_grant_id
                AND assignment.duty_grant_version
                    = resolved_duty_grant_version
                AND assignment.assigned_at <= evaluated_time
                AND evaluated_time < assignment.expires_at
                AND NOT EXISTS (
                    SELECT 1
                    FROM trust.case_assignment_releases AS release_record
                    WHERE release_record.assignment_id
                        = assignment.assignment_id
                )
          )
          OR (
              safety_case.status = 'IN_REVIEW'
              AND EXISTS (
                  SELECT 1
                  FROM trust.case_assignments AS assignment
                  JOIN trust.safety_holds AS assigned_hold
                    ON assigned_hold.hold_id = assignment.hold_id
                   AND assigned_hold.case_id = assignment.case_id
                   AND assigned_hold.release_assignment_id
                        = assignment.assignment_id
                  WHERE assignment.case_id = safety_case.case_id
                    AND assignment.assignment_purpose_code = 'HOLD_RELEASE'
                    AND assignment.officer_user_id = query_actor_user_id
                    AND assignment.duty_grant_id = resolved_duty_grant_id
                    AND assignment.duty_grant_version
                        = resolved_duty_grant_version
                    AND assignment.excluded_officer_user_id
                        = assigned_hold.issued_by_user_id
                    AND assignment.officer_user_id
                        <> assignment.excluded_officer_user_id
                    AND assignment.assigned_at <= evaluated_time
                    AND evaluated_time < assignment.expires_at
                    AND assignment.expires_at <= assigned_hold.expires_at
                    AND assigned_hold.status = 'ACTIVE'
                    AND assigned_hold.requires_independent_release
                    AND assigned_hold.reason_code IN (
                        'PARTICIPANT_SAFETY_RISK',
                        'RETALIATION_RISK'
                    )
                    AND assigned_hold.effective_at <= evaluated_time
                    AND evaluated_time < assigned_hold.expires_at
                    AND NOT EXISTS (
                        SELECT 1
                        FROM trust.case_assignment_releases AS release_record
                        WHERE release_record.assignment_id
                            = assignment.assignment_id
                    )
              )
          )
      );
END
$function$;

REVOKE ALL ON FUNCTION trust_api.read_assigned_case_v1(
    uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_assigned_case_v1(
    uuid, uuid, uuid
) TO trust_officer;

CREATE FUNCTION trust_api.evaluate_demand_hold_v1(
    query_actor_id uuid,
    query_organization_id uuid,
    query_demand_id uuid,
    query_prospective_aggregate_version bigint,
    query_demand_version_id uuid,
    query_content_sha256 bytea,
    query_action text,
    query_policy_version text
)
RETURNS TABLE (
    actor_id uuid,
    organization_id uuid,
    demand_id uuid,
    prospective_aggregate_version bigint,
    demand_version_id uuid,
    content_sha256 bytea,
    action text,
    policy_version text,
    decision varchar(5),
    evidence_sha256 bytea,
    evaluated_at timestamptz,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    evaluated_time timestamptz := transaction_timestamp();
    blocker_document jsonb;
    blocker_valid_until timestamptz;
    is_blocked boolean;
    result_valid_until timestamptz;
    result_evidence_sha256 bytea;
BEGIN
    IF current_user <> 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_decision'
       OR query_actor_id IS NULL
       OR query_actor_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_organization_id IS NULL
       OR query_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_demand_id IS NULL
       OR query_demand_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_demand_version_id IS NULL
       OR query_demand_version_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR query_prospective_aggregate_version IS NULL
       OR query_prospective_aggregate_version < 1
       OR query_content_sha256 IS NULL
       OR octet_length(query_content_sha256) <> 32
       OR query_action NOT IN (
            'SUBMIT_DEMAND',
            'VERIFY_DEMAND',
            'REQUEST_MATCHING'
       )
       OR query_policy_version <> 'demand-safety-hold-v1'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'TRUST_HOLD_QUERY_INVALID';
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_HOLD_EVALUATION', true);
    PERFORM set_config('app.actor_id', query_actor_id::text, true);
    PERFORM set_config('app.organization_id', query_organization_id::text, true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', query_demand_id::text, true);

    SELECT
        COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'aggregate_version', hold.aggregate_version,
                    'expires_at', to_char(
                        hold.expires_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                    ),
                    'hold_id', hold.hold_id::text,
                    'policy_version', hold.policy_version
                )
                ORDER BY hold.hold_id
            ),
            '[]'::jsonb
        ),
        min(hold.expires_at),
        count(*) > 0
    INTO blocker_document, blocker_valid_until, is_blocked
    FROM trust.safety_holds AS hold
    WHERE hold.organization_id = query_organization_id
      AND hold.demand_id = query_demand_id
      AND hold.demand_version_id = query_demand_version_id
      AND hold.status = 'ACTIVE'
      AND hold.effective_at <= evaluated_time
      AND evaluated_time < hold.expires_at
      AND query_action = ANY(hold.action_codes);

    result_valid_until := CASE
        WHEN is_blocked THEN LEAST(
            blocker_valid_until,
            evaluated_time + interval '15 seconds'
        )
        ELSE evaluated_time + interval '15 seconds'
    END;
    result_evidence_sha256 := sha256(convert_to(
        concat_ws(
            E'\x1f',
            'TRUST_HOLD_EVALUATION_V1',
            query_actor_id::text,
            query_organization_id::text,
            query_demand_id::text,
            query_prospective_aggregate_version::text,
            query_demand_version_id::text,
            encode(query_content_sha256, 'hex'),
            query_action,
            query_policy_version,
            CASE WHEN is_blocked THEN 'BLOCK' ELSE 'ALLOW' END,
            to_char(
                evaluated_time AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            ),
            to_char(
                result_valid_until AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            ),
            blocker_document::text
        ),
        'UTF8'
    ));

    RETURN QUERY SELECT
        query_actor_id,
        query_organization_id,
        query_demand_id,
        query_prospective_aggregate_version,
        query_demand_version_id,
        query_content_sha256,
        query_action,
        query_policy_version,
        (CASE WHEN is_blocked THEN 'BLOCK' ELSE 'ALLOW' END)::varchar(5),
        result_evidence_sha256,
        evaluated_time,
        result_valid_until;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.evaluate_demand_hold_v1(
    uuid, uuid, uuid, bigint, uuid, bytea, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.evaluate_demand_hold_v1(
    uuid, uuid, uuid, bigint, uuid, bytea, text, text
) TO trust_decision;

SET LOCAL ROLE schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO trust_schema_owner;
GRANT INSERT ON audit.audit_events TO trust_schema_owner;
GRANT INSERT ON infra.outbox_events TO trust_schema_owner;

CREATE POLICY rls_trust_audit_insert
ON audit.audit_events
FOR INSERT TO trust_schema_owner
WITH CHECK (
    session_user IN (
        'trust_self',
        'trust_officer',
        'trust_appeal',
        'trust_decision'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true),
        ''
    )::uuid
    AND target_kind = 'SafetyCase'
    AND target_id = NULLIF(current_setting('app.case_id', true), '')::uuid
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NOT safe_attributes ?| ARRAY[
        'reporter_user_id',
        'demand_owner_user_id',
        'session_id',
        'authority_marker_sha256',
        'reporter_party_marker_sha256',
        'target_marker_sha256',
        'sealed_note_reference',
        'sealed_note_sha256'
    ]::text[]
);

CREATE POLICY rls_trust_outbox_insert
ON infra.outbox_events
FOR INSERT TO trust_schema_owner
WITH CHECK (
    session_user IN (
        'trust_self',
        'trust_officer',
        'trust_appeal',
        'trust_decision'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true),
        ''
    )::uuid
    AND aggregate_type = 'SafetyCase'
    AND aggregate_id = NULLIF(current_setting('app.case_id', true), '')::uuid
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NOT payload ?| ARRAY[
        'reporter_user_id',
        'demand_owner_user_id',
        'session_id',
        'authority_marker_sha256',
        'reporter_party_marker_sha256',
        'target_marker_sha256',
        'sealed_note_reference',
        'sealed_note_sha256'
    ]::text[]
);

SET LOCAL ROLE trust_schema_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA trust FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA trust_meta FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA trust FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA trust_api FROM PUBLIC;
