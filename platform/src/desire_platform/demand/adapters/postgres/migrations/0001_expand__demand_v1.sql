-- Independent Demand PostgreSQL 18 schema, fixed authority surfaces, and RLS.

CREATE SCHEMA demand AUTHORIZATION demand_schema_owner;
CREATE SCHEMA demand_meta AUTHORIZATION demand_schema_owner;
REVOKE ALL ON SCHEMA demand, demand_meta FROM PUBLIC;

CREATE TABLE demand_meta.schema_migrations (
    component varchar(32) NOT NULL,
    version integer NOT NULL,
    phase varchar(16) NOT NULL,
    name varchar(128) NOT NULL,
    checksum_sha256 bytea NOT NULL,
    manifest_sha256 bytea NOT NULL,
    runner_version varchar(96) NOT NULL,
    applied_at timestamptz NOT NULL,
    CONSTRAINT pk_demand_schema_migrations PRIMARY KEY (component, version),
    CONSTRAINT ck_demand_migration_component CHECK (component = 'demand'),
    CONSTRAINT ck_demand_migration_phase CHECK (
        phase IN ('expand', 'migrate', 'contract')
    ),
    CONSTRAINT ck_demand_migration_hashes CHECK (
        octet_length(checksum_sha256) = 32
        AND octet_length(manifest_sha256) = 32
    )
);

CREATE TABLE demand_meta.schema_contracts (
    singleton_key boolean PRIMARY KEY,
    schema_head_version integer NOT NULL,
    min_app_compatible_version integer NOT NULL,
    max_app_compatible_version integer NOT NULL,
    required_iam_schema_version integer NOT NULL,
    api_contract_sha256 bytea NOT NULL,
    event_contract_sha256 bytea NOT NULL,
    content_contract_sha256 bytea NOT NULL,
    migration_manifest_sha256 bytea NOT NULL,
    generated_at timestamptz NOT NULL,
    CONSTRAINT ck_demand_schema_contract_singleton CHECK (singleton_key),
    CONSTRAINT ck_demand_schema_contract_versions CHECK (
        schema_head_version >= 1
        AND min_app_compatible_version >= 1
        AND max_app_compatible_version >= min_app_compatible_version
        AND required_iam_schema_version >= 16
    ),
    CONSTRAINT ck_demand_schema_contract_hashes CHECK (
        octet_length(api_contract_sha256) = 32
        AND octet_length(event_contract_sha256) = 32
        AND octet_length(content_contract_sha256) = 32
        AND octet_length(migration_manifest_sha256) = 32
    )
);

CREATE VIEW demand.schema_compatibility AS
SELECT
    'demand'::text AS component,
    COALESCE((SELECT max(version) FROM demand_meta.schema_migrations), 0)::integer
        AS current_schema_version,
    schema_head_version,
    min_app_compatible_version,
    max_app_compatible_version,
    required_iam_schema_version,
    migration_manifest_sha256
FROM demand_meta.schema_contracts
WHERE singleton_key;

CREATE TABLE demand.demands (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    creator_user_id uuid NOT NULL,
    client_reference_digest_key_id varchar(128) NOT NULL,
    client_reference_digest bytea NOT NULL,
    status varchar(32) NOT NULL,
    aggregate_version bigint NOT NULL,
    current_version_id uuid NOT NULL,
    current_submission_id uuid NULL,
    current_review_id uuid NULL,
    verified_version_id uuid NULL,
    current_funding_marker_id uuid NULL,
    current_matching_request_id uuid NULL,
    expires_at timestamptz NOT NULL,
    terminal_at timestamptz NULL,
    terminal_reason_code varchar(64) NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_demand_client_reference UNIQUE (
        organization_id,
        client_reference_digest_key_id,
        client_reference_digest
    ),
    CONSTRAINT uq_demand_org_id UNIQUE (organization_id, id),
    CONSTRAINT ck_demand_client_digest CHECK (
        octet_length(client_reference_digest) = 32
    ),
    CONSTRAINT ck_demand_status CHECK (
        status IN (
            'DRAFT', 'SUBMITTED', 'NEEDS_CHANGES', 'VERIFIED',
            'FUNDING_PENDING', 'FUNDED', 'MATCHING', 'MATCHED', 'NO_MATCH',
            'CANCELLED', 'EXPIRED'
        )
    ),
    CONSTRAINT ck_demand_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_demand_terminal_shape CHECK (
        (
            status IN ('CANCELLED', 'EXPIRED')
            AND terminal_at IS NOT NULL
            AND terminal_reason_code IS NOT NULL
        )
        OR
        (
            status NOT IN ('CANCELLED', 'EXPIRED')
            AND terminal_at IS NULL
            AND terminal_reason_code IS NULL
        )
    ),
    CONSTRAINT ck_demand_pointer_shape CHECK (
        (status IN ('DRAFT', 'SUBMITTED', 'NEEDS_CHANGES')
            AND verified_version_id IS NULL
            AND current_funding_marker_id IS NULL
            AND current_matching_request_id IS NULL)
        OR
        (status IN ('VERIFIED', 'FUNDING_PENDING')
            AND verified_version_id = current_version_id
            AND current_funding_marker_id IS NULL
            AND current_matching_request_id IS NULL)
        OR
        (status IN ('FUNDED', 'NO_MATCH')
            AND verified_version_id = current_version_id
            AND current_funding_marker_id IS NOT NULL
            AND current_matching_request_id IS NULL)
        OR
        (status IN ('MATCHING', 'MATCHED')
            AND verified_version_id = current_version_id
            AND current_funding_marker_id IS NOT NULL
            AND current_matching_request_id IS NOT NULL)
        OR status IN ('CANCELLED', 'EXPIRED')
    ),
    CONSTRAINT ck_demand_times CHECK (
        expires_at >= created_at AND updated_at >= created_at
        AND (terminal_at IS NULL OR terminal_at >= created_at)
    )
);

CREATE TABLE demand.demand_versions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    version_no integer NOT NULL,
    based_on_demand_version_id uuid NULL,
    demand_schema_version integer NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    canonical_version_bytes bytea NOT NULL,
    content jsonb NOT NULL,
    content_sha256 bytea NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT uq_demand_version_no UNIQUE (
        organization_id, demand_id, version_no
    ),
    CONSTRAINT uq_demand_version_org_id UNIQUE (organization_id, demand_id, id),
    CONSTRAINT fk_demand_version_root FOREIGN KEY (organization_id, demand_id)
        REFERENCES demand.demands (organization_id, id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_demand_version_number CHECK (version_no >= 1),
    CONSTRAINT ck_demand_version_base CHECK (
        (version_no = 1 AND based_on_demand_version_id IS NULL)
        OR (version_no > 1 AND based_on_demand_version_id IS NOT NULL)
    ),
    CONSTRAINT ck_demand_version_contract CHECK (
        demand_schema_version = 1
        AND canonicalization_version = 'demand-content-json-v1'
        AND octet_length(canonical_version_bytes) BETWEEN 1 AND 1048576
        AND jsonb_typeof(content) = 'object'
        AND octet_length(content_sha256) = 32
    )
);

ALTER TABLE demand.demands
ADD CONSTRAINT fk_demand_current_version
FOREIGN KEY (organization_id, id, current_version_id)
REFERENCES demand.demand_versions (organization_id, demand_id, id)
DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE demand.demand_submissions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    content_sha256 bytea NOT NULL,
    submitted_by_user_id uuid NOT NULL,
    content_policy_version varchar(64) NOT NULL,
    content_policy_result_sha256 bytea NOT NULL,
    rule_requirement_sha256 bytea NOT NULL,
    submitted_at timestamptz NOT NULL,
    CONSTRAINT uq_demand_submission_version UNIQUE (
        organization_id, demand_id, demand_version_id
    ),
    CONSTRAINT uq_demand_submission_org_id UNIQUE (organization_id, demand_id, id),
    CONSTRAINT fk_demand_submission_version FOREIGN KEY (
        organization_id, demand_id, demand_version_id
    ) REFERENCES demand.demand_versions (organization_id, demand_id, id),
    CONSTRAINT ck_demand_submission_hashes CHECK (
        octet_length(content_sha256) = 32
        AND octet_length(content_policy_result_sha256) = 32
        AND octet_length(rule_requirement_sha256) = 32
    )
);

CREATE TABLE demand.demand_review_assignments (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL,
    duty_grant_id uuid NOT NULL,
    duty_grant_version bigint NOT NULL,
    purpose_code varchar(64) NOT NULL,
    conflict_attestation_sha256 bytea NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    status varchar(16) NOT NULL,
    expires_at timestamptz NOT NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_demand_review_assignment_org_id UNIQUE (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_demand_assignment_submission FOREIGN KEY (
        organization_id, demand_id, submission_id
    ) REFERENCES demand.demand_submissions (organization_id, demand_id, id),
    CONSTRAINT ck_demand_assignment_status CHECK (
        status IN ('ACTIVE', 'COMPLETED', 'REVOKED')
    ),
    CONSTRAINT ck_demand_assignment_shape CHECK (
        purpose_code = 'DEMAND_REVIEW'
        AND duty_grant_version >= 1
        AND aggregate_version >= 1
        AND octet_length(conflict_attestation_sha256) = 32
        AND octet_length(authority_marker_sha256) = 32
        AND ((status = 'ACTIVE' AND completed_at IS NULL)
            OR (status <> 'ACTIVE' AND completed_at IS NOT NULL))
    )
);

CREATE UNIQUE INDEX uq_demand_active_review_assignment
ON demand.demand_review_assignments (organization_id, demand_id)
WHERE status = 'ACTIVE';

CREATE TABLE demand.demand_reviews (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    content_sha256 bytea NOT NULL,
    assignment_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL,
    decision varchar(32) NOT NULL,
    reason_codes text[] NOT NULL,
    required_field_codes text[] NOT NULL,
    budget_health_code varchar(32) NULL,
    risk_code varchar(32) NULL,
    evidence_summary_sha256 bytea NULL,
    rule_requirement_sha256 bytea NULL,
    reviewed_at timestamptz NOT NULL,
    CONSTRAINT uq_demand_review_assignment UNIQUE (assignment_id),
    CONSTRAINT uq_demand_review_org_id UNIQUE (organization_id, demand_id, id),
    CONSTRAINT fk_demand_review_assignment FOREIGN KEY (
        organization_id, demand_id, assignment_id
    ) REFERENCES demand.demand_review_assignments (organization_id, demand_id, id),
    CONSTRAINT fk_demand_review_submission FOREIGN KEY (
        organization_id, demand_id, submission_id
    ) REFERENCES demand.demand_submissions (organization_id, demand_id, id),
    CONSTRAINT ck_demand_review_hash CHECK (octet_length(content_sha256) = 32),
    CONSTRAINT ck_demand_review_shape CHECK (
        (decision = 'NEEDS_CHANGES'
            AND cardinality(reason_codes) BETWEEN 1 AND 20
            AND cardinality(required_field_codes) BETWEEN 1 AND 50
            AND budget_health_code IS NULL AND risk_code IS NULL
            AND evidence_summary_sha256 IS NULL)
        OR
        (decision = 'VERIFIED'
            AND cardinality(reason_codes) = 0
            AND cardinality(required_field_codes) = 0
            AND budget_health_code IN ('HEALTHY', 'APPROVED_EXCEPTION')
            AND risk_code IN ('STANDARD', 'ELEVATED_APPROVED')
            AND octet_length(evidence_summary_sha256) = 32
            AND octet_length(rule_requirement_sha256) = 32)
    )
);

CREATE TABLE demand.demand_funding_markers (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    funding_id uuid NOT NULL,
    status varchar(16) NOT NULL,
    source_event_id uuid NOT NULL UNIQUE,
    source_aggregate_version bigint NOT NULL,
    amount_currency_sha256 bytea NOT NULL,
    verification_reference_sha256 bytea NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT uq_demand_funding_org_id UNIQUE (organization_id, demand_id, id),
    CONSTRAINT fk_demand_funding_version FOREIGN KEY (
        organization_id, demand_id, demand_version_id
    ) REFERENCES demand.demand_versions (organization_id, demand_id, id),
    CONSTRAINT ck_demand_funding_shape CHECK (
        status = 'SECURED'
        AND source_aggregate_version >= 1
        AND octet_length(amount_currency_sha256) = 32
        AND octet_length(verification_reference_sha256) = 32
    )
);

CREATE TABLE demand.matching_requests (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    status varchar(16) NOT NULL,
    demand_version_id uuid NOT NULL,
    verified_review_id uuid NOT NULL,
    funding_marker_id uuid NOT NULL,
    funding_id uuid NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    budget_rule_bundle_id uuid NOT NULL,
    risk_rule_bundle_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    reason_code_bundle_id uuid NOT NULL,
    composite_rule_requirement_id uuid NOT NULL,
    matching_selector_digest bytea NOT NULL,
    rule_requirement_sha256 bytea NOT NULL,
    budget_override_code varchar(32) NULL,
    authorized_workload_principal_id uuid NOT NULL,
    authorization_digest bytea NOT NULL,
    requested_at timestamptz NOT NULL,
    closed_at timestamptz NULL,
    CONSTRAINT uq_demand_matching_org_id UNIQUE (organization_id, demand_id, id),
    CONSTRAINT fk_demand_matching_version FOREIGN KEY (
        organization_id, demand_id, demand_version_id
    ) REFERENCES demand.demand_versions (organization_id, demand_id, id),
    CONSTRAINT fk_demand_matching_review FOREIGN KEY (
        organization_id, demand_id, verified_review_id
    ) REFERENCES demand.demand_reviews (organization_id, demand_id, id),
    CONSTRAINT fk_demand_matching_funding FOREIGN KEY (
        organization_id, demand_id, funding_marker_id
    ) REFERENCES demand.demand_funding_markers (organization_id, demand_id, id),
    CONSTRAINT ck_demand_matching_shape CHECK (
        aggregate_version >= 1
        AND status IN ('OPEN', 'CLOSED')
        AND ((status = 'OPEN' AND closed_at IS NULL)
            OR (status = 'CLOSED' AND closed_at IS NOT NULL))
        AND octet_length(matching_selector_digest) = 32
        AND octet_length(rule_requirement_sha256) = 32
        AND octet_length(authorization_digest) = 32
        AND (budget_override_code IS NULL
            OR budget_override_code = 'APPROVED_EXCEPTION')
    )
);

CREATE UNIQUE INDEX uq_demand_open_matching_request
ON demand.matching_requests (organization_id, demand_id)
WHERE status = 'OPEN';

CREATE TABLE demand.source_inbox (
    source_event_id uuid PRIMARY KEY,
    source_kind varchar(32) NOT NULL,
    event_type varchar(64) NOT NULL,
    schema_version integer NOT NULL,
    source_aggregate_id uuid NOT NULL,
    source_aggregate_version bigint NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    envelope_sha256 bytea NOT NULL,
    status varchar(16) NOT NULL,
    result_aggregate_version bigint NULL,
    result_event_types text[] NULL,
    completed_at timestamptz NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT ck_demand_source_inbox_shape CHECK (
        schema_version = 1
        AND source_aggregate_version >= 1
        AND octet_length(envelope_sha256) = 32
        AND status IN ('IN_PROGRESS', 'COMPLETED')
        AND ((status = 'IN_PROGRESS' AND result_aggregate_version IS NULL
            AND result_event_types IS NULL AND completed_at IS NULL)
        OR (status = 'COMPLETED' AND result_aggregate_version >= 1
            AND cardinality(result_event_types) >= 1 AND completed_at IS NOT NULL))
    )
);

CREATE TABLE demand.receipt_key_policy (
    singleton_key boolean PRIMARY KEY,
    active_idempotency_key_id varchar(128) NOT NULL,
    active_payload_key_id varchar(128) NOT NULL,
    active_canonicalization_version varchar(64) NOT NULL,
    retained_idempotency_key_ids text[] NOT NULL,
    retained_payload_key_ids text[] NOT NULL,
    retained_canonicalization_versions text[] NOT NULL,
    finance_workload_principal_id uuid NOT NULL,
    finance_authority_marker_sha256 bytea NOT NULL,
    system_workload_principal_id uuid NOT NULL,
    system_authority_marker_sha256 bytea NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    budget_rule_bundle_id uuid NOT NULL,
    risk_rule_bundle_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    reason_code_bundle_id uuid NOT NULL,
    composite_rule_requirement_id uuid NOT NULL,
    rule_requirement_sha256 bytea NOT NULL,
    matching_selector_digest bytea NOT NULL,
    rule_effective_at timestamptz NOT NULL,
    rule_effective_until timestamptz NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_demand_receipt_policy_singleton CHECK (singleton_key),
    CONSTRAINT ck_demand_receipt_policy_keys CHECK (
        active_idempotency_key_id <> active_payload_key_id
        AND active_idempotency_key_id = ANY(retained_idempotency_key_ids)
        AND active_payload_key_id = ANY(retained_payload_key_ids)
        AND active_canonicalization_version = ANY(retained_canonicalization_versions)
        AND octet_length(finance_authority_marker_sha256) = 32
        AND octet_length(system_authority_marker_sha256) = 32
        AND octet_length(rule_requirement_sha256) = 32
        AND octet_length(matching_selector_digest) = 32
        AND (rule_effective_until IS NULL
            OR rule_effective_until > rule_effective_at)
    )
);

CREATE TABLE demand.command_receipts (
    receipt_id uuid PRIMARY KEY,
    principal_kind varchar(16) NOT NULL,
    principal_id uuid NOT NULL,
    organization_id uuid NOT NULL,
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
    safe_response_body jsonb NULL,
    target_id uuid NULL,
    target_version bigint NULL,
    result_status varchar(32) NULL,
    event_types text[] NULL,
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_demand_receipt_identity UNIQUE (
        principal_kind, principal_id, organization_id,
        command_name, command_version,
        idempotency_key_digest_key_id, idempotency_key_digest
    ),
    CONSTRAINT ck_demand_receipt_hashes CHECK (
        octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
        AND idempotency_key_digest_key_id <> payload_hash_key_id
    ),
    CONSTRAINT ck_demand_receipt_transport CHECK (
        principal_kind = 'USER' AND command_version = 1
        AND http_method = 'POST' AND left(canonical_path, 4) = '/v1/'
        AND canonicalization_version = 'demand-command-json-v1'
    ),
    CONSTRAINT ck_demand_receipt_shape CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
        AND ((status = 'IN_PROGRESS'
            AND response_http_status IS NULL
            AND response_schema_name IS NULL
            AND response_schema_version IS NULL
            AND response_entity_tag IS NULL
            AND safe_response_body IS NULL
            AND target_id IS NULL AND target_version IS NULL
            AND result_status IS NULL AND event_types IS NULL
            AND completed_at IS NULL)
        OR (status = 'COMPLETED'
            AND response_http_status BETWEEN 200 AND 299
            AND response_schema_name IS NOT NULL
            AND response_schema_version = 1
            AND response_entity_tag IS NOT NULL
            AND jsonb_typeof(safe_response_body) = 'object'
            AND target_id IS NOT NULL AND target_version >= 1
            AND result_status IS NOT NULL
            AND cardinality(event_types) >= 1
            AND completed_at IS NOT NULL))
    )
);

INSERT INTO demand.receipt_key_policy (
    singleton_key,
    active_idempotency_key_id,
    active_payload_key_id,
    active_canonicalization_version,
    retained_idempotency_key_ids,
    retained_payload_key_ids,
    retained_canonicalization_versions,
    finance_workload_principal_id,
    finance_authority_marker_sha256,
    system_workload_principal_id,
    system_authority_marker_sha256,
    taxonomy_bundle_id,
    budget_rule_bundle_id,
    risk_rule_bundle_id,
    matching_rule_bundle_id,
    reason_code_bundle_id,
    composite_rule_requirement_id,
    rule_requirement_sha256,
    matching_selector_digest,
    rule_effective_at,
    rule_effective_until,
    updated_at
) VALUES (
    true,
    'demand-idempotency-2026-01',
    'demand-payload-2026-01',
    'demand-command-json-v1',
    ARRAY[
        'demand-idempotency-2026-01',
        'demand-idempotency-retained-2025-12'
    ]::text[],
    ARRAY[
        'demand-payload-2026-01',
        'demand-payload-retained-2025-12'
    ]::text[],
    ARRAY['demand-command-json-v1']::text[],
    '48000000-0000-4000-8000-000000000001'::uuid,
    decode('d48c8643a2b65b291f98db043ceb9804a825901027e8a13be1cf88a83ea3f789', 'hex'),
    '48000000-0000-4000-8000-000000000001'::uuid,
    decode('d48c8643a2b65b291f98db043ceb9804a825901027e8a13be1cf88a83ea3f789', 'hex'),
    '50000000-0000-4000-8000-000000000001'::uuid,
    '51000000-0000-4000-8000-000000000001'::uuid,
    '52000000-0000-4000-8000-000000000001'::uuid,
    '53000000-0000-4000-8000-000000000001'::uuid,
    '54000000-0000-4000-8000-000000000001'::uuid,
    '55000000-0000-4000-8000-000000000001'::uuid,
    decode('98ba1470ec6171ad33a9a8123cd855278241ac607f87ef4226b1f4f4a3bb88e3', 'hex'),
    decode('3bd2f51daac99e67e0da34eb15134ab3cc3a786c994899c5246fe33689179ead', 'hex'),
    '2020-01-01T00:00:00Z'::timestamptz,
    '2100-01-01T00:00:00Z'::timestamptz,
    transaction_timestamp()
);

CREATE FUNCTION demand.reject_immutable_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'trg_demand_immutable_fact',
        MESSAGE = 'Demand immutable facts are append only';
END
$function$;

CREATE TRIGGER trg_demand_version_immutable
BEFORE UPDATE OR DELETE ON demand.demand_versions
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE TRIGGER trg_demand_submission_immutable
BEFORE UPDATE OR DELETE ON demand.demand_submissions
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE TRIGGER trg_demand_review_immutable
BEFORE UPDATE OR DELETE ON demand.demand_reviews
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE TRIGGER trg_demand_funding_immutable
BEFORE UPDATE OR DELETE ON demand.demand_funding_markers
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE FUNCTION demand.capture_match_inputs_v1(
    candidate_match_run_id uuid,
    candidate_workload_principal_id uuid,
    candidate_matching_request_ids uuid[],
    candidate_authorization_digest bytea
)
RETURNS TABLE (
    matching_request_id uuid,
    matching_request_version bigint,
    matching_request_status varchar,
    organization_id uuid,
    demand_id uuid,
    demand_status varchar,
    demand_version_id uuid,
    demand_version_no integer,
    verification_decision varchar,
    content_sha256 bytea,
    canonical_version_bytes bytea,
    taxonomy_bundle_id uuid,
    funding_id uuid,
    funding_status varchar,
    composite_rule_requirement_id uuid,
    budget_rule_bundle_id uuid,
    risk_rule_bundle_id uuid,
    matching_rule_bundle_id uuid,
    reason_code_bundle_id uuid,
    matching_selector_digest bytea,
    rule_requirement_sha256 bytea,
    budget_override_code varchar,
    captured_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    IF session_user <> 'demand_matching'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            <> 'DEMAND_MATCH_CAPTURE'
       OR candidate_match_run_id IS NULL
       OR candidate_workload_principal_id IS NULL
       OR candidate_matching_request_ids IS NULL
       OR cardinality(candidate_matching_request_ids) NOT BETWEEN 1 AND 500
       OR cardinality(candidate_matching_request_ids)
            <> cardinality(ARRAY(SELECT DISTINCT value FROM unnest(candidate_matching_request_ids) value))
       OR octet_length(candidate_authorization_digest) <> 32 THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        matching.id,
        matching.aggregate_version,
        matching.status,
        root.organization_id,
        root.id,
        root.status,
        version.id,
        version.version_no,
        review.decision,
        version.content_sha256,
        version.canonical_version_bytes,
        version.taxonomy_bundle_id,
        funding.funding_id,
        funding.status,
        matching.composite_rule_requirement_id,
        matching.budget_rule_bundle_id,
        matching.risk_rule_bundle_id,
        matching.matching_rule_bundle_id,
        matching.reason_code_bundle_id,
        matching.matching_selector_digest,
        matching.rule_requirement_sha256,
        matching.budget_override_code,
        transaction_timestamp()
    FROM unnest(candidate_matching_request_ids) WITH ORDINALITY requested(id, ordinal)
    JOIN demand.matching_requests matching ON matching.id = requested.id
    JOIN demand.demands root
      ON root.organization_id = matching.organization_id
     AND root.id = matching.demand_id
     AND root.current_matching_request_id = matching.id
     AND root.current_version_id = matching.demand_version_id
     AND root.verified_version_id = matching.demand_version_id
     AND root.current_funding_marker_id = matching.funding_marker_id
    JOIN demand.demand_versions version
      ON version.organization_id = matching.organization_id
     AND version.demand_id = matching.demand_id
     AND version.id = matching.demand_version_id
    JOIN demand.demand_reviews review
      ON review.organization_id = matching.organization_id
     AND review.demand_id = matching.demand_id
     AND review.id = matching.verified_review_id
     AND review.demand_version_id = matching.demand_version_id
     AND review.content_sha256 = version.content_sha256
    JOIN demand.demand_funding_markers funding
      ON funding.organization_id = matching.organization_id
     AND funding.demand_id = matching.demand_id
     AND funding.id = matching.funding_marker_id
     AND funding.demand_version_id = matching.demand_version_id
     AND funding.funding_id = matching.funding_id
    WHERE matching.status = 'OPEN'
      AND root.status = 'MATCHING'
      AND review.decision = 'VERIFIED'
      AND funding.status = 'SECURED'
      AND matching.authorized_workload_principal_id
            = candidate_workload_principal_id
      AND matching.authorization_digest = candidate_authorization_digest
    ORDER BY requested.ordinal;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA demand FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA demand FROM PUBLIC;
REVOKE ALL ON SCHEMA demand, demand_meta FROM PUBLIC;

GRANT USAGE ON SCHEMA demand TO
    demand_self, demand_review, demand_finance, demand_matching, demand_system;
GRANT SELECT ON demand.schema_compatibility TO
    demand_self, demand_review, demand_finance, demand_matching, demand_system;
GRANT SELECT, INSERT, UPDATE ON demand.demands TO
    demand_self, demand_review, demand_finance, demand_system;
GRANT SELECT, INSERT ON demand.demand_versions TO demand_self;
GRANT SELECT ON demand.demand_versions TO
    demand_review, demand_finance, demand_system;
GRANT SELECT, INSERT ON demand.demand_submissions TO demand_self;
GRANT SELECT ON demand.demand_submissions TO demand_review;
GRANT SELECT, UPDATE ON demand.demand_review_assignments TO demand_review;
GRANT SELECT, INSERT ON demand.demand_reviews TO demand_review;
GRANT SELECT, INSERT ON demand.demand_funding_markers TO demand_finance;
GRANT SELECT ON demand.demand_funding_markers TO demand_review;
GRANT SELECT, INSERT ON demand.matching_requests TO demand_review;
GRANT SELECT, INSERT, UPDATE ON demand.source_inbox TO
    demand_finance, demand_system;
GRANT SELECT, INSERT, UPDATE ON demand.command_receipts TO
    demand_self, demand_review;
GRANT SELECT ON demand.receipt_key_policy TO
    demand_self, demand_review, demand_finance, demand_system;
GRANT EXECUTE ON FUNCTION demand.capture_match_inputs_v1(
    uuid, uuid, uuid[], bytea
) TO demand_matching;

ALTER TABLE demand.demands ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demands FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_submissions FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_review_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_review_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_reviews FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_funding_markers ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_funding_markers FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.source_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.source_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.command_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.receipt_key_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.receipt_key_policy FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_demand_root_self ON demand.demands
FOR ALL TO demand_self
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_root_review ON demand.demands
FOR ALL TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_root_finance ON demand.demands
FOR ALL TO demand_finance
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
);

CREATE POLICY rls_demand_root_system ON demand.demands
FOR ALL TO demand_system
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
);

CREATE POLICY rls_demand_version_self ON demand.demand_versions
FOR ALL TO demand_self
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_version_review ON demand.demand_versions
FOR SELECT TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_version_finance ON demand.demand_versions
FOR SELECT TO demand_finance
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
);

CREATE POLICY rls_demand_version_system ON demand.demand_versions
FOR SELECT TO demand_system
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
);

CREATE POLICY rls_demand_submission_self ON demand.demand_submissions
FOR ALL TO demand_self
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_submission_review ON demand.demand_submissions
FOR SELECT TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_assignment_review ON demand.demand_review_assignments
FOR ALL TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND reviewer_user_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND reviewer_user_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_review_review ON demand.demand_reviews
FOR ALL TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND reviewer_user_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND reviewer_user_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_review_matching_definer ON demand.demand_reviews
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_MATCH_CAPTURE'
);

CREATE POLICY rls_demand_funding_finance ON demand.demand_funding_markers
FOR ALL TO demand_finance
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
);

CREATE POLICY rls_demand_funding_review ON demand.demand_funding_markers
FOR SELECT TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_matching_review ON demand.matching_requests
FOR ALL TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_root_matching_definer ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_MATCH_CAPTURE'
);

CREATE POLICY rls_demand_version_matching_definer ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_MATCH_CAPTURE'
);

CREATE POLICY rls_demand_funding_matching_definer ON demand.demand_funding_markers
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_MATCH_CAPTURE'
);

CREATE POLICY rls_demand_matching_matching_definer ON demand.matching_requests
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_MATCH_CAPTURE'
);

CREATE POLICY rls_demand_source_finance ON demand.source_inbox
FOR ALL TO demand_finance
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_FINANCE'
);

CREATE POLICY rls_demand_source_system ON demand.source_inbox
FOR ALL TO demand_system
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND demand_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
);

CREATE POLICY rls_demand_receipt_self ON demand.command_receipts
FOR ALL TO demand_self
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_receipt_review ON demand.command_receipts
FOR ALL TO demand_review
USING (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
)
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
);

CREATE POLICY rls_demand_key_policy_writer ON demand.receipt_key_policy
FOR SELECT TO demand_self, demand_review, demand_finance, demand_system
USING (singleton_key);

SET LOCAL ROLE schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO
    demand_self, demand_review, demand_finance, demand_system;
GRANT INSERT ON audit.audit_events TO
    demand_self, demand_review, demand_finance, demand_system;
GRANT INSERT ON infra.outbox_events TO
    demand_self, demand_review, demand_finance, demand_system;

CREATE POLICY rls_demand_audit_insert
ON audit.audit_events
FOR INSERT TO demand_self, demand_review, demand_finance, demand_system
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND target_kind = 'Demand'
    AND target_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        IN ('DEMAND_OWNER', 'DEMAND_REVIEW', 'DEMAND_FINANCE', 'DEMAND_SYSTEM')
);

CREATE POLICY rls_demand_outbox_insert
ON infra.outbox_events
FOR INSERT TO demand_self, demand_review, demand_finance, demand_system
WITH CHECK (
    organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND aggregate_type = 'Demand'
    AND aggregate_id = NULLIF(current_setting('app.demand_id', true), '')::uuid
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        IN ('DEMAND_OWNER', 'DEMAND_REVIEW', 'DEMAND_FINANCE', 'DEMAND_SYSTEM')
);

SET LOCAL ROLE demand_schema_owner;
