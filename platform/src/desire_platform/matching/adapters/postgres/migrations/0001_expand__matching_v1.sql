-- Independent Matching PostgreSQL 18 schema, exact relationships, and FORCE RLS.

CREATE SCHEMA matching AUTHORIZATION matching_schema_owner;
CREATE SCHEMA matching_meta AUTHORIZATION matching_schema_owner;
REVOKE ALL ON SCHEMA matching, matching_meta FROM PUBLIC;

CREATE TABLE matching_meta.schema_migrations (
    component varchar(32) NOT NULL,
    version integer NOT NULL,
    phase varchar(16) NOT NULL,
    name varchar(128) NOT NULL,
    checksum_sha256 bytea NOT NULL,
    manifest_sha256 bytea NOT NULL,
    runner_version varchar(96) NOT NULL,
    applied_at timestamptz NOT NULL,
    CONSTRAINT pk_matching_schema_migrations PRIMARY KEY (component, version),
    CONSTRAINT ck_matching_migration_component CHECK (component = 'matching'),
    CONSTRAINT ck_matching_migration_phase CHECK (
        phase IN ('expand', 'migrate', 'contract')
    ),
    CONSTRAINT ck_matching_migration_hashes CHECK (
        octet_length(checksum_sha256) = 32
        AND octet_length(manifest_sha256) = 32
    )
);

CREATE TABLE matching_meta.schema_contracts (
    singleton_key boolean PRIMARY KEY,
    schema_head_version integer NOT NULL,
    min_app_compatible_version integer NOT NULL,
    max_app_compatible_version integer NOT NULL,
    required_iam_schema_version integer NOT NULL,
    api_contract_sha256 bytea NOT NULL,
    event_contract_sha256 bytea NOT NULL,
    rule_contract_sha256 bytea NOT NULL,
    input_manifest_contract_sha256 bytea NOT NULL,
    run_input_contract_sha256 bytea NOT NULL,
    candidate_contract_sha256 bytea NOT NULL,
    disclosure_contract_sha256 bytea NOT NULL,
    migration_manifest_sha256 bytea NOT NULL,
    generated_at timestamptz NOT NULL,
    CONSTRAINT ck_matching_contract_singleton CHECK (singleton_key),
    CONSTRAINT ck_matching_contract_versions CHECK (
        schema_head_version >= 1
        AND min_app_compatible_version >= 1
        AND max_app_compatible_version >= min_app_compatible_version
        AND required_iam_schema_version >= 43
    ),
    CONSTRAINT ck_matching_contract_hashes CHECK (
        octet_length(api_contract_sha256) = 32
        AND octet_length(event_contract_sha256) = 32
        AND octet_length(rule_contract_sha256) = 32
        AND octet_length(input_manifest_contract_sha256) = 32
        AND octet_length(run_input_contract_sha256) = 32
        AND octet_length(candidate_contract_sha256) = 32
        AND octet_length(disclosure_contract_sha256) = 32
        AND octet_length(migration_manifest_sha256) = 32
    )
);

CREATE VIEW matching.schema_compatibility AS
SELECT
    'matching'::text AS component,
    COALESCE((
        SELECT max(version)
        FROM matching_meta.schema_migrations
        WHERE component = 'matching'
    ), 0)::integer AS current_schema_version,
    schema_head_version,
    min_app_compatible_version,
    max_app_compatible_version,
    required_iam_schema_version,
    migration_manifest_sha256
FROM matching_meta.schema_contracts
WHERE singleton_key;

CREATE TABLE matching.rule_bundles (
    id uuid PRIMARY KEY,
    semantic_version varchar(64) NOT NULL,
    status varchar(16) NOT NULL,
    selector_digest bytea NOT NULL,
    jurisdiction_code varchar(32) NOT NULL,
    locale varchar(32) NOT NULL,
    demand_type_code varchar(64) NOT NULL,
    taxonomy_family_code varchar(64) NOT NULL,
    engine_identifier varchar(64) NOT NULL,
    engine_major integer NOT NULL,
    engine_artifact_sha256 bytea NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    budget_rule_version varchar(64) NOT NULL,
    matching_rule_version varchar(64) NOT NULL,
    reason_code_version varchar(64) NOT NULL,
    explanation_template_version varchar(64) NOT NULL,
    canonical_manifest_sha256 bytea NOT NULL,
    signature_key_id varchar(128) NOT NULL,
    review_approval_id uuid NOT NULL,
    review_approval_version bigint NOT NULL,
    effective_at timestamptz NOT NULL,
    effective_until timestamptz NULL,
    published_by_workload_id uuid NOT NULL,
    published_authority_marker_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_rule_semantic UNIQUE (semantic_version),
    CONSTRAINT uq_matching_rule_selector_id UNIQUE (selector_digest, id),
    CONSTRAINT ck_matching_rule_status CHECK (
        status IN ('DRAFT', 'ACTIVE', 'SUPERSEDED', 'RETIRED')
    ),
    CONSTRAINT ck_matching_rule_contract CHECK (
        engine_identifier = 'deterministic-matcher-v1'
        AND engine_major = 1
        AND review_approval_version >= 1
        AND octet_length(selector_digest) = 32
        AND octet_length(engine_artifact_sha256) = 32
        AND octet_length(canonical_manifest_sha256) = 32
        AND octet_length(published_authority_marker_sha256) = 32
        AND (effective_until IS NULL OR effective_until > effective_at)
        AND updated_at >= created_at
    )
);

CREATE UNIQUE INDEX uq_matching_active_rule_selector
ON matching.rule_bundles (selector_digest)
WHERE status = 'ACTIVE';

CREATE TABLE matching.rule_selectors (
    selector_digest bytea PRIMARY KEY,
    current_bundle_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_selector_current FOREIGN KEY (
        selector_digest, current_bundle_id
    ) REFERENCES matching.rule_bundles (selector_digest, id)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_matching_selector_shape CHECK (
        octet_length(selector_digest) = 32 AND aggregate_version >= 1
    )
);

CREATE TABLE matching.matching_attempts (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    demand_content_sha256 bytea NOT NULL,
    demand_aggregate_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    composite_rule_requirement_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    selector_digest bytea NOT NULL,
    source_event_id uuid NOT NULL UNIQUE,
    attempt_no integer NOT NULL,
    status varchar(32) NOT NULL,
    aggregate_version bigint NOT NULL,
    current_match_run_id uuid NOT NULL,
    selection_id uuid NULL,
    input_baseline_sha256 bytea NOT NULL,
    system_workload_id uuid NOT NULL,
    system_authority_marker_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    terminal_at timestamptz NULL,
    CONSTRAINT uq_matching_attempt_org_id UNIQUE (organization_id, id),
    CONSTRAINT uq_matching_attempt_demand_no UNIQUE (
        organization_id, demand_id, attempt_no
    ),
    CONSTRAINT fk_matching_attempt_rule FOREIGN KEY (
        selector_digest, matching_rule_bundle_id
    ) REFERENCES matching.rule_bundles (selector_digest, id),
    CONSTRAINT ck_matching_attempt_status CHECK (
        status IN (
            'OPEN', 'SELECTED', 'CLOSED_NO_SELECTION',
            'INVALIDATED', 'CANCELLED'
        )
    ),
    CONSTRAINT ck_matching_attempt_shape CHECK (
        attempt_no >= 1
        AND aggregate_version >= 1
        AND demand_aggregate_version >= 1
        AND matching_request_version >= 1
        AND octet_length(demand_content_sha256) = 32
        AND octet_length(selector_digest) = 32
        AND octet_length(input_baseline_sha256) = 32
        AND octet_length(system_authority_marker_sha256) = 32
        AND ((status = 'OPEN' AND terminal_at IS NULL)
            OR (status <> 'OPEN' AND terminal_at IS NOT NULL))
        AND updated_at >= created_at
    )
);

CREATE UNIQUE INDEX uq_matching_open_attempt_per_demand
ON matching.matching_attempts (organization_id, demand_id)
WHERE status = 'OPEN';

CREATE TABLE matching.match_runs (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    run_no integer NOT NULL,
    status varchar(16) NOT NULL,
    aggregate_version bigint NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    input_manifest_sha256 bytea NULL,
    input_set_sha256 bytea NULL,
    ordered_result_sha256 bytea NULL,
    candidate_count integer NULL,
    eligible_count integer NULL,
    excluded_count integer NULL,
    worker_id uuid NULL,
    lease_token_digest_key_id varchar(128) NULL,
    lease_token_digest bytea NULL,
    fencing_generation bigint NOT NULL,
    lease_until timestamptz NULL,
    supersedes_run_id uuid NULL,
    superseded_by_run_id uuid NULL,
    failure_code varchar(64) NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_run_attempt_no UNIQUE (attempt_id, run_no),
    CONSTRAINT uq_matching_run_attempt_id UNIQUE (attempt_id, id),
    CONSTRAINT uq_matching_run_org_attempt_id UNIQUE (
        organization_id, attempt_id, id
    ),
    CONSTRAINT fk_matching_run_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_run_rule FOREIGN KEY (matching_rule_bundle_id)
        REFERENCES matching.rule_bundles (id),
    CONSTRAINT fk_matching_run_supersedes FOREIGN KEY (
        attempt_id, supersedes_run_id
    ) REFERENCES matching.match_runs (attempt_id, id)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_matching_run_superseded_by FOREIGN KEY (
        attempt_id, superseded_by_run_id
    ) REFERENCES matching.match_runs (attempt_id, id)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_matching_run_status CHECK (
        status IN (
            'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED',
            'SUPERSEDED', 'CANCELLED'
        )
    ),
    CONSTRAINT ck_matching_run_shape CHECK (
        run_no >= 1 AND aggregate_version >= 1 AND fencing_generation >= 0
        AND updated_at >= created_at
        AND (supersedes_run_id IS NULL OR supersedes_run_id <> id)
        AND (superseded_by_run_id IS NULL OR superseded_by_run_id <> id)
        AND (
            (status = 'QUEUED'
                AND worker_id IS NULL AND lease_token_digest IS NULL
                AND lease_until IS NULL AND input_set_sha256 IS NULL
                AND ordered_result_sha256 IS NULL AND failure_code IS NULL)
            OR (status = 'RUNNING'
                AND worker_id IS NOT NULL
                AND lease_token_digest_key_id IS NOT NULL
                AND octet_length(lease_token_digest) = 32
                AND lease_until IS NOT NULL
                AND input_manifest_sha256 IS NOT NULL
                AND input_set_sha256 IS NOT NULL
                AND ordered_result_sha256 IS NULL AND failure_code IS NULL)
            OR (status IN ('COMPLETED', 'SUPERSEDED')
                AND octet_length(input_manifest_sha256) = 32
                AND octet_length(input_set_sha256) = 32
                AND octet_length(ordered_result_sha256) = 32
                AND candidate_count >= 0 AND eligible_count >= 0
                AND excluded_count >= 0
                AND candidate_count = eligible_count + excluded_count
                AND failure_code IS NULL)
            OR (status = 'FAILED'
                AND input_set_sha256 IS NOT NULL AND failure_code IS NOT NULL)
            OR status = 'CANCELLED'
        )
    )
);

ALTER TABLE matching.matching_attempts
ADD CONSTRAINT fk_matching_attempt_current_run FOREIGN KEY (
    id, current_match_run_id
) REFERENCES matching.match_runs (attempt_id, id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE matching.match_run_inputs (
    match_run_id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    manifest_schema_version integer NOT NULL,
    manifest_canonicalization_version varchar(64) NOT NULL,
    canonical_manifest_bytes bytea NOT NULL,
    manifest jsonb NOT NULL,
    manifest_sha256 bytea NOT NULL,
    run_input_schema_version integer NOT NULL,
    run_input_canonicalization_version varchar(64) NOT NULL,
    canonical_run_input_bytes bytea NOT NULL,
    run_input jsonb NOT NULL,
    input_set_sha256 bytea NOT NULL,
    candidate_allowlist_sha256 bytea NOT NULL,
    candidate_count integer NOT NULL,
    captured_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_input_attempt_run UNIQUE (attempt_id, match_run_id),
    CONSTRAINT fk_matching_input_run FOREIGN KEY (
        organization_id, attempt_id, match_run_id
    ) REFERENCES matching.match_runs (organization_id, attempt_id, id),
    CONSTRAINT ck_matching_input_contract CHECK (
        manifest_schema_version = 1
        AND manifest_canonicalization_version = 'match-input-manifest-v1'
        AND run_input_schema_version = 1
        AND run_input_canonicalization_version = 'match-run-input-v1'
        AND octet_length(canonical_manifest_bytes) BETWEEN 1 AND 1048576
        AND octet_length(canonical_run_input_bytes) BETWEEN 1 AND 8388608
        AND jsonb_typeof(manifest) = 'object'
        AND jsonb_typeof(run_input) = 'object'
        AND octet_length(manifest_sha256) = 32
        AND octet_length(input_set_sha256) = 32
        AND octet_length(candidate_allowlist_sha256) = 32
        AND candidate_count >= 0
    )
);

CREATE TABLE matching.match_candidates (
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    creator_user_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_version_id uuid NOT NULL,
    profile_content_sha256 bytea NOT NULL,
    evidence_version_digest bytea NOT NULL,
    eligibility varchar(16) NOT NULL,
    exclusion_reason_codes text[] NOT NULL,
    component_scores jsonb NOT NULL,
    total_score numeric(5,2) NULL,
    rank integer NULL,
    evidence_facts jsonb NOT NULL,
    candidate_result_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_matching_candidate PRIMARY KEY (
        match_run_id, creator_user_id
    ),
    CONSTRAINT uq_matching_candidate_profile UNIQUE (
        match_run_id, profile_id, profile_version_id
    ),
    CONSTRAINT uq_matching_candidate_invitation_target UNIQUE (
        attempt_id, match_run_id, creator_user_id,
        profile_id, profile_version_id, eligibility
    ),
    CONSTRAINT fk_matching_candidate_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT ck_matching_candidate_eligibility CHECK (
        eligibility IN ('ELIGIBLE', 'EXCLUDED')
    ),
    CONSTRAINT ck_matching_candidate_hashes CHECK (
        octet_length(profile_content_sha256) = 32
        AND octet_length(evidence_version_digest) = 32
        AND octet_length(candidate_result_sha256) = 32
        AND jsonb_typeof(component_scores) = 'array'
        AND jsonb_typeof(evidence_facts) = 'array'
    ),
    CONSTRAINT ck_matching_candidate_result_shape CHECK (
        (eligibility = 'ELIGIBLE'
            AND cardinality(exclusion_reason_codes) = 0
            AND jsonb_array_length(component_scores) = 6
            AND total_score BETWEEN 0.00 AND 100.00
            AND rank >= 1)
        OR
        (eligibility = 'EXCLUDED'
            AND cardinality(exclusion_reason_codes) >= 1
            AND jsonb_array_length(component_scores) = 0
            AND total_score IS NULL AND rank IS NULL)
    )
);

CREATE UNIQUE INDEX uq_matching_eligible_rank
ON matching.match_candidates (match_run_id, rank)
WHERE eligibility = 'ELIGIBLE';

CREATE TABLE matching.invitations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    creator_user_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_version_id uuid NOT NULL,
    profile_content_sha256 bytea NOT NULL,
    candidate_eligibility varchar(16) NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    funding_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    disclosure_snapshot_id uuid NOT NULL,
    snapshot_sha256 bytea NOT NULL,
    creator_authority_marker_sha256 bytea NOT NULL,
    status varchar(16) NOT NULL,
    aggregate_version bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    sent_at timestamptz NULL,
    responded_at timestamptz NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_invitation_org_id UNIQUE (organization_id, id),
    CONSTRAINT uq_matching_invitation_attempt_id UNIQUE (attempt_id, id),
    CONSTRAINT uq_matching_invitation_attempt_id_status UNIQUE (
        attempt_id, id, status
    ),
    CONSTRAINT uq_matching_invitation_response_target UNIQUE (
        id, creator_user_id, snapshot_sha256
    ),
    CONSTRAINT fk_matching_invitation_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_invitation_candidate FOREIGN KEY (
        attempt_id, match_run_id, creator_user_id,
        profile_id, profile_version_id, candidate_eligibility
    ) REFERENCES matching.match_candidates (
        attempt_id, match_run_id, creator_user_id,
        profile_id, profile_version_id, eligibility
    ),
    CONSTRAINT ck_matching_invitation_status CHECK (
        status IN (
            'CREATED', 'SENT', 'ACCEPTED', 'DECLINED',
            'WITHDRAWN', 'EXPIRED', 'REVOKED'
        )
    ),
    CONSTRAINT ck_matching_invitation_shape CHECK (
        candidate_eligibility = 'ELIGIBLE'
        AND aggregate_version >= 1
        AND octet_length(profile_content_sha256) = 32
        AND octet_length(snapshot_sha256) = 32
        AND octet_length(creator_authority_marker_sha256) = 32
        AND expires_at > created_at AND updated_at >= created_at
        AND ((status = 'CREATED' AND sent_at IS NULL AND responded_at IS NULL)
            OR (status = 'SENT' AND sent_at IS NOT NULL
                AND responded_at IS NULL)
            OR (status IN ('ACCEPTED', 'DECLINED', 'WITHDRAWN')
                AND sent_at IS NOT NULL AND responded_at IS NOT NULL)
            OR status IN ('EXPIRED', 'REVOKED'))
    )
);

CREATE UNIQUE INDEX uq_matching_open_invitation_per_creator
ON matching.invitations (attempt_id, creator_user_id)
WHERE status IN ('CREATED', 'SENT');

CREATE TABLE matching.invitation_disclosure_snapshots (
    id uuid PRIMARY KEY,
    invitation_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_version_id uuid NOT NULL,
    schema_version integer NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    canonical_snapshot_bytes bytea NOT NULL,
    snapshot jsonb NOT NULL,
    demand_content_sha256 bytea NOT NULL,
    profile_content_sha256 bytea NOT NULL,
    snapshot_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_snapshot_invitation_hash UNIQUE (
        invitation_id, snapshot_sha256
    ),
    CONSTRAINT uq_matching_snapshot_reference UNIQUE (
        id, invitation_id, snapshot_sha256
    ),
    CONSTRAINT fk_matching_snapshot_invitation FOREIGN KEY (
        organization_id, invitation_id
    ) REFERENCES matching.invitations (organization_id, id)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_matching_snapshot_contract CHECK (
        schema_version = 1
        AND canonicalization_version = 'invitation-disclosure-json-v1'
        AND octet_length(canonical_snapshot_bytes) BETWEEN 1 AND 1048576
        AND jsonb_typeof(snapshot) = 'object'
        AND octet_length(demand_content_sha256) = 32
        AND octet_length(profile_content_sha256) = 32
        AND octet_length(snapshot_sha256) = 32
    )
);

ALTER TABLE matching.invitations
ADD CONSTRAINT fk_matching_invitation_snapshot FOREIGN KEY (
    disclosure_snapshot_id, id, snapshot_sha256
) REFERENCES matching.invitation_disclosure_snapshots (
    id, invitation_id, snapshot_sha256
) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE matching.invitation_responses (
    id uuid PRIMARY KEY,
    invitation_id uuid NOT NULL UNIQUE,
    creator_user_id uuid NOT NULL,
    response_kind varchar(16) NOT NULL,
    snapshot_sha256 bytea NOT NULL,
    reason_code varchar(64) NULL,
    restricted_note varchar(1000) NULL,
    responded_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_response_invitation FOREIGN KEY (
        invitation_id, creator_user_id, snapshot_sha256
    ) REFERENCES matching.invitations (
        id, creator_user_id, snapshot_sha256
    ),
    CONSTRAINT ck_matching_response_kind CHECK (
        response_kind IN ('ACCEPTED', 'DECLINED')
    ),
    CONSTRAINT ck_matching_response_shape CHECK (
        octet_length(snapshot_sha256) = 32
        AND ((response_kind = 'ACCEPTED' AND reason_code IS NULL
                AND restricted_note IS NULL)
            OR (response_kind = 'DECLINED' AND reason_code IS NOT NULL))
    )
);

CREATE TABLE matching.invitation_withdrawals (
    id uuid PRIMARY KEY,
    invitation_id uuid NOT NULL UNIQUE,
    creator_user_id uuid NOT NULL,
    snapshot_sha256 bytea NOT NULL,
    reason_code varchar(64) NOT NULL,
    restricted_note varchar(1000) NULL,
    withdrawn_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_withdrawal_invitation FOREIGN KEY (
        invitation_id, creator_user_id, snapshot_sha256
    ) REFERENCES matching.invitations (
        id, creator_user_id, snapshot_sha256
    ),
    CONSTRAINT ck_matching_withdrawal_shape CHECK (
        octet_length(snapshot_sha256) = 32
        AND length(reason_code) BETWEEN 1 AND 64
    )
);

CREATE TABLE matching.selections (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL UNIQUE,
    match_run_id uuid NOT NULL,
    status varchar(32) NOT NULL,
    aggregate_version bigint NOT NULL,
    current_invitation_set_sha256 bytea NOT NULL,
    chosen_invitation_id uuid NULL,
    chosen_invitation_status varchar(16) NULL,
    selection_basis_code varchar(64) NULL,
    reason_code varchar(64) NULL,
    decision_actor_id uuid NULL,
    coordinator_workload_id uuid NOT NULL,
    coordinator_authority_marker_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_selection_org_id UNIQUE (organization_id, id),
    CONSTRAINT uq_matching_selection_attempt_id UNIQUE (attempt_id, id),
    CONSTRAINT fk_matching_selection_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_selection_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT fk_matching_selection_chosen_invitation FOREIGN KEY (
        attempt_id, chosen_invitation_id, chosen_invitation_status
    ) REFERENCES matching.invitations (attempt_id, id, status)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_matching_selection_status CHECK (
        status IN ('OPEN', 'SELECTED', 'CLOSED_NO_SELECTION', 'CANCELLED')
    ),
    CONSTRAINT ck_matching_selection_shape CHECK (
        aggregate_version >= 1
        AND octet_length(current_invitation_set_sha256) = 32
        AND octet_length(coordinator_authority_marker_sha256) = 32
        AND updated_at >= created_at
        AND ((status = 'OPEN'
                AND chosen_invitation_id IS NULL
                AND chosen_invitation_status IS NULL
                AND selection_basis_code IS NULL
                AND reason_code IS NULL AND decision_actor_id IS NULL)
            OR (status = 'SELECTED'
                AND chosen_invitation_id IS NOT NULL
                AND chosen_invitation_status = 'ACCEPTED'
                AND selection_basis_code IS NOT NULL
                AND reason_code IS NULL AND decision_actor_id IS NOT NULL)
            OR (status = 'CLOSED_NO_SELECTION'
                AND chosen_invitation_id IS NULL
                AND chosen_invitation_status IS NULL
                AND selection_basis_code IS NULL
                AND reason_code IS NOT NULL AND decision_actor_id IS NOT NULL)
            OR (status = 'CANCELLED'
                AND chosen_invitation_id IS NULL
                AND chosen_invitation_status IS NULL
                AND selection_basis_code IS NULL
                AND reason_code IS NOT NULL))
    )
);

ALTER TABLE matching.matching_attempts
ADD CONSTRAINT fk_matching_attempt_selection FOREIGN KEY (
    id, selection_id
) REFERENCES matching.selections (attempt_id, id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE matching.candidate_selector_assignments (
    id uuid PRIMARY KEY,
    assignment_version bigint NOT NULL,
    status varchar(16) NOT NULL,
    assignee_user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    selection_id uuid NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    assigned_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_matching_selector_assignment_selection_id UNIQUE (
        selection_id, id
    ),
    CONSTRAINT fk_matching_selector_assignment_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT ck_matching_selector_assignment_status CHECK (
        status IN ('ACTIVE', 'COMPLETED', 'REVOKED', 'EXPIRED')
    ),
    CONSTRAINT ck_matching_selector_assignment_shape CHECK (
        assignment_version >= 1
        AND octet_length(authority_marker_sha256) = 32
        AND expires_at > assigned_at
        AND ((status = 'ACTIVE' AND completed_at IS NULL)
            OR (status <> 'ACTIVE' AND completed_at IS NOT NULL))
    )
);

CREATE UNIQUE INDEX uq_matching_active_candidate_selector
ON matching.candidate_selector_assignments (selection_id)
WHERE status = 'ACTIVE';

CREATE TABLE matching.matching_review_assignments (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    match_run_id uuid NULL,
    reviewer_user_id uuid NOT NULL,
    duty_grant_id uuid NOT NULL,
    duty_grant_version bigint NOT NULL,
    purpose_code varchar(64) NOT NULL,
    conflict_attestation_sha256 bytea NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    status varchar(16) NOT NULL,
    aggregate_version bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_matching_assignment_attempt_id UNIQUE (attempt_id, id),
    CONSTRAINT fk_matching_assignment_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_assignment_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT ck_matching_assignment_status CHECK (
        status IN ('ACTIVE', 'COMPLETED', 'REVOKED', 'EXPIRED')
    ),
    CONSTRAINT ck_matching_assignment_shape CHECK (
        purpose_code IN ('MATCH_RETRY', 'INVITATION_REVIEW', 'ATTEMPT_REVIEW')
        AND duty_grant_version >= 1 AND aggregate_version >= 1
        AND octet_length(conflict_attestation_sha256) = 32
        AND octet_length(authority_marker_sha256) = 32
        AND expires_at > created_at
        AND ((status = 'ACTIVE' AND completed_at IS NULL)
            OR (status <> 'ACTIVE' AND completed_at IS NOT NULL))
    )
);

CREATE UNIQUE INDEX uq_matching_active_review_assignment
ON matching.matching_review_assignments (
    attempt_id, reviewer_user_id, purpose_code
)
WHERE status = 'ACTIVE';

CREATE TABLE matching.match_jobs (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    job_kind varchar(32) NOT NULL,
    status varchar(16) NOT NULL,
    workload_id uuid NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    lease_token_digest_key_id varchar(128) NULL,
    lease_token_digest bytea NULL,
    fencing_generation bigint NOT NULL,
    available_at timestamptz NOT NULL,
    lease_until timestamptz NULL,
    attempt_count integer NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_matching_job_run_kind UNIQUE (match_run_id, job_kind),
    CONSTRAINT fk_matching_job_run FOREIGN KEY (
        organization_id, attempt_id, match_run_id
    ) REFERENCES matching.match_runs (organization_id, attempt_id, id),
    CONSTRAINT ck_matching_job_kind CHECK (
        job_kind IN ('CAPTURE_INPUTS', 'RUN_MATCH', 'EXPIRE_INVITATIONS')
    ),
    CONSTRAINT ck_matching_job_status CHECK (
        status IN ('AVAILABLE', 'LEASED', 'COMPLETED', 'FAILED', 'CANCELLED')
    ),
    CONSTRAINT ck_matching_job_shape CHECK (
        fencing_generation >= 0 AND attempt_count >= 0
        AND octet_length(authority_marker_sha256) = 32
        AND ((status = 'AVAILABLE'
                AND lease_token_digest IS NULL AND lease_until IS NULL
                AND completed_at IS NULL)
            OR (status = 'LEASED'
                AND lease_token_digest_key_id IS NOT NULL
                AND octet_length(lease_token_digest) = 32
                AND lease_until IS NOT NULL AND completed_at IS NULL)
            OR (status IN ('COMPLETED', 'FAILED', 'CANCELLED')
                AND completed_at IS NOT NULL))
    )
);

CREATE UNIQUE INDEX uq_matching_active_job_lease
ON matching.match_jobs (match_run_id)
WHERE status = 'LEASED';

CREATE TABLE matching.source_inbox (
    consumer_name varchar(96) NOT NULL,
    source_event_id uuid NOT NULL,
    event_type varchar(96) NOT NULL,
    schema_version integer NOT NULL,
    source_aggregate_id uuid NOT NULL,
    source_aggregate_version bigint NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    envelope_sha256 bytea NOT NULL,
    workload_id uuid NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    status varchar(16) NOT NULL,
    target_attempt_id uuid NULL,
    target_aggregate_version bigint NULL,
    result_event_types text[] NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT pk_matching_source_inbox PRIMARY KEY (
        consumer_name, source_event_id
    ),
    CONSTRAINT ck_matching_source_inbox_shape CHECK (
        schema_version = 1 AND source_aggregate_version >= 1
        AND octet_length(envelope_sha256) = 32
        AND octet_length(authority_marker_sha256) = 32
        AND status IN ('IN_PROGRESS', 'COMPLETED')
        AND ((status = 'IN_PROGRESS'
                AND target_attempt_id IS NULL
                AND target_aggregate_version IS NULL
                AND result_event_types IS NULL AND completed_at IS NULL)
            OR (status = 'COMPLETED'
                AND target_attempt_id IS NOT NULL
                AND target_aggregate_version >= 1
                AND cardinality(result_event_types) >= 1
                AND completed_at IS NOT NULL))
    )
);

CREATE TABLE matching.command_receipts (
    id uuid PRIMARY KEY,
    principal_kind varchar(16) NOT NULL,
    principal_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    operation varchar(64) NOT NULL,
    command_version integer NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    identity_key_id varchar(128) NOT NULL,
    identity_digest bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_hash bytea NOT NULL,
    principal_authority_marker_sha256 bytea NOT NULL,
    http_method varchar(8) NOT NULL,
    canonical_path varchar(512) NOT NULL,
    target_kind varchar(64) NOT NULL,
    target_id uuid NOT NULL,
    parent_kind varchar(64) NULL,
    parent_id uuid NULL,
    if_match_version bigint NULL,
    status varchar(16) NOT NULL,
    response_http_status integer NULL,
    response_schema_name varchar(96) NULL,
    response_schema_version integer NULL,
    response_entity_tag varchar(128) NULL,
    safe_response_body jsonb NULL,
    target_version bigint NULL,
    result_status varchar(32) NULL,
    event_types text[] NULL,
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_matching_receipt_identity UNIQUE (
        principal_kind, principal_id, organization_id,
        operation, command_version, identity_key_id, identity_digest
    ),
    CONSTRAINT ck_matching_receipt_principal CHECK (
        principal_kind IN ('USER', 'SYSTEM')
    ),
    CONSTRAINT ck_matching_receipt_transport CHECK (
        command_version = 1
        AND canonicalization_version = 'matching-command-json-v1'
        AND http_method = 'POST' AND left(canonical_path, 4) = '/v1/'
        AND (parent_kind IS NULL) = (parent_id IS NULL)
    ),
    CONSTRAINT ck_matching_receipt_hashes CHECK (
        identity_key_id <> payload_hash_key_id
        AND octet_length(identity_digest) = 32
        AND octet_length(payload_hash) = 32
        AND octet_length(principal_authority_marker_sha256) = 32
    ),
    CONSTRAINT ck_matching_receipt_shape CHECK (
        retain_until > created_at
        AND status IN ('IN_PROGRESS', 'COMPLETED')
        AND ((status = 'IN_PROGRESS'
                AND response_http_status IS NULL
                AND response_schema_name IS NULL
                AND response_schema_version IS NULL
                AND response_entity_tag IS NULL
                AND safe_response_body IS NULL
                AND target_version IS NULL AND result_status IS NULL
                AND event_types IS NULL AND completed_at IS NULL)
            OR (status = 'COMPLETED'
                AND response_http_status BETWEEN 200 AND 299
                AND response_schema_name = 'MatchingCommandResult'
                AND response_schema_version = 1
                AND response_entity_tag IS NOT NULL
                AND jsonb_typeof(safe_response_body) = 'object'
                AND target_version >= 1 AND result_status IS NOT NULL
                AND cardinality(event_types) >= 1
                AND completed_at IS NOT NULL
                AND completed_at < retain_until))
    )
);

CREATE FUNCTION matching.reject_immutable_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, matching
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'trg_matching_immutable_fact',
        MESSAGE = 'Matching immutable facts are append only';
END
$function$;

CREATE TRIGGER trg_matching_input_immutable
BEFORE UPDATE OR DELETE ON matching.match_run_inputs
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TRIGGER trg_matching_candidate_immutable
BEFORE UPDATE OR DELETE ON matching.match_candidates
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TRIGGER trg_matching_snapshot_immutable
BEFORE UPDATE OR DELETE ON matching.invitation_disclosure_snapshots
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TRIGGER trg_matching_response_immutable
BEFORE UPDATE OR DELETE ON matching.invitation_responses
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TRIGGER trg_matching_withdrawal_immutable
BEFORE UPDATE OR DELETE ON matching.invitation_withdrawals
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

REVOKE ALL ON ALL TABLES IN SCHEMA matching FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA matching FROM PUBLIC;
REVOKE ALL ON SCHEMA matching, matching_meta FROM PUBLIC;

GRANT USAGE ON SCHEMA matching TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;
GRANT SELECT ON matching.schema_compatibility TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;
GRANT SELECT ON matching.rule_bundles TO
    matching_review, matching_worker, matching_coordinator;
GRANT SELECT ON matching.rule_selectors TO matching_review, matching_worker;
GRANT INSERT, UPDATE ON matching.rule_bundles, matching.rule_selectors TO
    matching_worker;
GRANT SELECT ON matching.matching_attempts, matching.match_runs TO
    matching_selector, matching_review, matching_worker, matching_coordinator;
GRANT INSERT, UPDATE ON matching.matching_attempts, matching.match_runs TO
    matching_worker, matching_coordinator;
GRANT SELECT, INSERT ON matching.match_run_inputs, matching.match_candidates TO
    matching_worker;
GRANT SELECT ON matching.match_candidates TO matching_review;
GRANT SELECT ON matching.invitations TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;
GRANT UPDATE ON matching.invitations TO
    matching_creator, matching_review, matching_worker;
GRANT INSERT ON matching.invitations TO matching_review, matching_worker;
GRANT SELECT ON matching.invitation_disclosure_snapshots TO
    matching_creator, matching_selector, matching_review, matching_coordinator;
GRANT INSERT ON matching.invitation_disclosure_snapshots TO matching_review;
GRANT SELECT, INSERT ON matching.invitation_responses TO matching_creator;
GRANT SELECT, INSERT ON matching.invitation_withdrawals TO matching_creator;
GRANT SELECT ON matching.invitation_responses TO
    matching_review, matching_coordinator;
GRANT SELECT ON matching.invitation_withdrawals TO
    matching_review, matching_coordinator;
GRANT SELECT, UPDATE ON matching.selections TO
    matching_selector, matching_review, matching_coordinator;
GRANT INSERT ON matching.selections TO matching_review, matching_worker;
GRANT SELECT ON matching.candidate_selector_assignments TO matching_selector;
GRANT SELECT, INSERT, UPDATE ON matching.candidate_selector_assignments TO
    matching_worker, matching_coordinator;
GRANT SELECT, INSERT, UPDATE ON matching.matching_review_assignments TO
    matching_review, matching_worker;
GRANT SELECT, INSERT, UPDATE ON matching.match_jobs TO matching_worker;
GRANT SELECT, INSERT, UPDATE ON matching.source_inbox TO matching_worker;
GRANT SELECT, INSERT, UPDATE ON matching.command_receipts TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;

ALTER TABLE matching.rule_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.rule_bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.rule_selectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.rule_selectors FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.matching_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.matching_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.match_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.match_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.match_run_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.match_run_inputs FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.match_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.match_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.invitation_disclosure_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.invitation_disclosure_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.invitation_responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.invitation_responses FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.invitation_withdrawals ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.invitation_withdrawals FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.selections ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.selections FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.candidate_selector_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.candidate_selector_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.matching_review_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.matching_review_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.match_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.match_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.source_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.source_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.command_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_matching_assignment_reviewer
ON matching.matching_review_assignments
FOR ALL TO matching_review
USING (
    status = 'ACTIVE' AND expires_at > transaction_timestamp()
    AND id = NULLIF(current_setting('app.assignment_id', true), '')::uuid
    AND reviewer_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_REVIEW'
)
WITH CHECK (
    id = NULLIF(current_setting('app.assignment_id', true), '')::uuid
    AND reviewer_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_job_worker
ON matching.match_jobs
FOR ALL TO matching_worker
USING (
    id = NULLIF(current_setting('app.job_id', true), '')::uuid
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
    AND (
        (status = 'AVAILABLE' AND available_at <= transaction_timestamp()
            AND NULLIF(current_setting('app.operation', true), '')
                IN ('CLAIM_MATCH_JOB', 'CREATE_MATCHING_ATTEMPT', 'RETRY_MATCH_RUN'))
        OR
        (status IN ('LEASED', 'COMPLETED', 'FAILED')
            AND lease_until > transaction_timestamp()
            AND lease_token_digest_key_id = NULLIF(
                current_setting('app.lease_token_digest_key_id', true), ''
            )
            AND lease_token_digest = pg_catalog.decode(
                NULLIF(current_setting('app.lease_token_digest', true), ''), 'hex'
            ))
        OR (status = 'CANCELLED'
            AND NULLIF(current_setting('app.operation', true), '')
                = 'CANCEL_MATCH_JOB')
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.job_id', true), '')::uuid
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
    AND (
        (status = 'AVAILABLE'
            AND NULLIF(current_setting('app.operation', true), '')
                IN ('CREATE_MATCHING_ATTEMPT', 'RETRY_MATCH_RUN'))
        OR
        (status IN ('LEASED', 'COMPLETED', 'FAILED')
            AND lease_until > transaction_timestamp()
            AND lease_token_digest_key_id = NULLIF(
                current_setting('app.lease_token_digest_key_id', true), ''
            )
            AND lease_token_digest = pg_catalog.decode(
                NULLIF(current_setting('app.lease_token_digest', true), ''), 'hex'
            ))
        OR (status = 'CANCELLED'
            AND NULLIF(current_setting('app.operation', true), '')
                = 'CANCEL_MATCH_JOB')
    )
);

CREATE POLICY rls_matching_candidate_selector_assignment
ON matching.candidate_selector_assignments
FOR SELECT TO matching_selector
USING (
    status = 'ACTIVE' AND expires_at > transaction_timestamp()
    AND id = NULLIF(current_setting('app.selector_assignment_id', true), '')::uuid
    AND assignee_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
);

CREATE POLICY rls_matching_candidate_selector_assignment_system
ON matching.candidate_selector_assignments
FOR ALL TO matching_worker, matching_coordinator
USING (
    selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        IN ('MATCHING_WORKER', 'MATCHING_COORDINATOR')
)
WITH CHECK (
    selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        IN ('MATCHING_WORKER', 'MATCHING_COORDINATOR')
);

CREATE POLICY rls_matching_attempt_reviewer
ON matching.matching_attempts
FOR SELECT TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = matching_attempts.id
));

CREATE POLICY rls_matching_attempt_worker
ON matching.matching_attempts
FOR ALL TO matching_worker
USING (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.attempt_id = matching_attempts.id
))
WITH CHECK (
    id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND system_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND system_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_attempt_selector
ON matching.matching_attempts
FOR SELECT TO matching_selector
USING (
    organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND EXISTS (
        SELECT 1 FROM matching.candidate_selector_assignments AS selector_assignment
        WHERE selector_assignment.selection_id = matching_attempts.selection_id
          AND selector_assignment.demand_id = matching_attempts.demand_id
    )
);

CREATE POLICY rls_matching_attempt_coordinator
ON matching.matching_attempts
FOR ALL TO matching_coordinator
USING (
    id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND system_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND system_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
)
WITH CHECK (
    id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND system_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND system_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
);

CREATE POLICY rls_matching_run_reviewer
ON matching.match_runs
FOR SELECT TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = match_runs.attempt_id
      AND (assignment.match_run_id IS NULL OR assignment.match_run_id = match_runs.id)
));

CREATE POLICY rls_matching_run_worker
ON matching.match_runs
FOR ALL TO matching_worker
USING (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.match_run_id = match_runs.id
))
WITH CHECK (
    id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_run_selector
ON matching.match_runs
FOR SELECT TO matching_selector
USING (EXISTS (
    SELECT 1
    FROM matching.selections AS selection
    JOIN matching.candidate_selector_assignments AS selector_assignment
      ON selector_assignment.selection_id = selection.id
    WHERE selection.attempt_id = match_runs.attempt_id
      AND selection.id = NULLIF(
          current_setting('app.selection_id', true), ''
      )::uuid
));

CREATE POLICY rls_matching_run_coordinator
ON matching.match_runs
FOR SELECT TO matching_coordinator
USING (
    attempt_id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
);

CREATE POLICY rls_matching_input_worker
ON matching.match_run_inputs
FOR ALL TO matching_worker
USING (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.match_run_id = match_run_inputs.match_run_id
))
WITH CHECK (
    match_run_id = NULLIF(
        current_setting('app.match_run_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_candidate_worker
ON matching.match_candidates
FOR ALL TO matching_worker
USING (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.match_run_id = match_candidates.match_run_id
))
WITH CHECK (
    match_run_id = NULLIF(
        current_setting('app.match_run_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_candidate_reviewer
ON matching.match_candidates
FOR SELECT TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = match_candidates.attempt_id
      AND (assignment.match_run_id IS NULL
        OR assignment.match_run_id = match_candidates.match_run_id)
));

CREATE POLICY rls_matching_invitation_creator
ON matching.invitations
FOR SELECT TO matching_creator
USING (
    creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND creator_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
);

CREATE POLICY rls_matching_invitation_creator_update
ON matching.invitations
FOR UPDATE TO matching_creator
USING (
    id = NULLIF(current_setting('app.invitation_id', true), '')::uuid
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND creator_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND status = 'SENT' AND expires_at > transaction_timestamp()
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
)
WITH CHECK (
    id = NULLIF(current_setting('app.invitation_id', true), '')::uuid
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND status IN ('ACCEPTED', 'DECLINED')
);

CREATE POLICY rls_matching_invitation_creator_withdraw
ON matching.invitations
FOR UPDATE TO matching_creator
USING (
    id = NULLIF(current_setting('app.invitation_id', true), '')::uuid
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND creator_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND status = 'ACCEPTED'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
)
WITH CHECK (
    id = NULLIF(current_setting('app.invitation_id', true), '')::uuid
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND status = 'WITHDRAWN'
);

CREATE POLICY rls_matching_invitation_reviewer
ON matching.invitations
FOR ALL TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = invitations.attempt_id
      AND (assignment.match_run_id IS NULL
        OR assignment.match_run_id = invitations.match_run_id)
))
WITH CHECK (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = invitations.attempt_id
      AND (assignment.match_run_id IS NULL
        OR assignment.match_run_id = invitations.match_run_id)
));

CREATE POLICY rls_matching_invitation_worker
ON matching.invitations
FOR ALL TO matching_worker
USING (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.attempt_id = invitations.attempt_id
))
WITH CHECK (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.attempt_id = invitations.attempt_id
));

CREATE POLICY rls_matching_invitation_selector
ON matching.invitations
FOR SELECT TO matching_selector
USING (EXISTS (
    SELECT 1
    FROM matching.selections AS selection
    JOIN matching.candidate_selector_assignments AS selector_assignment
      ON selector_assignment.selection_id = selection.id
    WHERE selection.attempt_id = invitations.attempt_id
      AND selection.id = NULLIF(
          current_setting('app.selection_id', true), ''
      )::uuid
));

CREATE POLICY rls_matching_invitation_coordinator
ON matching.invitations
FOR SELECT TO matching_coordinator
USING (
    attempt_id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
);

CREATE POLICY rls_matching_snapshot_creator
ON matching.invitation_disclosure_snapshots
FOR SELECT TO matching_creator
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_disclosure_snapshots.invitation_id
));

CREATE POLICY rls_matching_snapshot_reviewer
ON matching.invitation_disclosure_snapshots
FOR ALL TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_disclosure_snapshots.invitation_id
))
WITH CHECK (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_disclosure_snapshots.invitation_id
));

CREATE POLICY rls_matching_snapshot_selector
ON matching.invitation_disclosure_snapshots
FOR SELECT TO matching_selector
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_disclosure_snapshots.invitation_id
));

CREATE POLICY rls_matching_snapshot_coordinator
ON matching.invitation_disclosure_snapshots
FOR SELECT TO matching_coordinator
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_disclosure_snapshots.invitation_id
));

CREATE POLICY rls_matching_response_creator
ON matching.invitation_responses
FOR ALL TO matching_creator
USING (
    creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
)
WITH CHECK (
    creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
);

CREATE POLICY rls_matching_response_reviewer
ON matching.invitation_responses
FOR SELECT TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_responses.invitation_id
));

CREATE POLICY rls_matching_response_coordinator
ON matching.invitation_responses
FOR SELECT TO matching_coordinator
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_responses.invitation_id
));

CREATE POLICY rls_matching_withdrawal_creator
ON matching.invitation_withdrawals
FOR ALL TO matching_creator
USING (
    creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
)
WITH CHECK (
    creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND EXISTS (
        SELECT 1 FROM matching.invitations AS invitation
        WHERE invitation.id = invitation_withdrawals.invitation_id
          AND invitation.creator_user_id = invitation_withdrawals.creator_user_id
          AND invitation.status = 'WITHDRAWN'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
);

CREATE POLICY rls_matching_withdrawal_reviewer
ON matching.invitation_withdrawals
FOR SELECT TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_withdrawals.invitation_id
));

CREATE POLICY rls_matching_withdrawal_coordinator
ON matching.invitation_withdrawals
FOR SELECT TO matching_coordinator
USING (EXISTS (
    SELECT 1 FROM matching.invitations AS invitation
    WHERE invitation.id = invitation_withdrawals.invitation_id
));

CREATE POLICY rls_matching_selection_selector
ON matching.selections
FOR ALL TO matching_selector
USING (EXISTS (
    SELECT 1
    FROM matching.candidate_selector_assignments AS selector_assignment
    WHERE selector_assignment.selection_id = selections.id
      AND selector_assignment.organization_id = selections.organization_id
))
WITH CHECK (EXISTS (
    SELECT 1
    FROM matching.candidate_selector_assignments AS selector_assignment
    WHERE selector_assignment.selection_id = selections.id
      AND selector_assignment.organization_id = selections.organization_id
));

CREATE POLICY rls_matching_selection_reviewer
ON matching.selections
FOR ALL TO matching_review
USING (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = selections.attempt_id
))
WITH CHECK (EXISTS (
    SELECT 1 FROM matching.matching_review_assignments AS assignment
    WHERE assignment.attempt_id = selections.attempt_id
));

CREATE POLICY rls_matching_selection_worker
ON matching.selections
FOR INSERT TO matching_worker
WITH CHECK (EXISTS (
    SELECT 1 FROM matching.match_jobs AS job
    WHERE job.attempt_id = selections.attempt_id
));

CREATE POLICY rls_matching_selection_coordinator
ON matching.selections
FOR ALL TO matching_coordinator
USING (
    id = NULLIF(current_setting('app.selection_id', true), '')::uuid
    AND coordinator_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND coordinator_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
)
WITH CHECK (
    id = NULLIF(current_setting('app.selection_id', true), '')::uuid
    AND coordinator_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND coordinator_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
);

CREATE POLICY rls_matching_source_worker
ON matching.source_inbox
FOR ALL TO matching_worker
USING (
    workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND source_event_id = NULLIF(
        current_setting('app.source_event_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
)
WITH CHECK (
    workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND source_event_id = NULLIF(
        current_setting('app.source_event_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_receipt_principal
ON matching.command_receipts
FOR ALL TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator
USING (
    principal_id = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), '')::uuid,
        NULLIF(current_setting('app.workload_id', true), '')::uuid
    )
    AND operation = NULLIF(current_setting('app.operation', true), '')
    AND principal_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
)
WITH CHECK (
    principal_id = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), '')::uuid,
        NULLIF(current_setting('app.workload_id', true), '')::uuid
    )
    AND operation = NULLIF(current_setting('app.operation', true), '')
    AND principal_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_rule_worker
ON matching.rule_bundles
FOR ALL TO matching_worker
USING (
    published_by_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND published_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
)
WITH CHECK (
    published_by_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND published_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_rule_reviewer
ON matching.rule_bundles
FOR SELECT TO matching_review
USING (EXISTS (
    SELECT 1
    FROM matching.match_runs AS run
    JOIN matching.matching_review_assignments AS assignment
      ON assignment.attempt_id = run.attempt_id
    WHERE run.matching_rule_bundle_id = rule_bundles.id
));

CREATE POLICY rls_matching_rule_coordinator
ON matching.rule_bundles
FOR SELECT TO matching_coordinator
USING (
    id = NULLIF(current_setting('app.rule_bundle_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
);

CREATE POLICY rls_matching_selector_worker
ON matching.rule_selectors
FOR ALL TO matching_worker
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
    AND EXISTS (
        SELECT 1 FROM matching.rule_bundles AS bundle
        WHERE bundle.id = rule_selectors.current_bundle_id
    )
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
    AND EXISTS (
        SELECT 1 FROM matching.rule_bundles AS bundle
        WHERE bundle.id = rule_selectors.current_bundle_id
    )
);

CREATE POLICY rls_matching_selector_reviewer
ON matching.rule_selectors
FOR SELECT TO matching_review
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_REVIEW'
);

SET LOCAL ROLE schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;
GRANT INSERT ON audit.audit_events TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;
GRANT INSERT ON infra.outbox_events TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator;

CREATE POLICY rls_matching_audit_insert
ON audit.audit_events
FOR INSERT TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator
WITH CHECK (
    actor_id = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), '')::uuid,
        NULLIF(current_setting('app.workload_id', true), '')::uuid
    )
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND causation_id = command_id
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND target_kind IN (
        'MatchingAttempt', 'MatchRun', 'Invitation', 'Selection'
    )
    AND target_id = NULLIF(current_setting('app.target_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR', 'MATCHING_REVIEW',
        'MATCHING_WORKER', 'MATCHING_COORDINATOR'
    )
);

CREATE POLICY rls_matching_outbox_insert
ON infra.outbox_events
FOR INSERT TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator
WITH CHECK (
    actor_id = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), '')::uuid,
        NULLIF(current_setting('app.workload_id', true), '')::uuid
    )
    AND causation_id = NULLIF(
        current_setting('app.command_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND aggregate_type IN (
        'MatchingAttempt', 'MatchRun', 'Invitation', 'Selection'
    )
    AND aggregate_id = NULLIF(current_setting('app.target_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR', 'MATCHING_REVIEW',
        'MATCHING_WORKER', 'MATCHING_COORDINATOR'
    )
);

SET LOCAL ROLE matching_schema_owner;

DO $assert$
DECLARE
    invalid_online_roles integer;
    invalid_rls integer;
BEGIN
    SELECT count(*) INTO invalid_online_roles
    FROM pg_catalog.pg_roles
    WHERE rolname IN (
        'matching_creator', 'matching_selector', 'matching_review',
        'matching_worker', 'matching_coordinator'
    )
      AND (rolsuper OR rolbypassrls OR rolinherit OR NOT rolcanlogin);
    IF invalid_online_roles <> 0
       OR (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN (
            'matching_creator', 'matching_selector', 'matching_review',
            'matching_worker', 'matching_coordinator'
       )) <> 5 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Matching online role assertion failed';
    END IF;

    SELECT count(*) INTO invalid_rls
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'matching'
      AND relation.relkind = 'r'
      AND (NOT relation.relrowsecurity OR NOT relation.relforcerowsecurity);
    IF invalid_rls <> 0 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Matching FORCE RLS assertion failed';
    END IF;
END
$assert$;
