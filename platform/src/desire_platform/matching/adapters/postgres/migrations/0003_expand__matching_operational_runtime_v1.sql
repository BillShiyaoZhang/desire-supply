-- Fixed operational Matching programs.  Runtime roles receive no direct table
-- authority; every mutation is performed by an exact, role-bound program.

ALTER TABLE matching.rule_bundles
ADD COLUMN canonical_manifest_bytes bytea NULL,
ADD COLUMN manifest jsonb NULL,
ADD COLUMN invitation_limit integer NULL,
ADD CONSTRAINT ck_matching_rule_v3_manifest CHECK (
    (
        canonical_manifest_bytes IS NULL
        AND manifest IS NULL
        AND invitation_limit IS NULL
    )
    OR
    (
        octet_length(canonical_manifest_bytes) BETWEEN 1 AND 1048576
        AND jsonb_typeof(manifest) = 'object'
        AND sha256(canonical_manifest_bytes) = canonical_manifest_sha256
        AND invitation_limit BETWEEN 1 AND 500
    )
);

-- A reviewer cannot know a Creator's future authenticated session marker.
-- New invitations bind instead to the exact immutable Profile capture that
-- produced the eligible candidate.  IAM46 resolves the current Creator
-- session marker at list/read/respond time.  Legacy v1/v2 rows retain their
-- old marker shape but are never created by the v3 Operations programs.
ALTER TABLE matching.match_candidates
ADD CONSTRAINT uq_matching_candidate_recipient_evidence UNIQUE (
    attempt_id, match_run_id, creator_user_id, profile_id,
    profile_version_id, eligibility, profile_content_sha256,
    evidence_version_digest
);

ALTER TABLE matching.invitations
DROP CONSTRAINT ck_matching_invitation_shape,
ALTER COLUMN creator_authority_marker_sha256 DROP NOT NULL,
ADD COLUMN candidate_evidence_version_digest bytea NULL,
ADD CONSTRAINT fk_matching_invitation_recipient_evidence FOREIGN KEY (
    attempt_id, match_run_id, creator_user_id, profile_id,
    profile_version_id, candidate_eligibility, profile_content_sha256,
    candidate_evidence_version_digest
) REFERENCES matching.match_candidates (
    attempt_id, match_run_id, creator_user_id, profile_id,
    profile_version_id, eligibility, profile_content_sha256,
    evidence_version_digest
),
ADD CONSTRAINT ck_matching_invitation_shape_v3 CHECK (
    candidate_eligibility = 'ELIGIBLE'
    AND aggregate_version >= 1
    AND octet_length(profile_content_sha256) = 32
    AND octet_length(snapshot_sha256) = 32
    AND (
        (
            candidate_evidence_version_digest IS NULL
            AND octet_length(creator_authority_marker_sha256) = 32
        )
        OR
        (
            octet_length(candidate_evidence_version_digest) = 32
            AND creator_authority_marker_sha256 IS NULL
        )
    )
    AND expires_at > created_at AND updated_at >= created_at
    AND ((status = 'CREATED' AND sent_at IS NULL AND responded_at IS NULL)
        OR (status = 'SENT' AND sent_at IS NOT NULL
            AND responded_at IS NULL)
        OR (status IN ('ACCEPTED', 'DECLINED', 'WITHDRAWN')
            AND sent_at IS NOT NULL AND responded_at IS NOT NULL)
        OR status IN ('EXPIRED', 'REVOKED'))
);

ALTER TABLE matching.matching_attempts
ADD COLUMN source_authorization_digest bytea NULL,
ADD COLUMN original_actor_user_id uuid NULL,
ADD CONSTRAINT ck_matching_attempt_source_authorization_v3 CHECK (
    source_authorization_digest IS NULL
    OR octet_length(source_authorization_digest) = 32
),
ADD CONSTRAINT ck_matching_attempt_original_actor_v3 CHECK (
    original_actor_user_id IS NULL
    OR original_actor_user_id <> '00000000-0000-0000-0000-000000000000'::uuid
);

ALTER TABLE matching.source_inbox
ADD COLUMN original_actor_user_id uuid NULL,
ADD CONSTRAINT ck_matching_source_inbox_original_actor_v3 CHECK (
    original_actor_user_id IS NULL
    OR original_actor_user_id <>
        '00000000-0000-0000-0000-000000000000'::uuid
);

-- A worker may crash repeatedly before START_MATCH_RUN has persisted an input
-- set.  The frozen v1 constraint allowed FAILED only after start, which made a
-- bounded pre-start retry terminal state impossible.  Preserve every v1 state
-- and add exactly one closed pre-start terminal reason.
ALTER TABLE matching.match_runs
DROP CONSTRAINT ck_matching_run_shape,
ADD CONSTRAINT ck_matching_run_shape_v3 CHECK (
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
            AND failure_code IS NOT NULL
            AND (
                input_set_sha256 IS NOT NULL
                OR (
                    failure_code = 'WORKER_CLAIM_RETRY_EXHAUSTED'
                    AND input_manifest_sha256 IS NULL
                    AND input_set_sha256 IS NULL
                    AND ordered_result_sha256 IS NULL
                    AND worker_id IS NULL
                    AND lease_token_digest_key_id IS NULL
                    AND lease_token_digest IS NULL
                    AND lease_until IS NULL
                )
            ))
        OR status = 'CANCELLED'
    )
);

ALTER TABLE matching.match_jobs
ADD CONSTRAINT ck_matching_job_attempt_count_v3 CHECK (
    attempt_count BETWEEN 0 AND 3
);

ALTER TABLE matching.match_run_inputs
DROP CONSTRAINT ck_matching_input_contract,
ADD COLUMN run_input_sha256 bytea NULL,
ADD COLUMN canonical_input_set_bytes bytea NULL,
ADD COLUMN source_capture_schema_version integer NULL,
ADD COLUMN source_capture_canonicalization_version varchar(64) NULL,
ADD COLUMN canonical_source_capture_bytes bytea NULL,
ADD COLUMN source_capture jsonb NULL,
ADD COLUMN source_capture_sha256 bytea NULL,
ADD COLUMN source_authorization_valid_until timestamptz NULL,
ADD CONSTRAINT ck_matching_input_contract_v3 CHECK (
    manifest_schema_version = 1
    AND manifest_canonicalization_version = 'match-input-manifest-v1'
    AND run_input_schema_version = 1
    AND run_input_canonicalization_version IN (
        'match-run-input-v1', 'match-run-input-json-v1'
    )
    AND octet_length(canonical_manifest_bytes) BETWEEN 1 AND 1048576
    AND octet_length(canonical_run_input_bytes) BETWEEN 1 AND 8388608
    AND jsonb_typeof(manifest) = 'object'
    AND jsonb_typeof(run_input) = 'object'
    AND octet_length(manifest_sha256) = 32
    AND octet_length(input_set_sha256) = 32
    AND octet_length(candidate_allowlist_sha256) = 32
    AND candidate_count >= 0
),
ADD CONSTRAINT ck_matching_input_source_capture_v3 CHECK (
    (
        run_input_sha256 IS NULL
        AND canonical_input_set_bytes IS NULL
        AND source_capture_schema_version IS NULL
        AND source_capture_canonicalization_version IS NULL
        AND canonical_source_capture_bytes IS NULL
        AND source_capture IS NULL
        AND source_capture_sha256 IS NULL
        AND source_authorization_valid_until IS NULL
    )
    OR
    (
        run_input_canonicalization_version = 'match-run-input-json-v1'
        AND octet_length(run_input_sha256) = 32
        AND sha256(canonical_run_input_bytes) = run_input_sha256
        AND octet_length(canonical_input_set_bytes)
            BETWEEN 1 AND 16777216
        AND sha256(canonical_input_set_bytes) = input_set_sha256
        AND source_capture_schema_version = 1
        AND source_capture_canonicalization_version
            = 'matching-source-capture-bundle-json-v1'
        AND octet_length(canonical_source_capture_bytes)
            BETWEEN 1 AND 16777216
        AND jsonb_typeof(source_capture) = 'object'
        AND octet_length(source_capture_sha256) = 32
        AND sha256(canonical_source_capture_bytes) = source_capture_sha256
        AND source_authorization_valid_until > captured_at
    )
);

CREATE TABLE matching.match_run_results (
    match_run_id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    input_set_sha256 bytea NOT NULL,
    engine_identifier varchar(64) NOT NULL,
    engine_artifact_sha256 bytea NOT NULL,
    engine_result_sha256 bytea NOT NULL,
    schema_version integer NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    canonical_result_bytes bytea NOT NULL,
    result jsonb NOT NULL,
    ordered_result_sha256 bytea NOT NULL,
    candidate_count integer NOT NULL,
    eligible_count integer NOT NULL,
    excluded_count integer NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_result_run FOREIGN KEY (
        organization_id, attempt_id, match_run_id
    ) REFERENCES matching.match_runs (organization_id, attempt_id, id),
    CONSTRAINT fk_matching_result_rule FOREIGN KEY (matching_rule_bundle_id)
        REFERENCES matching.rule_bundles (id),
    CONSTRAINT ck_matching_result_contract CHECK (
        schema_version = 1
        AND canonicalization_version = 'deterministic-match-result-json-v1'
        AND engine_identifier = 'deterministic-matcher-v1'
        AND octet_length(canonical_result_bytes) BETWEEN 1 AND 8388608
        AND jsonb_typeof(result) = 'object'
        AND octet_length(input_set_sha256) = 32
        AND octet_length(engine_artifact_sha256) = 32
        AND octet_length(engine_result_sha256) = 32
        AND sha256(canonical_result_bytes) = engine_result_sha256
        AND octet_length(ordered_result_sha256) = 32
        AND candidate_count >= 0
        AND eligible_count >= 0
        AND excluded_count >= 0
        AND candidate_count = eligible_count + excluded_count
    )
);

CREATE TRIGGER trg_matching_result_immutable
BEFORE UPDATE OR DELETE ON matching.match_run_results
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TABLE matching.reviewer_authority_projections (
    duty_grant_id uuid NOT NULL,
    duty_grant_version bigint NOT NULL,
    reviewer_user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    role_code varchar(64) NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    source_event_id uuid NOT NULL UNIQUE,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    status varchar(16) NOT NULL,
    projected_by_workload_id uuid NOT NULL,
    projected_at timestamptz NOT NULL,
    CONSTRAINT pk_matching_reviewer_authority PRIMARY KEY (
        duty_grant_id, duty_grant_version
    ),
    CONSTRAINT ck_matching_reviewer_authority_shape CHECK (
        duty_grant_version >= 1
        AND role_code = 'MATCHING_REVIEWER'
        AND octet_length(authority_marker_sha256) = 32
        AND status IN ('ACTIVE', 'REVOKED', 'EXPIRED')
        AND valid_until > valid_from
        AND projected_at >= valid_from
    )
);

CREATE TRIGGER trg_matching_reviewer_authority_immutable
BEFORE UPDATE OR DELETE ON matching.reviewer_authority_projections
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TABLE matching.candidate_selector_opt_in_receipts (
    id uuid PRIMARY KEY,
    command_id uuid NOT NULL UNIQUE,
    actor_user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    role_code varchar(64) NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    iam_evidence_sha256 bytea NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_selector_opt_in_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT uq_matching_selector_opt_in_binding UNIQUE (
        id, actor_user_id, session_id, organization_id, demand_id,
        selection_id, authority_marker_sha256
    ),
    CONSTRAINT ck_matching_selector_opt_in_shape CHECK (
        role_code = 'CANDIDATE_SELECTOR'
        AND octet_length(authority_marker_sha256) = 32
        AND octet_length(iam_evidence_sha256) = 32
        AND valid_until > recorded_at
    )
);

CREATE TRIGGER trg_matching_selector_opt_in_immutable
BEFORE UPDATE OR DELETE ON matching.candidate_selector_opt_in_receipts
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TABLE matching.selection_close_intents (
    id uuid PRIMARY KEY,
    receipt_id uuid NOT NULL UNIQUE,
    command_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    candidate_selector_assignment_id uuid NOT NULL,
    candidate_selector_assignment_version bigint NOT NULL,
    candidate_selector_authority_marker_sha256 bytea NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    demand_aggregate_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    current_invitation_set_sha256 bytea NOT NULL,
    reason_code varchar(64) NOT NULL,
    attempt_close_event_id uuid NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_hash bytea NOT NULL,
    status varchar(16) NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_close_intent_receipt FOREIGN KEY (receipt_id)
        REFERENCES matching.command_receipts (id),
    CONSTRAINT fk_matching_close_intent_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_close_intent_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_close_intent_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT fk_matching_close_intent_assignment FOREIGN KEY (
        selection_id, candidate_selector_assignment_id
    ) REFERENCES matching.candidate_selector_assignments (selection_id, id),
    CONSTRAINT ck_matching_close_intent_shape CHECK (
        status = 'READY'
        AND candidate_selector_assignment_version >= 1
        AND demand_aggregate_version >= 1
        AND matching_request_version >= 1
        AND octet_length(candidate_selector_authority_marker_sha256) = 32
        AND octet_length(current_invitation_set_sha256) = 32
        AND octet_length(payload_hash) = 32
        AND reason_code ~ '^[A-Z][A-Z0-9_]{1,63}$'
    )
);

CREATE TRIGGER trg_matching_close_intent_immutable
BEFORE UPDATE OR DELETE ON matching.selection_close_intents
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

-- A zero-eligible-candidate result is a system fact, not a human selector
-- command.  Keep it separate from selector close intents so no synthetic
-- assignment, session, or authority marker can enter the terminal boundary.
CREATE TABLE matching.selection_system_close_intents (
    id uuid PRIMARY KEY,
    receipt_id uuid NOT NULL UNIQUE,
    command_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    original_actor_user_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    demand_aggregate_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    current_invitation_set_sha256 bytea NOT NULL,
    reason_code varchar(64) NOT NULL,
    attempt_close_event_id uuid NOT NULL UNIQUE,
    status varchar(16) NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_system_close_intent_receipt FOREIGN KEY (receipt_id)
        REFERENCES matching.command_receipts (id),
    CONSTRAINT fk_matching_system_close_intent_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_system_close_intent_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_system_close_intent_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT ck_matching_system_close_intent_shape CHECK (
        status = 'READY'
        AND original_actor_user_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND demand_aggregate_version >= 1
        AND matching_request_version >= 1
        AND octet_length(current_invitation_set_sha256) = 32
        AND reason_code = 'NO_ELIGIBLE_CANDIDATES'
    )
);

CREATE TRIGGER trg_matching_system_close_intent_immutable
BEFORE UPDATE OR DELETE ON matching.selection_system_close_intents
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

-- One durable, workload-bound completion item is created atomically with the
-- immutable selector intent.  The selection UUID is also the job UUID: a
-- selection can have only one terminal intent, so this is collision-free and
-- does not require the public HTTP caller to mint an operational identifier.
CREATE TABLE matching.selection_completion_jobs (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    intent_receipt_id uuid NOT NULL UNIQUE,
    intent_kind varchar(16) NOT NULL,
    status varchar(16) NOT NULL,
    workload_id uuid NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    lease_digest_key_id varchar(128) NULL,
    lease_digest bytea NULL,
    fencing_generation bigint NOT NULL,
    available_at timestamptz NOT NULL,
    lease_until timestamptz NULL,
    attempt_count integer NOT NULL,
    last_failure_code varchar(64) NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT fk_matching_completion_job_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_completion_job_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_completion_job_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT fk_matching_completion_job_receipt FOREIGN KEY (
        intent_receipt_id
    ) REFERENCES matching.command_receipts (id),
    CONSTRAINT ck_matching_completion_job_shape CHECK (
        intent_kind IN ('CHOOSE', 'CLOSE', 'SYSTEM_CLOSE')
        AND status IN ('AVAILABLE', 'LEASED', 'COMPLETED', 'FAILED')
        AND octet_length(authority_marker_sha256) = 32
        AND fencing_generation >= 0
        AND attempt_count BETWEEN 0 AND 3
        AND (
            (status = 'AVAILABLE'
             AND lease_digest_key_id IS NULL
             AND lease_digest IS NULL
             AND lease_until IS NULL
             AND completed_at IS NULL)
            OR
            (status = 'LEASED'
             AND lease_digest_key_id IS NOT NULL
             AND octet_length(lease_digest) = 32
             AND lease_until IS NOT NULL
             AND completed_at IS NULL)
            OR
            (status IN ('COMPLETED', 'FAILED')
             AND lease_digest_key_id IS NOT NULL
             AND octet_length(lease_digest) = 32
             AND lease_until IS NOT NULL
             AND completed_at IS NOT NULL)
        )
    )
);

CREATE UNIQUE INDEX uq_matching_completion_job_active_lease_digest
ON matching.selection_completion_jobs (
    workload_id, lease_digest_key_id, lease_digest
)
WHERE lease_digest IS NOT NULL;

-- Forward-compatible public representation: the stored aggregate remains
-- OPEN until cross-context coordination commits, while an immutable intent is
-- exposed as a distinct, non-actionable pending state at its own revision.
CREATE OR REPLACE FUNCTION matching.selection_projection_v1(
    exact_selection_id uuid,
    exact_assignment_id uuid,
    exact_assignment_version bigint
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
    SELECT jsonb_build_object(
        'selection_id', selection.id::text,
        'attempt_id', selection.attempt_id::text,
        'candidate_selector_assignment_id', exact_assignment_id::text,
        'candidate_selector_assignment_version', exact_assignment_version,
        'status', CASE
            WHEN selection.status='OPEN' AND choice_intent.id IS NOT NULL
                THEN 'PENDING_CHOICE'
            WHEN selection.status='OPEN'
                 AND (close_intent.id IS NOT NULL
                      OR system_close_intent.id IS NOT NULL)
                THEN 'PENDING_CLOSE'
            ELSE selection.status
        END,
        'aggregate_version', selection.aggregate_version,
        'updated_at', selection.updated_at,
        'current_invitation_set_sha256',
            encode(selection.current_invitation_set_sha256, 'hex'),
        'chosen_invitation_id', CASE
            WHEN selection.status='OPEN' THEN choice_intent.invitation_id::text
            ELSE selection.chosen_invitation_id::text
        END,
        'accepted_invitations', COALESCE((
            SELECT jsonb_agg(
                jsonb_build_object(
                    'invitation_id', invitation.id::text,
                    'creator_display_handle', 'creator_'
                        || substr(replace(invitation.creator_user_id::text, '-', ''), 1, 16),
                    'profile_id', invitation.profile_id::text,
                    'profile_version_id', invitation.profile_version_id::text,
                    'accepted_at', invitation.responded_at,
                    'capability_summary', 'Published creator profile '
                        || substr(replace(invitation.profile_id::text, '-', ''), 1, 16)
                ) ORDER BY invitation.id
            )
            FROM matching.invitations AS invitation
            WHERE invitation.attempt_id = selection.attempt_id
              AND invitation.match_run_id = selection.match_run_id
              AND invitation.status = 'ACCEPTED'
        ), '[]'::jsonb)
    )
    FROM matching.selections AS selection
    LEFT JOIN matching.selection_intents AS choice_intent
      ON choice_intent.selection_id=selection.id
    LEFT JOIN matching.selection_close_intents AS close_intent
      ON close_intent.selection_id=selection.id
    LEFT JOIN matching.selection_system_close_intents AS system_close_intent
      ON system_close_intent.selection_id=selection.id
    WHERE selection.id = exact_selection_id
$function$;

ALTER TABLE matching.candidate_selector_assignments
ADD COLUMN assignee_session_id uuid NULL,
ADD COLUMN opt_in_receipt_id uuid NULL,
ADD CONSTRAINT fk_matching_selector_assignment_opt_in
    FOREIGN KEY (
        opt_in_receipt_id, assignee_user_id, assignee_session_id,
        organization_id, demand_id, selection_id, authority_marker_sha256
    ) REFERENCES matching.candidate_selector_opt_in_receipts (
        id, actor_user_id, session_id, organization_id, demand_id,
        selection_id, authority_marker_sha256
    ),
ADD CONSTRAINT ck_matching_selector_assignment_v3_binding CHECK (
    (assignee_session_id IS NULL AND opt_in_receipt_id IS NULL)
    OR (assignee_session_id IS NOT NULL AND opt_in_receipt_id IS NOT NULL)
);

-- v1/v2 ACTIVE assignments carry only a user marker.  There is no trustworthy
-- authenticated Session or IAM44 opt-in fact from which to backfill the v3
-- binding.  Revoke those live grants while this DDL transaction exclusively
-- owns the table so they cannot become invisible-but-slot-holding rows under
-- the restrictive v3 policy.  The migration ledger is the administrative
-- audit boundary; fabricating a user command, audit event, or outbox fact here
-- would incorrectly attribute an action that never occurred.  Non-ACTIVE
-- history remains byte-for-byte attributable to its original schema shape.
-- ADD COLUMN above already holds ACCESS EXCLUSIVE through commit, so no
-- runtime statement can observe the brief owner-only FORCE bypass.
ALTER TABLE matching.candidate_selector_assignments
NO FORCE ROW LEVEL SECURITY;

UPDATE matching.candidate_selector_assignments
SET status = 'REVOKED',
    assignment_version = assignment_version + 1,
    completed_at = transaction_timestamp()
WHERE status = 'ACTIVE'
  AND assignee_session_id IS NULL
  AND opt_in_receipt_id IS NULL;

ALTER TABLE matching.candidate_selector_assignments
FORCE ROW LEVEL SECURITY;

ALTER TABLE matching.matching_review_assignments
ADD COLUMN reviewer_session_id uuid NULL,
ADD COLUMN claim_receipt_id uuid NULL,
ADD COLUMN claim_command_id uuid NULL,
ADD COLUMN role_code varchar(64) NULL,
ADD COLUMN duty_code varchar(64) NULL,
ADD CONSTRAINT fk_matching_review_assignment_claim_receipt
    FOREIGN KEY (claim_receipt_id) REFERENCES matching.command_receipts (id),
ADD CONSTRAINT uq_matching_review_assignment_claim_command
    UNIQUE (claim_command_id),
ADD CONSTRAINT uq_matching_review_assignment_exact_binding UNIQUE (
    id, reviewer_user_id, reviewer_session_id, organization_id,
    attempt_id, match_run_id, authority_marker_sha256
),
ADD CONSTRAINT ck_matching_review_assignment_v3_binding CHECK (
    (
        reviewer_session_id IS NULL
        AND claim_receipt_id IS NULL
        AND claim_command_id IS NULL
        AND role_code IS NULL
        AND duty_code IS NULL
    )
    OR
    (
        reviewer_session_id IS NOT NULL
        AND claim_receipt_id IS NOT NULL
        AND claim_command_id IS NOT NULL
        AND role_code = 'MATCHING_REVIEWER'
        AND duty_code = 'OPERATIONS_REVIEWER'
    )
);

-- The same fail-closed transition releases every legacy review slot.  A v2
-- row has neither a reviewer Session nor an immutable claim receipt, so it
-- cannot safely authorize v3 resume/resolve operations.  Bound v3 rows are
-- excluded explicitly, which also documents the idempotent data predicate.
ALTER TABLE matching.matching_review_assignments
NO FORCE ROW LEVEL SECURITY;

UPDATE matching.matching_review_assignments
SET status = 'REVOKED',
    aggregate_version = aggregate_version + 1,
    completed_at = transaction_timestamp()
WHERE status = 'ACTIVE'
  AND reviewer_session_id IS NULL
  AND claim_receipt_id IS NULL
  AND claim_command_id IS NULL
  AND role_code IS NULL
  AND duty_code IS NULL;

ALTER TABLE matching.matching_review_assignments
FORCE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX uq_matching_active_review_target
ON matching.matching_review_assignments (attempt_id, purpose_code)
WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX uq_matching_active_review_per_reviewer
ON matching.matching_review_assignments (reviewer_user_id)
WHERE status = 'ACTIVE';

CREATE TABLE matching.complete_selection_records (
    choose_receipt_id uuid PRIMARY KEY,
    completion_command_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    expected_demand_version bigint NOT NULL,
    completed_demand_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    expected_matching_request_version bigint NOT NULL,
    completed_matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    candidate_selector_assignment_id uuid NOT NULL,
    candidate_selector_assignment_version bigint NOT NULL,
    original_actor_user_id uuid NOT NULL,
    coordinator_workload_id uuid NOT NULL,
    coordinator_authority_marker_sha256 bytea NOT NULL,
    trust_evidence_sha256 bytea NOT NULL,
    trust_evaluated_at timestamptz NOT NULL,
    trust_valid_until timestamptz NOT NULL,
    demand_matched_event_id uuid NOT NULL,
    matching_event_ids uuid[] NOT NULL,
    status varchar(16) NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_completion_intent FOREIGN KEY (choose_receipt_id)
        REFERENCES matching.command_receipts (id),
    CONSTRAINT fk_matching_completion_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_completion_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_completion_invitation FOREIGN KEY (
        attempt_id, invitation_id
    ) REFERENCES matching.invitations (attempt_id, id),
    CONSTRAINT fk_matching_completion_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT fk_matching_completion_assignment FOREIGN KEY (
        selection_id, candidate_selector_assignment_id
    ) REFERENCES matching.candidate_selector_assignments (selection_id, id),
    CONSTRAINT ck_matching_completion_shape CHECK (
        status = 'COMPLETED'
        AND expected_demand_version >= 1
        AND completed_demand_version = expected_demand_version + 1
        AND expected_matching_request_version >= 1
        AND completed_matching_request_version
            = expected_matching_request_version + 1
        AND candidate_selector_assignment_version >= 1
        AND octet_length(coordinator_authority_marker_sha256) = 32
        AND octet_length(trust_evidence_sha256) = 32
        AND trust_valid_until > trust_evaluated_at
        AND completed_at <= trust_valid_until
        AND cardinality(matching_event_ids) = 2
    )
);

CREATE TRIGGER trg_matching_completion_immutable
BEFORE UPDATE OR DELETE ON matching.complete_selection_records
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TABLE matching.complete_selection_close_records (
    close_receipt_id uuid PRIMARY KEY,
    completion_command_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    expected_demand_version bigint NOT NULL,
    completed_demand_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    expected_matching_request_version bigint NOT NULL,
    completed_matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    candidate_selector_assignment_id uuid NOT NULL,
    candidate_selector_assignment_version bigint NOT NULL,
    original_actor_user_id uuid NOT NULL,
    coordinator_workload_id uuid NOT NULL,
    coordinator_authority_marker_sha256 bytea NOT NULL,
    reason_code varchar(64) NOT NULL,
    demand_closed_event_id uuid NOT NULL,
    matching_event_ids uuid[] NOT NULL,
    status varchar(16) NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_close_completion_intent FOREIGN KEY (
        close_receipt_id
    ) REFERENCES matching.command_receipts (id),
    CONSTRAINT fk_matching_close_completion_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_close_completion_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_close_completion_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT fk_matching_close_completion_assignment FOREIGN KEY (
        selection_id, candidate_selector_assignment_id
    ) REFERENCES matching.candidate_selector_assignments (selection_id, id),
    CONSTRAINT ck_matching_close_completion_shape CHECK (
        status = 'COMPLETED'
        AND expected_demand_version >= 1
        AND completed_demand_version = expected_demand_version + 1
        AND expected_matching_request_version >= 1
        AND completed_matching_request_version
            = expected_matching_request_version + 1
        AND candidate_selector_assignment_version >= 1
        AND octet_length(coordinator_authority_marker_sha256) = 32
        AND reason_code ~ '^[A-Z][A-Z0-9_]{1,63}$'
        AND cardinality(matching_event_ids) = 2
    )
);

CREATE TRIGGER trg_matching_close_completion_immutable
BEFORE UPDATE OR DELETE ON matching.complete_selection_close_records
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

CREATE TABLE matching.complete_selection_system_close_records (
    close_receipt_id uuid PRIMARY KEY,
    system_close_intent_id uuid NOT NULL UNIQUE,
    completion_command_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    expected_demand_version bigint NOT NULL,
    completed_demand_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    expected_matching_request_version bigint NOT NULL,
    completed_matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    original_actor_user_id uuid NOT NULL,
    coordinator_workload_id uuid NOT NULL,
    coordinator_authority_marker_sha256 bytea NOT NULL,
    reason_code varchar(64) NOT NULL,
    demand_closed_event_id uuid NOT NULL UNIQUE,
    matching_event_ids uuid[] NOT NULL,
    status varchar(16) NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_system_close_completion_intent FOREIGN KEY (
        system_close_intent_id
    ) REFERENCES matching.selection_system_close_intents (id),
    CONSTRAINT fk_matching_system_close_completion_receipt FOREIGN KEY (
        close_receipt_id
    ) REFERENCES matching.command_receipts (id),
    CONSTRAINT fk_matching_system_close_completion_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_system_close_completion_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_system_close_completion_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT ck_matching_system_close_completion_shape CHECK (
        status = 'COMPLETED'
        AND expected_demand_version >= 1
        AND completed_demand_version = expected_demand_version + 1
        AND expected_matching_request_version >= 1
        AND completed_matching_request_version
            = expected_matching_request_version + 1
        AND original_actor_user_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(coordinator_authority_marker_sha256) = 32
        AND reason_code = 'NO_ELIGIBLE_CANDIDATES'
        AND cardinality(matching_event_ids) = 2
    )
);

CREATE TRIGGER trg_matching_system_close_completion_immutable
BEFORE UPDATE OR DELETE ON matching.complete_selection_system_close_records
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

-- Trust is evaluated through the separately credentialed trust_decision
-- adapter immediately before a reviewer mutation.  Matching freezes the exact
-- short-lived ALLOW result and every fact it covered in the same transaction
-- as the command; it never persists a caller assertion in lieu of evidence.
CREATE TABLE matching.review_hold_evidence (
    id uuid PRIMARY KEY,
    command_id uuid NOT NULL UNIQUE,
    operation varchar(32) NOT NULL,
    actor_user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_aggregate_version bigint NOT NULL,
    demand_version_id uuid NOT NULL,
    demand_content_sha256 bytea NOT NULL,
    policy_version varchar(64) NOT NULL,
    decision varchar(8) NOT NULL,
    evidence_sha256 bytea NOT NULL,
    evaluated_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT fk_matching_review_hold_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_review_hold_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT ck_matching_review_hold_shape CHECK (
        operation IN ('CREATE_INVITATION', 'PUBLISH_INVITATION')
        AND demand_aggregate_version >= 1
        AND policy_version = 'demand-safety-hold-v1'
        AND decision = 'ALLOW'
        AND octet_length(demand_content_sha256) = 32
        AND octet_length(evidence_sha256) = 32
        AND valid_until > evaluated_at
        AND valid_until - evaluated_at <= interval '15 seconds'
        AND recorded_at >= evaluated_at
        AND recorded_at <= valid_until
    )
);

CREATE TRIGGER trg_matching_review_hold_immutable
BEFORE UPDATE OR DELETE ON matching.review_hold_evidence
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

ALTER TABLE matching.match_run_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.match_run_results FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.reviewer_authority_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.reviewer_authority_projections FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.candidate_selector_opt_in_receipts
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.candidate_selector_opt_in_receipts
    FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_close_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_close_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_system_close_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_system_close_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_completion_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_completion_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.complete_selection_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.complete_selection_records FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.complete_selection_close_records
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.complete_selection_close_records
    FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.complete_selection_system_close_records
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.complete_selection_system_close_records
    FORCE ROW LEVEL SECURITY;
ALTER TABLE matching.review_hold_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.review_hold_evidence FORCE ROW LEVEL SECURITY;

-- Remove the v1 direct-table authority.  Public traffic and all operational
-- traffic now use only matching_api SECURITY DEFINER programs.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA matching FROM
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator, matching_assignment;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA matching FROM
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator, matching_assignment;
GRANT SELECT ON matching.schema_compatibility TO
    matching_creator, matching_selector, matching_review,
    matching_worker, matching_coordinator, matching_assignment;

GRANT USAGE ON SCHEMA matching_api TO
    matching_review, matching_worker, matching_coordinator,
    matching_assignment;

-- IAM46 proves the current Creator principal before these v3 invitation rows
-- (which deliberately carry no future-session marker) become visible.  The
-- evidence GUC is set only inside the fixed Matching programs; runtime roles
-- retain no relation privilege even if they forge a custom GUC themselves.
CREATE POLICY rls_matching_creator_v3_invitation_definer
ON matching.invitations
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_creator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND creator_authority_marker_sha256 IS NULL
    AND octet_length(candidate_evidence_version_digest) = 32
    AND octet_length(pg_catalog.decode(NULLIF(
        current_setting('app.creator_authority_evidence_sha256', true), ''
    ),'hex')) = 32
    AND (
        (
            NULLIF(current_setting('app.operation', true), '')
                = 'LIST_MATCHING_INVITATIONS'
            AND COALESCE(current_setting('app.invitation_id', true), '') = ''
            AND status <> 'CREATED'
        )
        OR (
            NULLIF(current_setting('app.operation', true), '') IN (
                'READ_MATCHING_INVITATION','ACCEPT_INVITATION',
                'DECLINE_INVITATION','WITHDRAW_INVITATION'
            )
            AND id = NULLIF(
                current_setting('app.invitation_id', true), ''
            )::uuid
        )
    )
)
WITH CHECK (
    session_user = 'matching_creator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_INVITATION','DECLINE_INVITATION','WITHDRAW_INVITATION'
    )
    AND id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND creator_authority_marker_sha256 IS NULL
    AND octet_length(candidate_evidence_version_digest) = 32
    AND octet_length(pg_catalog.decode(NULLIF(
        current_setting('app.creator_authority_evidence_sha256', true), ''
    ),'hex')) = 32
    AND status IN ('ACCEPTED','DECLINED','WITHDRAWN')
);

CREATE POLICY rls_matching_creator_v3_snapshot_definer
ON matching.invitation_disclosure_snapshots
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_creator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
    AND octet_length(pg_catalog.decode(NULLIF(
        current_setting('app.creator_authority_evidence_sha256', true), ''
    ),'hex')) = 32
    AND EXISTS (
        SELECT 1
        FROM matching.invitations AS invitation
        WHERE invitation.id=invitation_disclosure_snapshots.invitation_id
          AND invitation.creator_user_id=NULLIF(
              current_setting('app.actor_user_id', true), ''
          )::uuid
          AND invitation.creator_authority_marker_sha256 IS NULL
          AND octet_length(
              invitation.candidate_evidence_version_digest
          )=32
    )
);

-- The owner is still subject to FORCE RLS.  These policies are deliberately
-- restricted by session_user and the transaction-local scope established by
-- the operational adapter.  No runtime role can exercise them directly.
CREATE POLICY rls_matching_operational_rule_definer
ON matching.rule_bundles
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
    AND published_by_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND published_authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
)
WITH CHECK (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
    AND published_by_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND published_authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_worker_rule_read_definer
ON matching.rule_bundles
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND id = NULLIF(
        current_setting('app.rule_bundle_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_operational_selector_definer
ON matching.rule_selectors
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
)
WITH CHECK (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_operational_attempt_definer
ON matching.matching_attempts
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_WORKER', 'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
)
WITH CHECK (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_WORKER', 'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
);

CREATE POLICY rls_matching_operational_run_definer
ON matching.match_runs
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_WORKER', 'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
)
WITH CHECK (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_WORKER', 'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
);

-- PostgreSQL applies UPDATE RLS visibility to rows locked by SELECT ... FOR
-- SHARE. Candidate selection locks exactly the current run while holding the
-- parent attempt FOR UPDATE; expose only that one run to the definer for the
-- lock, and never permit a selector-authored row image.
CREATE POLICY rls_matching_selector_run_lock_definer
ON matching.match_runs
FOR UPDATE TO matching_schema_owner
USING (
    session_user = 'matching_selector'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND attempt_id = NULLIF(
        current_setting('app.attempt_id', true), ''
    )::uuid
    AND id = NULLIF(
        current_setting('app.match_run_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND NULLIF(current_setting('app.operation', true), '')
        IN ('CHOOSE_CREATOR', 'CLOSE_SELECTION')
)
WITH CHECK (false);

CREATE POLICY rls_matching_review_claim_attempt_definer
ON matching.matching_attempts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
    AND status = 'OPEN'
);

CREATE POLICY rls_matching_review_claim_run_definer
ON matching.match_runs
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
    AND status IN ('COMPLETED', 'FAILED')
);

CREATE POLICY rls_matching_operational_input_definer
ON matching.match_run_inputs
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
)
WITH CHECK (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_operational_candidate_definer
ON matching.match_candidates
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND EXISTS (
        SELECT 1 FROM matching.matching_attempts AS attempt
        WHERE attempt.id = match_candidates.attempt_id
          AND attempt.organization_id = NULLIF(
              current_setting('app.organization_id', true), ''
          )::uuid
    )
)
WITH CHECK (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_WORKER'
);

CREATE POLICY rls_matching_operational_invitation_definer
ON matching.invitations
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
)
WITH CHECK (
    session_user IN ('matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
);

CREATE POLICY rls_matching_operational_snapshot_definer
ON matching.invitation_disclosure_snapshots
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_REVIEW'
)
WITH CHECK (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_operational_selection_definer
ON matching.selections
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_WORKER', 'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
)
WITH CHECK (
    session_user IN ('matching_worker', 'matching_review', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_WORKER', 'MATCHING_REVIEW', 'MATCHING_COORDINATOR'
    )
);

CREATE POLICY rls_matching_assignment_selection_definer
ON matching.selections
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(current_setting('app.selection_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
);

CREATE POLICY rls_matching_assignment_selection_lock_definer
ON matching.selections
FOR UPDATE TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
)
WITH CHECK (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
);

CREATE POLICY rls_matching_assignment_attempt_definer
ON matching.matching_attempts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND (
        selection_id = NULLIF(
            current_setting('app.selection_id', true), ''
        )::uuid
        OR COALESCE(current_setting('app.selection_id', true), '') = ''
    )
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
);

CREATE POLICY rls_matching_assignment_attempt_lock_definer
ON matching.matching_attempts
FOR UPDATE TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND (
        selection_id = NULLIF(
            current_setting('app.selection_id', true), ''
        )::uuid
        OR COALESCE(current_setting('app.selection_id', true), '') = ''
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
)
WITH CHECK (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
);

CREATE POLICY rls_matching_operational_selector_assignment_definer
ON matching.candidate_selector_assignments
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_worker', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user IN ('matching_worker', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_assignment_selector_assignment_definer
ON matching.candidate_selector_assignments
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND (
        (
            status = 'ACTIVE'
            AND assignee_user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
            )::uuid
            AND assignee_session_id = NULLIF(
                current_setting('app.session_id', true), ''
            )::uuid
            AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
                current_setting('app.authority_marker_sha256', true), ''
            ), 'hex')
        )
        OR (
            status = 'EXPIRED'
            AND completed_at IS NOT NULL
            AND expires_at <= transaction_timestamp()
        )
    )
);

CREATE POLICY rls_matching_review_selector_assignment_definer
ON matching.candidate_selector_assignments
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

-- The marker is session-bound by IAM44.  This restrictive policy adds the
-- missing session equality to every existing v2 selector program without
-- altering the immutable 0002 bytes.
CREATE POLICY rls_matching_selector_session_binding_definer
ON matching.candidate_selector_assignments
AS RESTRICTIVE
FOR SELECT TO matching_schema_owner
USING (
    session_user <> 'matching_selector'
    OR (
        assignee_session_id IS NOT NULL
        AND assignee_session_id = NULLIF(
            current_setting('app.session_id', true), ''
        )::uuid
    )
);

CREATE POLICY rls_matching_operational_review_assignment_definer
ON matching.matching_review_assignments
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_review', 'matching_worker')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user IN ('matching_review', 'matching_worker')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_review_claim_assignment_definer
ON matching.matching_review_assignments
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
)
WITH CHECK (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        IN ('MATCHING_REVIEW_CLAIM', 'MATCHING_REVIEW')
    AND (
        NULLIF(current_setting('app.scope_kind', true), '')
            = 'MATCHING_REVIEW_CLAIM'
        OR (
            organization_id = NULLIF(
                current_setting('app.organization_id', true), ''
            )::uuid
            AND reviewer_user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
            )::uuid
            AND reviewer_session_id = NULLIF(
                current_setting('app.session_id', true), ''
            )::uuid
            AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
                current_setting('app.authority_marker_sha256', true), ''
            ), 'hex')
        )
    )
);

CREATE POLICY rls_matching_review_resume_assignment_definer
ON matching.matching_review_assignments
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_REVIEW_RESUME', 'MATCHING_REVIEW_RESOLVE'
    )
    AND reviewer_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND reviewer_session_id = NULLIF(
        current_setting('app.session_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_review_exact_assignment_definer
ON matching.matching_review_assignments
AS RESTRICTIVE
FOR SELECT TO matching_schema_owner
USING (
    session_user <> 'matching_review'
    OR NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_REVIEW_CLAIM', 'MATCHING_REVIEW_RESUME',
        'MATCHING_REVIEW_RESOLVE'
    )
    OR (
        reviewer_user_id = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )::uuid
        AND reviewer_session_id = NULLIF(
            current_setting('app.session_id', true), ''
        )::uuid
        AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
            current_setting('app.authority_marker_sha256', true), ''
        ), 'hex')
    )
);

CREATE POLICY rls_matching_operational_job_definer
ON matching.match_jobs
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
)
WITH CHECK (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

-- CLAIM_MATCH_JOB starts without a tenant target: the worker can only see an
-- eligible job already bound to its exact workload authority.  The function
-- binds app.organization_id from the locked row before performing any write.
CREATE POLICY rls_matching_worker_job_discovery_select_definer
ON matching.match_jobs
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCH_JOB'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
    AND job_kind = 'RUN_MATCH'
    AND (
        (status = 'AVAILABLE'
            AND available_at <= transaction_timestamp())
        OR (status = 'LEASED'
            AND lease_until <= transaction_timestamp())
    )
);

CREATE POLICY rls_matching_worker_job_discovery_lock_definer
ON matching.match_jobs
FOR UPDATE TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCH_JOB'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
    AND job_kind = 'RUN_MATCH'
    AND (
        (status = 'AVAILABLE'
            AND available_at <= transaction_timestamp())
        OR (status = 'LEASED'
            AND lease_until <= transaction_timestamp())
    )
);

CREATE POLICY rls_matching_worker_run_discovery_select_definer
ON matching.match_runs
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCH_JOB'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND EXISTS (
        SELECT 1
        FROM matching.match_jobs AS discovery_job
        WHERE discovery_job.match_run_id = match_runs.id
          AND discovery_job.organization_id = match_runs.organization_id
          AND discovery_job.attempt_id = match_runs.attempt_id
          AND discovery_job.workload_id = NULLIF(
              current_setting('app.workload_id', true), ''
          )::uuid
          AND discovery_job.authority_marker_sha256 = pg_catalog.decode(
              NULLIF(current_setting(
                  'app.authority_marker_sha256', true
              ), ''),
              'hex'
          )
          AND discovery_job.job_kind = 'RUN_MATCH'
          AND (
              (
                  discovery_job.status = 'AVAILABLE'
                  AND discovery_job.available_at
                      <= transaction_timestamp()
                  AND match_runs.status = 'QUEUED'
              )
              OR (
                  discovery_job.status = 'LEASED'
                  AND discovery_job.lease_until
                      <= transaction_timestamp()
                  AND match_runs.status IN ('QUEUED', 'RUNNING')
              )
          )
    )
);

CREATE POLICY rls_matching_operational_source_definer
ON matching.source_inbox
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
)
WITH CHECK (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

-- Organization is intentionally absent from worker job discovery.  Make its
-- command identity globally unique for the workload so concurrent retries
-- cannot claim jobs in two organizations with one idempotency identity.
CREATE UNIQUE INDEX uq_matching_claim_job_receipt_identity_global
ON matching.command_receipts (
    principal_id, command_version, identity_key_id, identity_digest
)
WHERE principal_kind = 'SYSTEM' AND operation = 'CLAIM_MATCH_JOB';

CREATE POLICY rls_matching_operational_receipt_definer
ON matching.command_receipts
FOR ALL TO matching_schema_owner
USING (
    session_user IN (
        'matching_assignment', 'matching_review',
        'matching_worker', 'matching_coordinator'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND operation = NULLIF(current_setting('app.operation', true), '')
)
WITH CHECK (
    session_user IN (
        'matching_assignment', 'matching_review',
        'matching_worker', 'matching_coordinator'
    )
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND operation = NULLIF(current_setting('app.operation', true), '')
);

-- A coordinator claim begins before any organization is known.  The only
-- globally visible receipts are its own workload-bound claim receipts; once a
-- target is derived the normal organization policy above governs all writes.
CREATE POLICY rls_matching_coordinator_claim_receipt_definer
ON matching.command_receipts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR_CLAIM'
    AND operation = 'CLAIM_SELECTION_COMPLETION'
    AND principal_kind = 'SYSTEM'
    AND principal_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND principal_authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_review_claim_receipt_definer
ON matching.command_receipts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
    AND operation = 'CLAIM_MATCHING_REVIEW'
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND principal_authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_review_resume_receipt_definer
ON matching.command_receipts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_RESUME'
    AND operation = 'RELEASE_MATCHING_REVIEW'
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND principal_authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE UNIQUE INDEX uq_matching_review_claim_receipt_identity
ON matching.command_receipts (
    principal_kind, principal_id, operation, command_version,
    identity_key_id, identity_digest
)
WHERE operation = 'CLAIM_MATCHING_REVIEW';

CREATE UNIQUE INDEX uq_matching_review_release_receipt_identity
ON matching.command_receipts (
    principal_kind, principal_id, operation, command_version,
    identity_key_id, identity_digest
)
WHERE operation = 'RELEASE_MATCHING_REVIEW';

CREATE UNIQUE INDEX uq_matching_coordinator_claim_receipt_identity
ON matching.command_receipts (
    principal_kind, principal_id, operation, command_version,
    identity_key_id, identity_digest
)
WHERE operation = 'CLAIM_SELECTION_COMPLETION';

-- A targetless claim must find its prior receipt before the receipt's tenant
-- is known.  Runtime roles still have no relation privileges, and this policy
-- is read-only, operation-specific, and exact-workload/authority scoped.
CREATE POLICY rls_matching_worker_claim_receipt_discovery_definer
ON matching.command_receipts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCH_JOB'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND principal_kind = 'SYSTEM'
    AND principal_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND operation = 'CLAIM_MATCH_JOB'
    AND principal_authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_operational_intent_definer
ON matching.selection_intents
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
);

CREATE POLICY rls_matching_review_intent_definer
ON matching.selection_intents
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_assignment_pending_intent_definer
ON matching.selection_intents
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
);

CREATE POLICY rls_matching_operational_close_intent_definer
ON matching.selection_close_intents
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_selector','matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user = 'matching_selector'
    AND actor_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND candidate_selector_assignment_id = NULLIF(
        current_setting('app.selector_assignment_id', true), ''
    )::uuid
    AND candidate_selector_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
);

CREATE POLICY rls_matching_review_close_intent_definer
ON matching.selection_close_intents
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_system_close_intent_definer
ON matching.selection_system_close_intents
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
)
WITH CHECK (false);

CREATE POLICY rls_matching_worker_system_close_intent_definer
ON matching.selection_system_close_intents
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND EXISTS (
        SELECT 1 FROM matching.matching_attempts AS attempt
        WHERE attempt.id = selection_system_close_intents.attempt_id
          AND attempt.organization_id
                = selection_system_close_intents.organization_id
          AND attempt.selection_id
                = selection_system_close_intents.selection_id
          AND attempt.current_match_run_id
                = selection_system_close_intents.match_run_id
          AND attempt.original_actor_user_id
                = selection_system_close_intents.original_actor_user_id
          AND attempt.system_workload_id = NULLIF(
                current_setting('app.workload_id', true), ''
              )::uuid
          AND attempt.system_authority_marker_sha256 = pg_catalog.decode(
                NULLIF(current_setting(
                    'app.authority_marker_sha256', true
                ), ''), 'hex'
              )
    )
);

CREATE POLICY rls_matching_selector_completion_job_definer
ON matching.selection_completion_jobs
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user = 'matching_selector'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND EXISTS (
        SELECT 1
        FROM matching.selections AS selection
        WHERE selection.id = selection_completion_jobs.selection_id
          AND selection.organization_id
                = selection_completion_jobs.organization_id
          AND selection.attempt_id = selection_completion_jobs.attempt_id
          AND selection.match_run_id = selection_completion_jobs.match_run_id
          AND selection.coordinator_workload_id
                = selection_completion_jobs.workload_id
          AND selection.coordinator_authority_marker_sha256
                = selection_completion_jobs.authority_marker_sha256
    )
);

CREATE POLICY rls_matching_worker_completion_job_definer
ON matching.selection_completion_jobs
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user = 'matching_worker'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_WORKER'
    AND intent_kind = 'SYSTEM_CLOSE'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND EXISTS (
        SELECT 1
        FROM matching.selections AS selection
        JOIN matching.matching_attempts AS attempt
          ON attempt.id = selection.attempt_id
         AND attempt.organization_id = selection.organization_id
        WHERE selection.id = selection_completion_jobs.selection_id
          AND selection.organization_id
                = selection_completion_jobs.organization_id
          AND selection.attempt_id = selection_completion_jobs.attempt_id
          AND selection.match_run_id = selection_completion_jobs.match_run_id
          AND selection.coordinator_workload_id
                = selection_completion_jobs.workload_id
          AND selection.coordinator_authority_marker_sha256
                = selection_completion_jobs.authority_marker_sha256
          AND attempt.system_workload_id = NULLIF(
                current_setting('app.workload_id', true), ''
              )::uuid
    )
);

-- Targetless claim visibility is bounded to the exact authenticated workload
-- and marker already frozen on the Selection.  Completion/failure switches to
-- organization + selection scope after the job itself derives those facts.
CREATE POLICY rls_matching_coordinator_completion_job_claim_definer
ON matching.selection_completion_jobs
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR_CLAIM'
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR_CLAIM'
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_coordinator_completion_job_definer
ON matching.selection_completion_jobs
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_COORDINATOR'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(NULLIF(
        current_setting('app.authority_marker_sha256', true), ''
    ), 'hex')
);

CREATE POLICY rls_matching_assignment_pending_close_intent_definer
ON matching.selection_close_intents
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_assignment'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND demand_id = NULLIF(
        current_setting('app.demand_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_ASSIGNMENT'
);

CREATE POLICY rls_matching_operational_result_definer
ON matching.match_run_results
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user = 'matching_worker'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_review_result_definer
ON matching.match_run_results
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_review_input_definer
ON matching.match_run_inputs
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_review_rule_definer
ON matching.rule_bundles
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND id = NULLIF(
        current_setting('app.rule_bundle_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_review_hold_definer
ON matching.review_hold_evidence
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND actor_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND operation = NULLIF(current_setting('app.operation', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
)
WITH CHECK (
    session_user = 'matching_review'
    AND actor_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND operation = NULLIF(current_setting('app.operation', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW'
);

CREATE POLICY rls_matching_operational_reviewer_authority_definer
ON matching.reviewer_authority_projections
FOR ALL TO matching_schema_owner
USING (
    (session_user = 'matching_worker'
        AND projected_by_workload_id = NULLIF(
            current_setting('app.workload_id', true), ''
        )::uuid)
    OR (session_user = 'matching_review'
        AND reviewer_user_id = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )::uuid
        AND organization_id = NULLIF(
            current_setting('app.organization_id', true), ''
        )::uuid)
)
WITH CHECK (
    session_user = 'matching_worker'
    AND projected_by_workload_id = NULLIF(
        current_setting('app.workload_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_operational_selector_opt_in_definer
ON matching.candidate_selector_opt_in_receipts
FOR ALL TO matching_schema_owner
USING (
    (session_user = 'matching_assignment'
        AND actor_user_id = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )::uuid
        AND session_id = NULLIF(
            current_setting('app.session_id', true), ''
        )::uuid)
    OR (session_user IN ('matching_worker', 'matching_coordinator')
        AND organization_id = NULLIF(
            current_setting('app.organization_id', true), ''
        )::uuid)
)
WITH CHECK (
    session_user = 'matching_assignment'
    AND actor_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND session_id = NULLIF(
        current_setting('app.session_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_operational_completion_definer
ON matching.complete_selection_records
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_operational_close_completion_definer
ON matching.complete_selection_close_records
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
);

CREATE POLICY rls_matching_operational_system_close_completion_definer
ON matching.complete_selection_system_close_records
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
);

SET LOCAL ROLE schema_owner;

CREATE POLICY rls_matching_operational_audit_definer
ON audit.audit_events
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user IN (
        'matching_assignment', 'matching_review',
        'matching_worker', 'matching_coordinator'
    )
    AND actor_kind = CASE
        WHEN session_user IN ('matching_assignment', 'matching_review')
        THEN 'USER' ELSE 'SYSTEM' END
    AND actor_id = CASE
        WHEN session_user IN ('matching_assignment', 'matching_review')
        THEN NULLIF(current_setting('app.actor_user_id', true), '')::uuid
        ELSE NULLIF(current_setting('app.workload_id', true), '')::uuid
    END
    AND command_id = NULLIF(
        current_setting('app.command_id', true), ''
    )::uuid
    AND causation_id = command_id
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND target_kind IN (
        'MatchingRule', 'MatchingAttempt', 'MatchRun', 'MatchJob',
        'Invitation', 'Selection', 'MatchingReviewAssignment',
        'CandidateSelectorAssignment', 'SelectionCompletionJob'
    )
);

CREATE POLICY rls_matching_operational_outbox_definer
ON infra.outbox_events
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user IN (
        'matching_assignment', 'matching_review',
        'matching_worker', 'matching_coordinator'
    )
    AND actor_kind = CASE
        WHEN session_user IN ('matching_assignment', 'matching_review')
        THEN 'USER' ELSE 'SYSTEM' END
    AND actor_id = CASE
        WHEN session_user IN ('matching_assignment', 'matching_review')
        THEN NULLIF(current_setting('app.actor_user_id', true), '')::uuid
        ELSE NULLIF(current_setting('app.workload_id', true), '')::uuid
    END
    AND causation_id = NULLIF(
        current_setting('app.command_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND aggregate_type IN (
        'MatchingRule', 'MatchingAttempt', 'MatchRun', 'MatchJob',
        'Invitation', 'Selection', 'MatchingReviewAssignment',
        'CandidateSelectorAssignment', 'SelectionCompletionJob'
    )
);

SET LOCAL ROLE matching_schema_owner;

CREATE FUNCTION matching.reviewer_invitation_projection_v1(
    exact_invitation_id uuid
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
    SELECT jsonb_build_object(
        'invitation_id',invitation.id::text,
        'attempt_id',invitation.attempt_id::text,
        'match_run_id',invitation.match_run_id::text,
        'creator_user_id',invitation.creator_user_id::text,
        'status',invitation.status,
        'aggregate_version',invitation.aggregate_version,
        'updated_at',invitation.updated_at,
        'expires_at',invitation.expires_at,
        'snapshot_sha256',encode(invitation.snapshot_sha256,'hex')
    )
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id
$function$;

CREATE FUNCTION matching.reviewer_attempt_projection_v1(
    exact_attempt_id uuid
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
    SELECT jsonb_build_object(
        'attempt_id',attempt.id::text,
        'demand_id',attempt.demand_id::text,
        'attempt_no',attempt.attempt_no,
        'status',attempt.status,
        'aggregate_version',attempt.aggregate_version,
        'updated_at',attempt.updated_at
    )
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=exact_attempt_id
$function$;

-- Build the only disclosure surface accepted by CREATE_INVITATION from the
-- immutable Demand capture.  Public-name authority is intentionally absent
-- from the cross-context capture, so the label is a non-identifying stable
-- organization reference rather than an invented organization name.
CREATE FUNCTION matching.expected_invitation_disclosure_v1(
    exact_invitation_id uuid,
    exact_organization_id uuid,
    exact_attempt_id uuid,
    exact_demand_id uuid,
    exact_demand_version_id uuid,
    exact_profile_id uuid,
    exact_profile_version_id uuid,
    exact_expires_at timestamptz,
    exact_demand_content_sha256 bytea,
    exact_profile_content_sha256 bytea,
    exact_canonical_demand_version jsonb
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT jsonb_build_object(
        'schema_version',1,
        'canonicalization_version','invitation-disclosure-json-v1',
        'invitation_id',exact_invitation_id::text,
        'attempt_id',exact_attempt_id::text,
        'demand_id',exact_demand_id::text,
        'demand_version_id',exact_demand_version_id::text,
        'profile_id',exact_profile_id::text,
        'profile_version_id',exact_profile_version_id::text,
        'organization_preview',jsonb_build_object(
            'organization_id',exact_organization_id::text,
            'display_label','Organization '
                || substr(replace(exact_organization_id::text,'-',''),1,12)
        ),
        'opportunity',jsonb_build_object(
            'title',left(COALESCE(
                exact_canonical_demand_version->'content'->'problem'
                    ->'desired_outcomes'->>0,
                exact_canonical_demand_version->'content'->'problem'
                    ->>'domain_code'
            ),120),
            'problem_summary',left(
                exact_canonical_demand_version->'content'->'problem'
                    ->>'background',500
            ),
            'deliverable_summaries',COALESCE((
                SELECT jsonb_agg(left(item.value->>'description',500)
                    ORDER BY item.ordinality)
                FROM jsonb_array_elements(
                    exact_canonical_demand_version->'content'->'scope'
                        ->'deliverables'
                ) WITH ORDINALITY AS item(value,ordinality)
            ),'[]'::jsonb),
            'acceptance_summaries',COALESCE((
                SELECT jsonb_agg(left(item.value->>'description',500)
                    ORDER BY item.ordinality)
                FROM jsonb_array_elements(
                    exact_canonical_demand_version->'content'->'acceptance'
                        ->'criteria'
                ) WITH ORDINALITY AS item(value,ordinality)
            ),'[]'::jsonb)
        ),
        'offer',jsonb_build_object(
            'currency',exact_canonical_demand_version->'content'->'budget'
                ->>'currency',
            'minimum_amount_minor',(
                exact_canonical_demand_version->'content'->'budget'
                    ->>'minimum_amount_minor'
            )::bigint,
            'maximum_amount_minor',(
                exact_canonical_demand_version->'content'->'budget'
                    ->>'maximum_amount_minor'
            )::bigint,
            'schedule_code','SCHEDULE.' || (
                exact_canonical_demand_version->'content'->'collaboration'
                    ->>'work_mode'
            ),
            'duration_weeks',(
                exact_canonical_demand_version->'content'->'schedule'
                    ->>'duration_weeks'
            )::integer
        ),
        'constraints',jsonb_build_object(
            'region_codes',COALESCE((
                SELECT jsonb_agg('REGION.' || upper(item.value)
                    ORDER BY item.value COLLATE "C")
                FROM jsonb_array_elements_text(
                    exact_canonical_demand_version->'content'->'location'
                        ->'allowed_creator_region_codes'
                ) AS item(value)
            ),'[]'::jsonb),
            'language_codes',COALESCE((
                SELECT jsonb_agg('LANGUAGE.' || upper(item.value)
                    ORDER BY item.value COLLATE "C")
                FROM jsonb_array_elements_text(
                    exact_canonical_demand_version->'content'
                        ->'collaboration'->'languages'
                ) AS item(value)
            ),'[]'::jsonb),
            'data_sensitivity_code',
                exact_canonical_demand_version->'content'->'risk'
                    ->>'data_sensitivity',
            'ai_use_code',CASE
                WHEN (exact_canonical_demand_version->'content'->'ai'
                        ->>'required')::boolean THEN 'REQUIRED'
                WHEN (exact_canonical_demand_version->'content'->'ai'
                        ->>'allowed')::boolean THEN 'OPTIONAL'
                ELSE 'PROHIBITED' END
        ),
        'expires_at',exact_expires_at,
        'demand_content_sha256',encode(exact_demand_content_sha256,'hex'),
        'profile_content_sha256',encode(exact_profile_content_sha256,'hex')
    )
$function$;

REVOKE ALL ON FUNCTION matching.reviewer_invitation_projection_v1(uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.reviewer_attempt_projection_v1(uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.expected_invitation_disclosure_v1(
    uuid,uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching.reviewer_invitation_projection_v1(uuid)
TO matching_review;
GRANT EXECUTE ON FUNCTION matching.reviewer_attempt_projection_v1(uuid)
TO matching_review;

CREATE FUNCTION matching_api.list_creator_invitations_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_limit integer,
    exact_cursor_updated_at timestamptz,
    exact_cursor_invitation_id uuid
)
RETURNS TABLE (
    safe_invitation jsonb,
    updated_at timestamptz,
    invitation_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    iam_authority record;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_creator'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_limit NOT BETWEEN 1 AND 101
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR (exact_cursor_updated_at IS NULL)
            <> (exact_cursor_invitation_id IS NULL)
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_CREATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_MATCHING_INVITATIONS'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR COALESCE(current_setting('app.organization_id', true), '') <> ''
       OR COALESCE(current_setting('app.invitation_id', true), '') <> ''
       OR COALESCE(current_setting('app.command_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT * INTO iam_authority
    FROM iam_api.resolve_matching_creator_authority_marker_v1(
        exact_actor_user_id,exact_session_id,
        'LIST_MATCHING_INVITATIONS',NULL,NULL
    );
    IF NOT FOUND
       OR iam_authority.actor_user_id <> exact_actor_user_id
       OR iam_authority.session_id <> exact_session_id
       OR iam_authority.operation_code <> 'LIST_MATCHING_INVITATIONS'
       OR iam_authority.role_code <> 'CREATOR'
       OR iam_authority.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR octet_length(iam_authority.evidence_sha256) <> 32
       OR iam_authority.valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    PERFORM set_config(
        'app.creator_authority_evidence_sha256',
        encode(iam_authority.evidence_sha256,'hex'),true
    );
    RETURN QUERY
    SELECT matching.recipient_invitation_projection_v1(invitation.id),
        invitation.updated_at,invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.status <> 'CREATED'
      AND (
        exact_cursor_updated_at IS NULL
        OR (invitation.updated_at,invitation.id)
            < (exact_cursor_updated_at,exact_cursor_invitation_id)
      )
    ORDER BY invitation.updated_at DESC,invitation.id DESC
    LIMIT exact_limit;
END
$function$;

CREATE FUNCTION matching_api.read_creator_invitation_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_invitation_id uuid
)
RETURNS TABLE (safe_invitation jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    iam_authority record;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_creator'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_invitation_id IS NULL
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_CREATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'READ_MATCHING_INVITATION'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR COALESCE(current_setting('app.organization_id', true), '') <> ''
       OR COALESCE(current_setting('app.command_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT * INTO iam_authority
    FROM iam_api.resolve_matching_creator_authority_marker_v1(
        exact_actor_user_id,exact_session_id,
        'READ_MATCHING_INVITATION',exact_invitation_id,NULL
    );
    IF NOT FOUND
       OR iam_authority.actor_user_id <> exact_actor_user_id
       OR iam_authority.session_id <> exact_session_id
       OR iam_authority.operation_code <> 'READ_MATCHING_INVITATION'
       OR iam_authority.role_code <> 'CREATOR'
       OR iam_authority.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR octet_length(iam_authority.evidence_sha256) <> 32
       OR iam_authority.valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    PERFORM set_config(
        'app.creator_authority_evidence_sha256',
        encode(iam_authority.evidence_sha256,'hex'),true
    );
    RETURN QUERY
    SELECT matching.recipient_invitation_projection_v1(invitation.id)
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id
      AND invitation.status <> 'CREATED';
END
$function$;

REVOKE ALL ON FUNCTION matching_api.list_creator_invitations_v1(
    uuid,uuid,bytea,integer,timestamptz,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION matching_api.read_creator_invitation_v1(
    uuid,uuid,bytea,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.list_creator_invitations_v1(
    uuid,uuid,bytea,integer,timestamptz,uuid
) TO matching_creator;
GRANT EXECUTE ON FUNCTION matching_api.read_creator_invitation_v1(
    uuid,uuid,bytea,uuid
) TO matching_creator;

-- v2 invitations carried a marker for a future Creator session.  v3 rows
-- deliberately do not: the exact immutable candidate capture identifies the
-- recipient and IAM46 proves the current authenticated Creator at response
-- time.  Keep the public v2 signature stable while replacing its body with a
-- dual-shape, fail-closed implementation.  Completed receipt recovery stays
-- ahead of the short-lived IAM evidence check so an exact retry can recover a
-- committed response after the evidence window has elapsed.
CREATE OR REPLACE FUNCTION matching_api.execute_creator_invitation_v1(
    exact_operation text,
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_invitation_id uuid,
    expected_invitation_version bigint,
    expected_snapshot_sha256 bytea,
    exact_reason_code text,
    exact_restricted_note text,
    expected_authority_marker_sha256 bytea,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_fact_id uuid,
    exact_audit_event_id uuid,
    exact_invitation_event_id uuid,
    exact_selection_event_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    target matching.invitations%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    new_invitation_status text;
    invitation_event_type text;
    new_invitation_version bigint;
    new_selection_version bigint;
    new_set_sha256 bytea;
    response_body jsonb;
    receipt_row record;
    iam_authority record;
    canonical_path text;
    iam_operation text;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_creator'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_operation NOT IN (
            'ACCEPT_INVITATION','DECLINE_INVITATION','WITHDRAW_INVITATION'
       )
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_invitation_id IS NULL
       OR expected_invitation_version < 1
       OR octet_length(expected_snapshot_sha256) <> 32
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR exact_restricted_note IS NOT NULL
            AND (length(exact_restricted_note) > 500
                OR exact_restricted_note ~ '[[:cntrl:]]')
       OR (exact_operation='ACCEPT_INVITATION'
            AND (exact_reason_code IS NOT NULL
                OR exact_restricted_note IS NOT NULL))
       OR (exact_operation IN ('DECLINE_INVITATION','WITHDRAW_INVITATION')
            AND (exact_reason_code IS NULL
                OR exact_reason_code !~ '^[A-Z][A-Z0-9_]{1,63}$'))
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_CREATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.selection_id', true), '') <> ''
       OR COALESCE(current_setting('app.demand_id', true), '') <> ''
       OR COALESCE(
            current_setting('app.selector_assignment_id', true), ''
       ) <> ''
    THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    canonical_path := '/v1/me/matching-invitations/'
        || exact_invitation_id::text || CASE exact_operation
            WHEN 'ACCEPT_INVITATION' THEN '/accept'
            WHEN 'DECLINE_INVITATION' THEN '/decline'
            ELSE '/withdraw' END;
    SELECT * INTO STRICT receipt_row
    FROM matching.claim_command_receipt_v1(
        exact_receipt_id,exact_actor_user_id,exact_organization_id,
        exact_operation,exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        expected_authority_marker_sha256,canonical_path,'Invitation',
        exact_invitation_id,expected_invitation_version
    );
    IF receipt_row.replayed THEN
        RETURN QUERY SELECT receipt_row.safe_response, true;
        RETURN;
    END IF;

    iam_operation := CASE exact_operation
        WHEN 'ACCEPT_INVITATION' THEN 'ACCEPT_MATCHING_INVITATION'
        WHEN 'DECLINE_INVITATION' THEN 'DECLINE_MATCHING_INVITATION'
        ELSE 'WITHDRAW_MATCHING_INVITATION' END;
    PERFORM set_config('app.organization_id','',true);
    PERFORM set_config('app.operation',iam_operation,true);
    SELECT * INTO iam_authority
    FROM iam_api.resolve_matching_creator_authority_marker_v1(
        exact_actor_user_id,exact_session_id,iam_operation,
        exact_invitation_id,exact_command_id
    );
    IF NOT FOUND
       OR iam_authority.actor_user_id <> exact_actor_user_id
       OR iam_authority.session_id <> exact_session_id
       OR iam_authority.operation_code <> iam_operation
       OR iam_authority.role_code <> 'CREATOR'
       OR iam_authority.authority_marker_sha256
            <> expected_authority_marker_sha256
       OR octet_length(iam_authority.evidence_sha256) <> 32
       OR iam_authority.valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    PERFORM set_config(
        'app.creator_authority_evidence_sha256',
        encode(iam_authority.evidence_sha256,'hex'),true
    );
    PERFORM set_config('app.organization_id',exact_organization_id::text,true);
    PERFORM set_config('app.operation',exact_operation,true);

    SELECT invitation.* INTO target
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',target.attempt_id::text,true);

    SELECT attempt.* INTO attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=target.attempt_id
    FOR SHARE;
    IF NOT FOUND OR attempt_row.selection_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM set_config('app.selection_id',attempt_row.selection_id::text,true);

    SELECT selection.* INTO selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
    FOR UPDATE;
    IF NOT FOUND OR selection_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING
            ERRCODE='P0001', MESSAGE=CASE
                WHEN exact_operation='WITHDRAW_INVITATION'
                THEN 'INVITATION_ALREADY_SELECTED'
                ELSE 'INVALID_STATE_TRANSITION' END;
    END IF;

    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=target.attempt_id
      AND invitation.match_run_id=target.match_run_id
    ORDER BY invitation.id
    FOR UPDATE;
    SELECT invitation.* INTO target
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id;

    IF target.aggregate_version <> expected_invitation_version
       OR target.snapshot_sha256 IS DISTINCT FROM expected_snapshot_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    IF target.organization_id <> exact_organization_id
       OR target.creator_user_id <> exact_actor_user_id
       OR NOT (
            (
                target.candidate_evidence_version_digest IS NULL
                AND target.creator_authority_marker_sha256
                    IS NOT DISTINCT FROM expected_authority_marker_sha256
            )
            OR
            (
                octet_length(target.candidate_evidence_version_digest)=32
                AND target.creator_authority_marker_sha256 IS NULL
            )
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;

    IF exact_operation IN ('ACCEPT_INVITATION','DECLINE_INVITATION') THEN
        IF target.status <> 'SENT'
           OR target.expires_at <= transaction_timestamp() THEN
            RAISE EXCEPTION USING
                ERRCODE='P0001', MESSAGE='INVALID_STATE_TRANSITION';
        END IF;
        new_invitation_status := CASE exact_operation
            WHEN 'ACCEPT_INVITATION' THEN 'ACCEPTED' ELSE 'DECLINED' END;
        invitation_event_type := CASE exact_operation
            WHEN 'ACCEPT_INVITATION' THEN 'InvitationAccepted'
            ELSE 'InvitationDeclined' END;
        INSERT INTO matching.invitation_responses (
            id,invitation_id,creator_user_id,response_kind,snapshot_sha256,
            reason_code,restricted_note,responded_at
        ) VALUES (
            exact_fact_id,target.id,target.creator_user_id,
            new_invitation_status,target.snapshot_sha256,exact_reason_code,
            exact_restricted_note,transaction_timestamp()
        );
    ELSE
        IF target.status <> 'ACCEPTED' THEN
            RAISE EXCEPTION USING
                ERRCODE='P0001', MESSAGE='INVALID_STATE_TRANSITION';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM matching.invitation_responses AS response
            WHERE response.invitation_id=target.id
              AND response.response_kind='ACCEPTED'
        ) OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE='P0001', MESSAGE='INVITATION_ALREADY_SELECTED';
        END IF;
        new_invitation_status := 'WITHDRAWN';
        invitation_event_type := 'InvitationWithdrawn';
        INSERT INTO matching.invitation_withdrawals (
            id,invitation_id,creator_user_id,snapshot_sha256,reason_code,
            restricted_note,withdrawn_at
        ) VALUES (
            exact_fact_id,target.id,target.creator_user_id,
            target.snapshot_sha256,exact_reason_code,exact_restricted_note,
            transaction_timestamp()
        );
    END IF;

    new_invitation_version := target.aggregate_version+1;
    UPDATE matching.invitations
    SET status=new_invitation_status,
        aggregate_version=new_invitation_version,
        responded_at=transaction_timestamp(),
        updated_at=transaction_timestamp()
    WHERE id=target.id;

    new_set_sha256 := matching.selection_invitation_set_sha256_v1(
        target.attempt_id,target.match_run_id
    );
    IF new_set_sha256 IS NULL
       OR new_set_sha256=selection_row.current_invitation_set_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    new_selection_version := selection_row.aggregate_version+1;
    UPDATE matching.selections
    SET aggregate_version=new_selection_version,
        current_invitation_set_sha256=new_set_sha256,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id;

    PERFORM matching.record_audit_v1(
        exact_audit_event_id,exact_actor_user_id,exact_operation,
        'Invitation',target.id,exact_organization_id,target.status,
        new_invitation_status,target.aggregate_version,new_invitation_version,
        exact_reason_code,exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('selection_id',selection_row.id::text,
            'selection_version',new_selection_version,
            'iam_evidence_sha256',encode(iam_authority.evidence_sha256,'hex'))
    );
    PERFORM matching.record_outbox_v1(
        exact_invitation_event_id,invitation_event_type,'Invitation',target.id,
        new_invitation_version,exact_actor_user_id,exact_organization_id,
        exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'invitation_id',target.id::text,'attempt_id',target.attempt_id::text,
            'run_id',target.match_run_id::text,
            'creator_user_id',target.creator_user_id::text,
            'profile_version_id',target.profile_version_id::text,
            'snapshot_sha256',encode(target.snapshot_sha256,'hex'),
            'status',new_invitation_status,'expires_at',target.expires_at,
            'reason_code',exact_reason_code)
    );
    PERFORM matching.record_outbox_v1(
        exact_selection_event_id,'SelectionInvitationSetChanged','Selection',
        selection_row.id,new_selection_version,exact_actor_user_id,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',selection_row.attempt_id::text,'status','OPEN',
            'current_invitation_set_sha256',encode(new_set_sha256,'hex'),
            'chosen_invitation_id',NULL,'selection_basis_code',NULL,
            'reason_code',NULL)
    );

    response_body := matching.recipient_invitation_projection_v1(target.id);
    IF response_body IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_invitation_version,
        new_invitation_status,ARRAY[
            invitation_event_type,'SelectionInvitationSetChanged'
        ]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.execute_creator_invitation_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,text,text,bytea,uuid,uuid,uuid,
    uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.execute_creator_invitation_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,text,text,bytea,uuid,uuid,uuid,
    uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) TO matching_creator;

CREATE FUNCTION matching.claim_operational_receipt_v1(
    exact_receipt_id uuid,
    exact_principal_kind text,
    exact_principal_id uuid,
    exact_organization_id uuid,
    exact_operation text,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_authority_marker_sha256 bytea,
    exact_canonical_path text,
    exact_target_kind text,
    exact_target_id uuid,
    exact_if_match_version bigint
)
RETURNS TABLE (safe_response jsonb, replayed boolean, claimed boolean)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    existing matching.command_receipts%ROWTYPE;
BEGIN
    IF exact_principal_kind NOT IN ('USER', 'SYSTEM')
       OR exact_principal_id IS NULL
       OR exact_organization_id IS NULL
       OR length(exact_operation) NOT BETWEEN 2 AND 64
       OR length(exact_identity_key_id) NOT BETWEEN 1 AND 128
       OR octet_length(exact_identity_digest) <> 32
       OR length(exact_payload_hash_key_id) NOT BETWEEN 1 AND 128
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR octet_length(exact_payload_hash) <> 32
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR left(exact_canonical_path, 4) <> '/v1/'
       OR length(exact_target_kind) NOT BETWEEN 2 AND 64
       OR exact_target_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SELECT receipt.* INTO existing
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind = exact_principal_kind
      AND receipt.principal_id = exact_principal_id
      AND receipt.organization_id = exact_organization_id
      AND receipt.operation = exact_operation
      AND receipt.command_version = 1
      AND receipt.identity_key_id = exact_identity_key_id
      AND receipt.identity_digest = exact_identity_digest
    FOR UPDATE;
    IF FOUND THEN
        IF existing.payload_hash_key_id IS DISTINCT FROM exact_payload_hash_key_id
           OR existing.payload_hash IS DISTINCT FROM exact_payload_hash
           OR existing.principal_authority_marker_sha256
                IS DISTINCT FROM exact_authority_marker_sha256
           OR existing.canonical_path IS DISTINCT FROM exact_canonical_path
           OR existing.target_kind IS DISTINCT FROM exact_target_kind
           OR existing.target_id IS DISTINCT FROM exact_target_id
           OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
        THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.safe_response_body IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SERVICE_UNAVAILABLE';
        END IF;
        RETURN QUERY SELECT existing.safe_response_body, true, false;
        RETURN;
    END IF;

    INSERT INTO matching.command_receipts (
        id,principal_kind,principal_id,organization_id,operation,
        command_version,canonicalization_version,identity_key_id,
        identity_digest,payload_hash_key_id,payload_hash,
        principal_authority_marker_sha256,http_method,canonical_path,
        target_kind,target_id,parent_kind,parent_id,if_match_version,status,
        response_http_status,response_schema_name,response_schema_version,
        response_entity_tag,safe_response_body,target_version,result_status,
        event_types,retain_until,created_at,completed_at
    ) VALUES (
        exact_receipt_id,exact_principal_kind,exact_principal_id,
        exact_organization_id,exact_operation,1,'matching-command-json-v1',
        exact_identity_key_id,exact_identity_digest,exact_payload_hash_key_id,
        exact_payload_hash,exact_authority_marker_sha256,'POST',
        exact_canonical_path,exact_target_kind,exact_target_id,NULL,NULL,
        exact_if_match_version,'IN_PROGRESS',NULL,NULL,NULL,NULL,NULL,NULL,
        NULL,NULL,transaction_timestamp()+interval '30 days',
        transaction_timestamp(),NULL
    ) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    RETURN QUERY SELECT NULL::jsonb, false, true;
END
$function$;

CREATE FUNCTION matching.record_operational_audit_v1(
    exact_event_id uuid,
    exact_actor_kind text,
    exact_actor_id uuid,
    exact_original_actor_id uuid,
    exact_action_code text,
    exact_target_kind text,
    exact_target_id uuid,
    exact_organization_id uuid,
    exact_before_status text,
    exact_after_status text,
    exact_before_version bigint,
    exact_after_version bigint,
    exact_reason_code text,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_safe_attributes jsonb
)
RETURNS void
LANGUAGE sql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, audit
AS $function$
    INSERT INTO audit.audit_events (
        event_id,occurred_at,actor_kind,actor_id,original_actor_id,
        action_code,target_kind,target_id,organization_id,before_status,
        after_status,before_version,after_version,role_code,purpose_code,
        reason_code,auth_strength_code,result_code,command_id,correlation_id,
        causation_id,trace_id,safe_attributes
    ) VALUES (
        exact_event_id,transaction_timestamp(),exact_actor_kind,exact_actor_id,
        exact_original_actor_id,exact_action_code,exact_target_kind,
        exact_target_id,exact_organization_id,exact_before_status,
        exact_after_status,exact_before_version,exact_after_version,NULL,NULL,
        exact_reason_code,NULL,'SUCCEEDED',exact_command_id,
        exact_correlation_id,exact_command_id,exact_trace_id,
        exact_safe_attributes
    )
$function$;

CREATE FUNCTION matching.record_operational_outbox_v1(
    exact_event_id uuid,
    exact_event_type text,
    exact_aggregate_type text,
    exact_aggregate_id uuid,
    exact_aggregate_version bigint,
    exact_actor_kind text,
    exact_actor_id uuid,
    exact_original_actor_id uuid,
    exact_organization_id uuid,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_payload jsonb
)
RETURNS void
LANGUAGE sql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, infra
AS $function$
    INSERT INTO infra.outbox_events (
        event_id,event_type,schema_version,occurred_at,aggregate_type,
        aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,
        correlation_id,causation_id,trace_id,organization_id,payload,
        delivery_status,attempt_count,available_at,lease_owner,lease_until,
        published_at,last_error_code,created_at
    ) VALUES (
        exact_event_id,exact_event_type,1,transaction_timestamp(),
        exact_aggregate_type,exact_aggregate_id,exact_aggregate_version,
        exact_actor_kind,exact_actor_id,exact_original_actor_id,
        exact_correlation_id,exact_command_id,exact_trace_id,
        exact_organization_id,exact_payload,'PENDING',0,
        transaction_timestamp(),NULL,NULL,NULL,NULL,transaction_timestamp()
    )
$function$;

REVOKE ALL ON FUNCTION matching.claim_operational_receipt_v1(
    uuid,text,uuid,uuid,text,text,bytea,text,bytea,bytea,text,text,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.record_operational_audit_v1(
    uuid,text,uuid,uuid,text,text,uuid,uuid,text,text,bigint,bigint,text,
    uuid,uuid,uuid,jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.record_operational_outbox_v1(
    uuid,text,text,uuid,bigint,text,uuid,uuid,uuid,uuid,uuid,uuid,jsonb
) FROM PUBLIC;

CREATE FUNCTION matching.assert_operational_context_v1(
    exact_session_user text,
    exact_scope_kind text,
    exact_operation text,
    exact_principal_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_command_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM exact_session_user
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_principal_id IS NULL
       OR exact_organization_id IS NULL
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR exact_command_id IS NULL
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM exact_scope_kind
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting(
            CASE WHEN exact_session_user IN (
                'matching_assignment', 'matching_review'
            ) THEN 'app.actor_user_id' ELSE 'app.workload_id' END,
            true
          ), '') IS DISTINCT FROM exact_principal_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_authority_marker_sha256, 'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION matching.assert_operational_context_v1(
    text,text,text,uuid,uuid,bytea,uuid
) FROM PUBLIC;

CREATE FUNCTION matching_api.claim_candidate_selector_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    expected_principal_marker_sha256 bytea,
    exact_assignment_id uuid,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    resolved record;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    existing_assignment matching.candidate_selector_assignments%ROWTYPE;
    recorded_time timestamptz := transaction_timestamp();
    response_body jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_assignment'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_demand_id IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR exact_assignment_id IS NULL OR exact_receipt_id IS NULL
       OR exact_command_id IS NULL
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_ASSIGNMENT'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'OPT_IN_CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_principal_marker_sha256,'hex')
       OR COALESCE(current_setting('app.selection_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    -- Completed receipt recovery precedes every mutable target and expiring
    -- IAM check.  The demand is the stable idempotency target; assignment ids
    -- are server allocated only for a newly claimed command.
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'USER',exact_actor_user_id,exact_organization_id,
        'OPT_IN_CANDIDATE_SELECTOR',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        expected_principal_marker_sha256,
        '/v1/matching/candidate-selector-assignments/claim',
        'Demand',exact_demand_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;

    -- Resolve exactly one current OPEN demand-scoped target under lock.  The
    -- browser never supplies a Selection or assignee identifier.
    BEGIN
        SELECT attempt.* INTO STRICT attempt_row
        FROM matching.matching_attempts AS attempt
        WHERE attempt.organization_id=exact_organization_id
          AND attempt.demand_id=exact_demand_id
          AND attempt.status='OPEN'
          AND attempt.selection_id IS NOT NULL
        FOR UPDATE;
        PERFORM set_config('app.selection_id',attempt_row.selection_id::text,true);
        SELECT selection.* INTO STRICT selection_row
        FROM matching.selections AS selection
        WHERE selection.id=attempt_row.selection_id
          AND selection.attempt_id=attempt_row.id
          AND selection.organization_id=exact_organization_id
          AND selection.status='OPEN'
        FOR UPDATE;
    EXCEPTION WHEN no_data_found THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    WHEN too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END;
    PERFORM set_config('app.selection_id',selection_row.id::text,true);

    -- A recorded decision is durable coordinator work.  Never expire its
    -- authority and hand the same still-open Selection to a second actor.
    IF EXISTS (
        SELECT 1 FROM matching.selection_intents AS intent
        WHERE intent.selection_id=selection_row.id
    ) OR EXISTS (
        SELECT 1 FROM matching.selection_close_intents AS close_intent
        WHERE close_intent.selection_id=selection_row.id
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='SELECTION_DECISION_PENDING';
    END IF;

    -- IAM44 returns the ordinary EditorPrincipal session marker for v2 route
    -- compatibility, plus a separate evidence digest bound to this opt-in.
    SELECT * INTO STRICT resolved
    FROM iam_api.resolve_candidate_selector_opt_in_marker_v1(
        exact_actor_user_id,exact_session_id,exact_organization_id,
        selection_row.id,exact_demand_id,exact_command_id
    );
    IF resolved.actor_user_id IS DISTINCT FROM exact_actor_user_id
       OR resolved.session_id IS DISTINCT FROM exact_session_id
       OR resolved.organization_id IS DISTINCT FROM exact_organization_id
       OR resolved.selection_id IS DISTINCT FROM selection_row.id
       OR resolved.demand_id IS DISTINCT FROM exact_demand_id
       OR resolved.role_code IS DISTINCT FROM 'CANDIDATE_SELECTOR'
       OR octet_length(resolved.authority_marker_sha256) <> 32
       OR octet_length(resolved.evidence_sha256) <> 32
       OR resolved.authority_marker_sha256
            IS DISTINCT FROM expected_principal_marker_sha256
       OR resolved.valid_until <= recorded_time THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    PERFORM set_config(
        'app.authority_marker_sha256',
        encode(resolved.authority_marker_sha256,'hex'),true
    );

    SELECT assignment.* INTO existing_assignment
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.selection_id=selection_row.id
      AND assignment.status='ACTIVE'
    FOR UPDATE;
    IF FOUND AND existing_assignment.expires_at<=recorded_time THEN
        UPDATE matching.candidate_selector_assignments
        SET status='EXPIRED',assignment_version=assignment_version+1,
            completed_at=recorded_time
        WHERE id=existing_assignment.id AND status='ACTIVE';
        existing_assignment.id := NULL;
    END IF;
    IF existing_assignment.id IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='CANDIDATE_SELECTOR_ALREADY_ASSIGNED';
    END IF;

    INSERT INTO matching.candidate_selector_opt_in_receipts (
        id,command_id,actor_user_id,session_id,organization_id,selection_id,
        demand_id,role_code,authority_marker_sha256,iam_evidence_sha256,
        valid_until,recorded_at
    ) VALUES (
        exact_receipt_id,exact_command_id,exact_actor_user_id,exact_session_id,
        exact_organization_id,selection_row.id,exact_demand_id,
        'CANDIDATE_SELECTOR',resolved.authority_marker_sha256,
        resolved.evidence_sha256,resolved.valid_until,recorded_time
    );
    INSERT INTO matching.candidate_selector_assignments (
        id,assignment_version,status,assignee_user_id,organization_id,
        demand_id,selection_id,authority_marker_sha256,assigned_at,
        expires_at,completed_at,assignee_session_id,opt_in_receipt_id
    ) VALUES (
        exact_assignment_id,1,'ACTIVE',exact_actor_user_id,
        exact_organization_id,exact_demand_id,selection_row.id,
        resolved.authority_marker_sha256,recorded_time,resolved.valid_until,
        NULL,exact_session_id,exact_receipt_id
    );
    PERFORM set_config(
        'app.selector_assignment_id',exact_assignment_id::text,true
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'USER',exact_actor_user_id,NULL,
        'OPT_IN_CANDIDATE_SELECTOR','CandidateSelectorAssignment',
        exact_assignment_id,exact_organization_id,NULL,'ACTIVE',NULL,1,NULL,
        exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('selection_id',selection_row.id::text,
            'demand_id',exact_demand_id::text,
            'opt_in_receipt_id',exact_receipt_id::text,
            'session_bound',true)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'CandidateSelectorAssigned',
        'CandidateSelectorAssignment',exact_assignment_id,1,'USER',
        exact_actor_user_id,NULL,exact_organization_id,exact_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('assignment_id',exact_assignment_id::text,
            'selection_id',selection_row.id::text,
            'demand_id',exact_demand_id::text,'status','ACTIVE')
    );
    response_body := jsonb_build_object(
        'candidate_selector_assignment_id',exact_assignment_id::text,
        'candidate_selector_assignment_version',1,
        'selection_id',selection_row.id::text,
        'attempt_id',attempt_row.id::text,
        'demand_id',exact_demand_id::text,
        'status','ACTIVE','expires_at',resolved.valid_until,
        'selection_status',selection_row.status,
        'selection_version',selection_row.aggregate_version,
        'current_invitation_set_sha256',
            encode(selection_row.current_invitation_set_sha256,'hex')
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,1,'ACTIVE',
        ARRAY['CandidateSelectorAssigned']::text[]
    );
    RETURN QUERY SELECT response_body, false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.claim_candidate_selector_v1(
    uuid,uuid,uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,
    uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.claim_candidate_selector_v1(
    uuid,uuid,uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,
    uuid,uuid,uuid,uuid
) TO matching_assignment;

CREATE FUNCTION matching_api.publish_rule_bundle_v1(
    exact_workload_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_canonical_manifest_bytes bytea,
    exact_manifest jsonb,
    exact_canonical_manifest_sha256 bytea,
    exact_signature_key_id text,
    exact_review_approval_id uuid,
    exact_review_approval_version bigint,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    bundle_id uuid;
    parsed_selector_digest bytea;
    effective_time timestamptz;
    effective_until_time timestamptz;
    parsed_engine_artifact_sha256 bytea;
    response_body jsonb;
    previous matching.rule_bundles%ROWTYPE;
    backfilled_legacy_v2 boolean := false;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_worker','MATCHING_WORKER','PUBLISH_MATCHING_RULE',
        exact_workload_id,exact_organization_id,
        exact_authority_marker_sha256,exact_command_id
    );
    IF jsonb_typeof(exact_manifest) <> 'object'
       OR octet_length(exact_canonical_manifest_bytes) NOT BETWEEN 1 AND 262144
       OR octet_length(exact_canonical_manifest_sha256) <> 32
       OR sha256(exact_canonical_manifest_bytes)
            IS DISTINCT FROM exact_canonical_manifest_sha256
       OR length(exact_signature_key_id) NOT BETWEEN 1 AND 128
       OR exact_review_approval_id IS NULL
       OR exact_review_approval_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    BEGIN
        bundle_id := (exact_manifest->>'bundle_id')::uuid;
        parsed_selector_digest := decode(
            exact_manifest->>'selector_digest','hex'
        );
        parsed_engine_artifact_sha256 := decode(
            exact_manifest->>'engine_artifact_sha256','hex'
        );
        effective_time := (exact_manifest->>'effective_at')::timestamptz;
        effective_until_time := NULLIF(
            exact_manifest->>'effective_until',''
        )::timestamptz;
        IF convert_from(exact_canonical_manifest_bytes,'UTF8')::jsonb
                IS DISTINCT FROM exact_manifest THEN
            RAISE EXCEPTION USING ERRCODE='22023',
                MESSAGE='INVALID_REQUEST';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END;
    -- v1 is deliberately a fixed reviewed bootstrap program.  A new rule
    -- release or engine artifact requires a forward migration; the worker is
    -- not a rule-authoring authority.  Signature/approval evidence is stored
    -- separately and can never be smuggled into the closed engine document.
    IF bundle_id IS DISTINCT FROM
            '53000000-0000-4000-8000-000000000001'::uuid
       OR parsed_selector_digest IS DISTINCT FROM decode(
            '3bd2f51daac99e67e0da34eb15134ab3cc3a786c994899c5246fe33689179ead',
            'hex'
       )
       OR exact_canonical_manifest_sha256 IS DISTINCT FROM decode(
            '7955850bf01a142cb555a82f5da8ad519beaf3e93277aad2c791e791e35838d2',
            'hex'
       )
       OR parsed_engine_artifact_sha256 IS DISTINCT FROM decode(
            'f00ca4864a86a90bec51e9f93e61da75c86016213942d416c604fcfe5fe6c79e',
            'hex'
       )
       OR (exact_manifest->>'schema_version')::integer <> 1
       OR (exact_manifest->>'canonicalization_version')
            IS DISTINCT FROM 'matching-rule-release-json-v1'
       OR (exact_manifest->>'engine_identifier')
            IS DISTINCT FROM 'deterministic-matcher-v1'
       OR (exact_manifest->>'engine_major')::integer <> 1
       OR (exact_manifest->>'invitation_limit')::integer <> 10
       OR effective_time IS NULL
       OR (exact_manifest->>'taxonomy_bundle_id')::uuid IS DISTINCT FROM
            '50000000-0000-4000-8000-000000000001'::uuid THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    -- The read policy exposes only this fixed release identifier.  Set the
    -- target before claiming the receipt so every same-ID legacy shape is
    -- visible for a deterministic closed comparison, even when its old
    -- publisher fields, selector, or status differ from the current request.
    PERFORM set_config('app.rule_bundle_id',bundle_id::text,true);

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,exact_organization_id,
        'PUBLISH_MATCHING_RULE',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/rule-bundles/publish',
        'MatchingRule',bundle_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;
    IF effective_time > transaction_timestamp()
       OR (effective_until_time IS NOT NULL
            AND effective_until_time <= transaction_timestamp()) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SELECT bundle.* INTO previous
    FROM matching.rule_bundles AS bundle
    WHERE bundle.id=bundle_id;
    IF FOUND THEN
        -- FOR UPDATE also requires an UPDATE policy.  The plain exact-ID read
        -- intentionally detects legacy publisher drift that the operational
        -- UPDATE policy will not expose; only an exact publisher can advance
        -- to the row lock and possible three-column completion below.
        IF previous.published_by_workload_id IS DISTINCT FROM
                exact_workload_id
           OR previous.published_authority_marker_sha256 IS DISTINCT FROM
                exact_authority_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
        END IF;
        SELECT bundle.* INTO previous
        FROM matching.rule_bundles AS bundle
        WHERE bundle.id=bundle_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
        END IF;
        IF previous.status IS DISTINCT FROM 'ACTIVE'
           OR previous.selector_digest IS DISTINCT FROM
                parsed_selector_digest THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
        END IF;
        -- A v2 installation can already contain the packaged bundle UUID and
        -- digest while lacking only the three v3 release-document columns.
        -- Complete that row in place only when every pre-v3 immutable field is
        -- exactly the reviewed release supplied by this fixed program.  A
        -- partial shape or any mismatch remains a closed rejection.
        IF previous.canonical_manifest_bytes IS NULL
           AND previous.manifest IS NULL
           AND previous.invitation_limit IS NULL THEN
            IF previous.semantic_version IS DISTINCT FROM
                    exact_manifest->>'semantic_version'
               OR previous.jurisdiction_code IS DISTINCT FROM
                    exact_manifest->>'jurisdiction_code'
               OR previous.locale IS DISTINCT FROM exact_manifest->>'locale'
               OR previous.demand_type_code IS DISTINCT FROM
                    exact_manifest->>'demand_type_code'
               OR previous.taxonomy_family_code IS DISTINCT FROM
                    exact_manifest->>'taxonomy_family_code'
               OR previous.engine_identifier IS DISTINCT FROM
                    'deterministic-matcher-v1'
               OR previous.engine_major IS DISTINCT FROM 1
               OR previous.engine_artifact_sha256 IS DISTINCT FROM
                    parsed_engine_artifact_sha256
               OR previous.taxonomy_bundle_id IS DISTINCT FROM
                    (exact_manifest->>'taxonomy_bundle_id')::uuid
               OR previous.budget_rule_version IS DISTINCT FROM
                    exact_manifest->>'budget_rule_version'
               OR previous.matching_rule_version IS DISTINCT FROM
                    exact_manifest->>'matching_rule_version'
               OR previous.reason_code_version IS DISTINCT FROM
                    exact_manifest->>'reason_code_version'
               OR previous.explanation_template_version IS DISTINCT FROM
                    exact_manifest->>'explanation_template_version'
               OR previous.canonical_manifest_sha256 IS DISTINCT FROM
                    exact_canonical_manifest_sha256
               OR previous.signature_key_id IS DISTINCT FROM
                    exact_signature_key_id
               OR previous.review_approval_id IS DISTINCT FROM
                    exact_review_approval_id
               OR previous.review_approval_version IS DISTINCT FROM
                    exact_review_approval_version
               OR previous.effective_at IS DISTINCT FROM effective_time
               OR previous.effective_until IS DISTINCT FROM
                    effective_until_time
               OR previous.published_by_workload_id IS DISTINCT FROM
                    exact_workload_id
               OR previous.published_authority_marker_sha256 IS DISTINCT FROM
                    exact_authority_marker_sha256 THEN
                RAISE EXCEPTION USING ERRCODE='P0001',
                    MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
            END IF;
            UPDATE matching.rule_bundles
            SET canonical_manifest_bytes=exact_canonical_manifest_bytes,
                manifest=exact_manifest,
                invitation_limit=(exact_manifest->>'invitation_limit')::integer
            WHERE id=previous.id
              AND canonical_manifest_bytes IS NULL
              AND manifest IS NULL
              AND invitation_limit IS NULL;
            previous.canonical_manifest_bytes := exact_canonical_manifest_bytes;
            previous.manifest := exact_manifest;
            previous.invitation_limit :=
                (exact_manifest->>'invitation_limit')::integer;
            backfilled_legacy_v2 := true;
        END IF;
        IF previous.canonical_manifest_sha256 IS DISTINCT FROM
                exact_canonical_manifest_sha256
           OR previous.canonical_manifest_bytes IS DISTINCT FROM
                exact_canonical_manifest_bytes
           OR previous.manifest IS DISTINCT FROM exact_manifest
           OR previous.engine_artifact_sha256 IS DISTINCT FROM
                parsed_engine_artifact_sha256
           OR previous.invitation_limit IS DISTINCT FROM
                (exact_manifest->>'invitation_limit')::integer
           OR previous.effective_at IS DISTINCT FROM effective_time
           OR previous.effective_until IS DISTINCT FROM effective_until_time
           OR previous.signature_key_id IS DISTINCT FROM exact_signature_key_id
           OR previous.review_approval_id IS DISTINCT FROM
                exact_review_approval_id
           OR previous.review_approval_version IS DISTINCT FROM
                exact_review_approval_version
           OR previous.semantic_version IS DISTINCT FROM
                exact_manifest->>'semantic_version'
           OR previous.jurisdiction_code IS DISTINCT FROM
                exact_manifest->>'jurisdiction_code'
           OR previous.locale IS DISTINCT FROM exact_manifest->>'locale'
           OR previous.demand_type_code IS DISTINCT FROM
                exact_manifest->>'demand_type_code'
           OR previous.taxonomy_family_code IS DISTINCT FROM
                exact_manifest->>'taxonomy_family_code'
           OR previous.engine_identifier IS DISTINCT FROM
                'deterministic-matcher-v1'
           OR previous.engine_major IS DISTINCT FROM 1
           OR previous.taxonomy_bundle_id IS DISTINCT FROM
                (exact_manifest->>'taxonomy_bundle_id')::uuid
           OR previous.budget_rule_version IS DISTINCT FROM
                exact_manifest->>'budget_rule_version'
           OR previous.matching_rule_version IS DISTINCT FROM
                exact_manifest->>'matching_rule_version'
           OR previous.reason_code_version IS DISTINCT FROM
                exact_manifest->>'reason_code_version'
           OR previous.explanation_template_version IS DISTINCT FROM
                exact_manifest->>'explanation_template_version'
           OR previous.published_by_workload_id IS DISTINCT FROM
                exact_workload_id
           OR previous.published_authority_marker_sha256 IS DISTINCT FROM
                exact_authority_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
        END IF;
        response_body := jsonb_build_object(
            'rule_bundle_id',bundle_id::text,'status','ACTIVE',
            'selector_digest',encode(parsed_selector_digest,'hex'),
            'canonical_manifest_sha256',
                encode(exact_canonical_manifest_sha256,'hex'),
            'engine_artifact_sha256',
                encode(parsed_engine_artifact_sha256,'hex'),
            'invitation_limit',
                (exact_manifest->>'invitation_limit')::integer
        );
        PERFORM matching.record_operational_audit_v1(
            exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
            'PUBLISH_MATCHING_RULE','MatchingRule',bundle_id,
            exact_organization_id,'ACTIVE','ACTIVE',
            previous.review_approval_version,
            exact_review_approval_version,NULL,
            exact_command_id,exact_correlation_id,exact_trace_id,
            jsonb_build_object(
                'selector_digest',encode(parsed_selector_digest,'hex'),
                'already_active',true,
                'legacy_v2_release_backfilled',backfilled_legacy_v2
            )
        );
        PERFORM matching.record_operational_outbox_v1(
            exact_outbox_event_id,'MatchingRulePublished','MatchingRule',
            bundle_id,exact_review_approval_version,'SYSTEM',
            exact_workload_id,NULL,exact_organization_id,exact_command_id,
            exact_correlation_id,exact_trace_id,
            jsonb_build_object('rule_bundle_id',bundle_id::text,
                'selector_digest',encode(parsed_selector_digest,'hex'),
                'status','ACTIVE','already_active',true)
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,
            exact_review_approval_version,'ACTIVE',
            ARRAY['MatchingRulePublished']::text[]
        );
        RETURN QUERY SELECT response_body, false;
        RETURN;
    END IF;

    SELECT bundle.* INTO previous
    FROM matching.rule_bundles AS bundle
    WHERE bundle.selector_digest=parsed_selector_digest
      AND bundle.status='ACTIVE'
    FOR UPDATE;
    IF FOUND THEN
        UPDATE matching.rule_bundles
        SET status='SUPERSEDED',effective_until=transaction_timestamp(),
            updated_at=transaction_timestamp()
        WHERE id=previous.id;
    END IF;

    INSERT INTO matching.rule_bundles (
        id,semantic_version,status,selector_digest,jurisdiction_code,locale,
        demand_type_code,taxonomy_family_code,engine_identifier,engine_major,
        engine_artifact_sha256,taxonomy_bundle_id,budget_rule_version,
        matching_rule_version,reason_code_version,
        explanation_template_version,canonical_manifest_sha256,
        canonical_manifest_bytes,manifest,invitation_limit,
        signature_key_id,review_approval_id,review_approval_version,
        effective_at,effective_until,published_by_workload_id,
        published_authority_marker_sha256,created_at,updated_at
    ) VALUES (
        bundle_id,exact_manifest->>'semantic_version','ACTIVE',
        parsed_selector_digest,
        exact_manifest->>'jurisdiction_code',exact_manifest->>'locale',
        exact_manifest->>'demand_type_code',
        exact_manifest->>'taxonomy_family_code','deterministic-matcher-v1',1,
        parsed_engine_artifact_sha256,
        (exact_manifest->>'taxonomy_bundle_id')::uuid,
        exact_manifest->>'budget_rule_version',
        exact_manifest->>'matching_rule_version',
        exact_manifest->>'reason_code_version',
        exact_manifest->>'explanation_template_version',
        exact_canonical_manifest_sha256,exact_canonical_manifest_bytes,
        exact_manifest,(exact_manifest->>'invitation_limit')::integer,
        exact_signature_key_id,
        exact_review_approval_id,
        exact_review_approval_version,
        effective_time,effective_until_time,exact_workload_id,
        exact_authority_marker_sha256,transaction_timestamp(),
        transaction_timestamp()
    );
    INSERT INTO matching.rule_selectors (
        selector_digest,current_bundle_id,aggregate_version,updated_at
    ) VALUES (parsed_selector_digest,bundle_id,1,transaction_timestamp())
    ON CONFLICT (selector_digest) DO UPDATE
    SET current_bundle_id=EXCLUDED.current_bundle_id,
        aggregate_version=matching.rule_selectors.aggregate_version+1,
        updated_at=transaction_timestamp();

    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'PUBLISH_MATCHING_RULE','MatchingRule',bundle_id,
        exact_organization_id,COALESCE(previous.status,'MISSING'),'ACTIVE',
        CASE WHEN previous.id IS NULL THEN NULL ELSE previous.review_approval_version END,
        exact_review_approval_version,NULL,
        exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'selector_digest',encode(parsed_selector_digest,'hex')
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'MatchingRulePublished','MatchingRule',bundle_id,
        exact_review_approval_version,'SYSTEM',
        exact_workload_id,NULL,exact_organization_id,exact_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('rule_bundle_id',bundle_id::text,
            'selector_digest',encode(parsed_selector_digest,'hex'),
            'status','ACTIVE')
    );
    response_body := jsonb_build_object(
        'rule_bundle_id',bundle_id::text,'status','ACTIVE',
        'selector_digest',encode(parsed_selector_digest,'hex'),
        'canonical_manifest_sha256',
            encode(exact_canonical_manifest_sha256,'hex'),
        'engine_artifact_sha256',
            encode(parsed_engine_artifact_sha256,'hex'),
        'invitation_limit',(exact_manifest->>'invitation_limit')::integer
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,
        exact_review_approval_version,'ACTIVE',
        ARRAY['MatchingRulePublished']::text[]
    );
    RETURN QUERY SELECT response_body, false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.publish_rule_bundle_v1(
    uuid,uuid,bytea,bytea,jsonb,bytea,text,uuid,bigint,uuid,uuid,text,bytea,
    text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.publish_rule_bundle_v1(
    uuid,uuid,bytea,bytea,jsonb,bytea,text,uuid,bigint,uuid,uuid,text,bytea,
    text,bytea,uuid,uuid,uuid,uuid
) TO matching_worker;

CREATE FUNCTION matching_api.read_rule_bundle_for_match_v1(
    exact_workload_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_rule_bundle_id uuid,
    exact_selector_digest bytea
)
RETURNS TABLE (
    rule_bundle_id uuid,
    selector_digest bytea,
    canonical_manifest_bytes bytea,
    manifest jsonb,
    canonical_manifest_sha256 bytea,
    engine_identifier varchar,
    engine_artifact_sha256 bytea,
    invitation_limit integer,
    effective_at timestamptz,
    effective_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'matching_worker'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_rule_bundle_id IS NULL
       OR octet_length(exact_selector_digest) <> 32
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_WORKER'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'READ_MATCHING_RULE'
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM exact_workload_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.rule_bundle_id', true), '')
            IS DISTINCT FROM exact_rule_bundle_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    RETURN QUERY
    SELECT bundle.id,bundle.selector_digest,bundle.canonical_manifest_bytes,
        bundle.manifest,bundle.canonical_manifest_sha256,
        bundle.engine_identifier,bundle.engine_artifact_sha256,
        bundle.invitation_limit,bundle.effective_at,bundle.effective_until
    FROM matching.rule_bundles AS bundle
    WHERE bundle.id=exact_rule_bundle_id
      AND bundle.selector_digest=exact_selector_digest
      AND bundle.status='ACTIVE'
      AND bundle.effective_at <= transaction_timestamp()
      AND (bundle.effective_until IS NULL
           OR bundle.effective_until > transaction_timestamp())
      AND bundle.canonical_manifest_bytes IS NOT NULL
      AND bundle.manifest IS NOT NULL
      AND bundle.invitation_limit IS NOT NULL
      AND bundle.engine_identifier='deterministic-matcher-v1'
      AND sha256(bundle.canonical_manifest_bytes)
            = bundle.canonical_manifest_sha256;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.read_rule_bundle_for_match_v1(
    uuid,uuid,bytea,uuid,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.read_rule_bundle_for_match_v1(
    uuid,uuid,bytea,uuid,bytea
) TO matching_worker;

CREATE FUNCTION matching_api.ingest_matching_requested_v1(
    exact_workload_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_requested jsonb,
    exact_attempt_id uuid,
    exact_run_id uuid,
    exact_job_id uuid,
    exact_selection_id uuid,
    exact_coordinator_workload_id uuid,
    exact_coordinator_authority_marker_sha256 bytea,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_run_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    inbox_row matching.source_inbox%ROWTYPE;
    source_event_id uuid;
    demand_id uuid;
    demand_version_id uuid;
    matching_request_id uuid;
    original_actor_user_id uuid;
    matching_rule_bundle_id uuid;
    selector_digest bytea;
    demand_content_sha256 bytea;
    rule_requirement_sha256 bytea;
    authorization_digest bytea;
    envelope_sha256 bytea;
    input_baseline_sha256 bytea;
    attempt_number integer;
    invitation_set_sha256 bytea;
    response_body jsonb;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_worker','MATCHING_WORKER','INGEST_MATCHING_REQUESTED',
        exact_workload_id,exact_organization_id,
        exact_authority_marker_sha256,exact_command_id
    );
    IF jsonb_typeof(exact_requested) <> 'object'
       OR exact_attempt_id IS NULL OR exact_run_id IS NULL
       OR exact_job_id IS NULL OR exact_selection_id IS NULL
       OR exact_coordinator_workload_id IS NULL
       OR exact_outbox_event_id IS NULL
       OR exact_run_outbox_event_id IS NULL
       OR exact_outbox_event_id = exact_run_outbox_event_id
       OR octet_length(exact_coordinator_authority_marker_sha256) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    BEGIN
        source_event_id := (exact_requested->>'source_event_id')::uuid;
        demand_id := (exact_requested->>'demand_id')::uuid;
        demand_version_id := (exact_requested->>'demand_version_id')::uuid;
        matching_request_id := (exact_requested->>'matching_request_id')::uuid;
        original_actor_user_id :=
            (exact_requested->>'original_actor_user_id')::uuid;
        matching_rule_bundle_id :=
            (exact_requested->>'matching_rule_bundle_id')::uuid;
        selector_digest := decode(
            exact_requested->>'matching_selector_digest','hex'
        );
        demand_content_sha256 := decode(
            exact_requested->>'demand_content_sha256','hex'
        );
        rule_requirement_sha256 := decode(
            exact_requested->>'rule_requirement_sha256','hex'
        );
        authorization_digest := decode(
            exact_requested->>'authorization_digest','hex'
        );
        envelope_sha256 := decode(
            exact_requested->>'envelope_sha256','hex'
        );
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END;
    IF source_event_id IS NULL OR demand_id IS NULL
       OR demand_version_id IS NULL OR matching_request_id IS NULL
       OR original_actor_user_id IS NULL
       OR original_actor_user_id =
            '00000000-0000-0000-0000-000000000000'::uuid
       OR (exact_requested->>'event_type') IS DISTINCT FROM 'MatchingRequested'
       OR (exact_requested->>'schema_version')::integer <> 1
       OR (exact_requested->>'aggregate_type') IS DISTINCT FROM 'Demand'
       OR (exact_requested->>'source_aggregate_id')::uuid
            IS DISTINCT FROM demand_id
       OR (exact_requested->>'source_aggregate_version')::bigint
            IS DISTINCT FROM (exact_requested->>'demand_aggregate_version')::bigint
       OR (exact_requested->>'authorized_workload_principal_id')::uuid
            IS DISTINCT FROM exact_workload_id
       OR (exact_requested->>'demand_aggregate_version')::bigint < 1
       OR (exact_requested->>'matching_request_version')::bigint < 1
       OR octet_length(selector_digest) <> 32
       OR octet_length(demand_content_sha256) <> 32
       OR octet_length(rule_requirement_sha256) <> 32
       OR octet_length(authorization_digest) <> 32
       OR authorization_digest IS DISTINCT FROM exact_authority_marker_sha256
       OR octet_length(envelope_sha256) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,exact_organization_id,
        'INGEST_MATCHING_REQUESTED',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/source-events/matching-requested',
        'MatchingAttempt',exact_attempt_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;

    SELECT inbox.* INTO inbox_row
    FROM matching.source_inbox AS inbox
    WHERE inbox.consumer_name='matching-requested-v1'
      AND inbox.source_event_id=source_event_id
    FOR UPDATE;
    IF FOUND THEN
        IF inbox_row.event_type <> 'MatchingRequested'
           OR inbox_row.source_aggregate_id <> demand_id
           OR inbox_row.source_aggregate_version
                <> (exact_requested->>'demand_aggregate_version')::bigint
           OR inbox_row.organization_id <> exact_organization_id
           OR inbox_row.demand_id <> demand_id
           OR inbox_row.demand_version_id <> demand_version_id
           OR inbox_row.original_actor_user_id <> original_actor_user_id
           OR inbox_row.envelope_sha256 <> envelope_sha256
           OR inbox_row.authority_marker_sha256
                <> exact_authority_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SOURCE_EVENT_REUSED';
        END IF;
        IF inbox_row.status <> 'COMPLETED'
           OR inbox_row.target_attempt_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SERVICE_UNAVAILABLE';
        END IF;
        response_body := jsonb_build_object(
            'attempt_id',inbox_row.target_attempt_id::text,
            'aggregate_version',inbox_row.target_aggregate_version,
            'status','OPEN','source_event_id',source_event_id::text
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,inbox_row.target_aggregate_version,
            'OPEN',ARRAY['MatchingAttemptOpened','MatchRunQueued']::text[]
        );
        RETURN QUERY SELECT response_body, true;
        RETURN;
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        exact_organization_id::text || ':' || demand_id::text, 0
    ));
    IF EXISTS (
        SELECT 1 FROM matching.matching_attempts AS attempt
        WHERE attempt.organization_id=exact_organization_id
          AND attempt.demand_id=demand_id AND attempt.status='OPEN'
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='PRECONDITION_FAILED';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM matching.rule_selectors AS selector
        JOIN matching.rule_bundles AS bundle
          ON bundle.id=selector.current_bundle_id
         AND bundle.selector_digest=selector.selector_digest
        WHERE selector.selector_digest=selector_digest
          AND bundle.id=matching_rule_bundle_id
          AND bundle.status='ACTIVE'
          AND bundle.effective_at<=transaction_timestamp()
          AND (bundle.effective_until IS NULL
               OR bundle.effective_until>transaction_timestamp())
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='MATCHING_RULE_UNAVAILABLE';
    END IF;
    SELECT COALESCE(max(attempt.attempt_no),0)+1 INTO attempt_number
    FROM matching.matching_attempts AS attempt
    WHERE attempt.organization_id=exact_organization_id
      AND attempt.demand_id=demand_id;
    input_baseline_sha256 := sha256(
        demand_content_sha256 || rule_requirement_sha256
        || authorization_digest || envelope_sha256
    );

    INSERT INTO matching.source_inbox (
        consumer_name,source_event_id,event_type,schema_version,
        source_aggregate_id,source_aggregate_version,organization_id,
        demand_id,demand_version_id,envelope_sha256,workload_id,
        authority_marker_sha256,status,target_attempt_id,
        target_aggregate_version,result_event_types,created_at,completed_at,
        original_actor_user_id
    ) VALUES (
        'matching-requested-v1',source_event_id,'MatchingRequested',1,
        demand_id,(exact_requested->>'demand_aggregate_version')::bigint,
        exact_organization_id,demand_id,demand_version_id,envelope_sha256,
        exact_workload_id,exact_authority_marker_sha256,'IN_PROGRESS',
        NULL,NULL,NULL,transaction_timestamp(),NULL,original_actor_user_id
    );
    SET CONSTRAINTS ALL DEFERRED;
    INSERT INTO matching.matching_attempts (
        id,organization_id,demand_id,demand_version_id,
        demand_content_sha256,demand_aggregate_version,matching_request_id,
        matching_request_version,funding_id,composite_rule_requirement_id,
        matching_rule_bundle_id,selector_digest,source_event_id,attempt_no,
        status,aggregate_version,current_match_run_id,selection_id,
        input_baseline_sha256,system_workload_id,
        system_authority_marker_sha256,created_at,updated_at,terminal_at,
        source_authorization_digest,original_actor_user_id
    ) VALUES (
        exact_attempt_id,exact_organization_id,demand_id,demand_version_id,
        demand_content_sha256,
        (exact_requested->>'demand_aggregate_version')::bigint,
        matching_request_id,
        (exact_requested->>'matching_request_version')::bigint,
        (exact_requested->>'funding_id')::uuid,
        (exact_requested->>'composite_rule_requirement_id')::uuid,
        matching_rule_bundle_id,selector_digest,source_event_id,attempt_number,
        'OPEN',1,exact_run_id,exact_selection_id,input_baseline_sha256,
        exact_workload_id,exact_authority_marker_sha256,
        transaction_timestamp(),transaction_timestamp(),NULL,
        authorization_digest,original_actor_user_id
    );
    INSERT INTO matching.match_runs (
        id,organization_id,attempt_id,demand_id,run_no,status,
        aggregate_version,matching_rule_bundle_id,input_manifest_sha256,
        input_set_sha256,ordered_result_sha256,candidate_count,
        eligible_count,excluded_count,worker_id,lease_token_digest_key_id,
        lease_token_digest,fencing_generation,lease_until,supersedes_run_id,
        superseded_by_run_id,failure_code,created_at,updated_at
    ) VALUES (
        exact_run_id,exact_organization_id,exact_attempt_id,demand_id,1,
        'QUEUED',1,matching_rule_bundle_id,NULL,NULL,NULL,NULL,NULL,NULL,
        NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,transaction_timestamp(),
        transaction_timestamp()
    );
    invitation_set_sha256 := matching.selection_invitation_set_sha256_v1(
        exact_attempt_id,exact_run_id
    );
    INSERT INTO matching.selections (
        id,organization_id,attempt_id,match_run_id,status,aggregate_version,
        current_invitation_set_sha256,chosen_invitation_id,
        chosen_invitation_status,selection_basis_code,reason_code,
        decision_actor_id,coordinator_workload_id,
        coordinator_authority_marker_sha256,created_at,updated_at
    ) VALUES (
        exact_selection_id,exact_organization_id,exact_attempt_id,exact_run_id,
        'OPEN',1,invitation_set_sha256,NULL,NULL,NULL,NULL,NULL,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        transaction_timestamp(),transaction_timestamp()
    );
    INSERT INTO matching.match_jobs (
        id,organization_id,attempt_id,match_run_id,job_kind,status,
        workload_id,authority_marker_sha256,lease_token_digest_key_id,
        lease_token_digest,fencing_generation,available_at,lease_until,
        attempt_count,created_at,completed_at
    ) VALUES (
        exact_job_id,exact_organization_id,exact_attempt_id,exact_run_id,
        'RUN_MATCH','AVAILABLE',exact_workload_id,
        exact_authority_marker_sha256,NULL,NULL,0,transaction_timestamp(),
        NULL,0,transaction_timestamp(),NULL
    );
    UPDATE matching.source_inbox
    SET status='COMPLETED',target_attempt_id=exact_attempt_id,
        target_aggregate_version=1,
        result_event_types=ARRAY['MatchingAttemptOpened','MatchRunQueued'],
        completed_at=transaction_timestamp()
    WHERE consumer_name='matching-requested-v1'
      AND source_event_id=source_event_id AND status='IN_PROGRESS';

    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'INGEST_MATCHING_REQUESTED','MatchingAttempt',exact_attempt_id,
        exact_organization_id,NULL,'OPEN',NULL,1,NULL,exact_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('source_event_id',source_event_id::text,
            'matching_request_id',matching_request_id::text,
            'run_id',exact_run_id::text,'job_id',exact_job_id::text)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'MatchingAttemptOpened','MatchingAttempt',
        exact_attempt_id,1,'SYSTEM',exact_workload_id,NULL,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'attempt_id',exact_attempt_id::text,'demand_id',demand_id::text,
            'demand_version_id',demand_version_id::text,
            'matching_request_id',matching_request_id::text,
            'attempt_no',attempt_number,'status','OPEN',
            'reason_code',NULL,'selection_id',NULL,
            'chosen_invitation_id',NULL)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_run_outbox_event_id,'MatchRunQueued','MatchRun',exact_run_id,1,
        'SYSTEM',exact_workload_id,NULL,exact_organization_id,
        exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'run_id',exact_run_id::text,'attempt_id',exact_attempt_id::text,
            'run_no',1,'rule_bundle_id',matching_rule_bundle_id::text,
            'input_set_sha256',repeat('0',64),'status','QUEUED',
            'candidate_count',NULL,'eligible_count',NULL,
            'excluded_count',NULL,'ordered_result_sha256',NULL,
            'failure_code',NULL,'successor_run_id',NULL)
    );
    response_body := jsonb_build_object(
        'attempt_id',exact_attempt_id::text,'aggregate_version',1,
        'run_id',exact_run_id::text,'job_id',exact_job_id::text,
        'selection_id',exact_selection_id::text,'status','OPEN',
        'source_event_id',source_event_id::text
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,1,'OPEN',
        ARRAY['MatchingAttemptOpened','MatchRunQueued']::text[]
    );
    RETURN QUERY SELECT response_body, false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.ingest_matching_requested_v1(
    uuid,uuid,bytea,jsonb,uuid,uuid,uuid,uuid,uuid,bytea,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.ingest_matching_requested_v1(
    uuid,uuid,bytea,jsonb,uuid,uuid,uuid,uuid,uuid,bytea,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid,uuid
) TO matching_worker;

CREATE FUNCTION matching_api.claim_match_job_v1(
    exact_workload_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_lease_token_digest_key_id text,
    exact_lease_token_digest bytea,
    exact_lease_seconds integer,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    prior matching.command_receipts%ROWTYPE;
    receipt_result record;
    job_row matching.match_jobs%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    selection_found boolean;
    new_fence bigint;
    next_run_no integer;
    successor_hex text;
    successor_run_id uuid;
    successor_job_id uuid;
    retry_allowed boolean;
    invitation_set_sha256 bytea;
    lease_deadline timestamptz;
    audit_action text;
    event_type text;
    response_body jsonb;
    event_payload jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_worker'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_workload_id IS NULL
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR exact_command_id IS NULL
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_WORKER'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_MATCH_JOB'
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM exact_workload_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_authority_marker_sha256, 'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR COALESCE(current_setting('app.organization_id', true), '') <> ''
    THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    IF length(exact_lease_token_digest_key_id) NOT BETWEEN 1 AND 128
       OR octet_length(exact_lease_token_digest) <> 32
       OR exact_lease_seconds NOT BETWEEN 1 AND 300
       OR exact_receipt_id IS NULL
       OR length(exact_identity_key_id) NOT BETWEEN 1 AND 128
       OR octet_length(exact_identity_digest) <> 32
       OR length(exact_payload_hash_key_id) NOT BETWEEN 1 AND 128
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR octet_length(exact_payload_hash) <> 32
       OR exact_audit_event_id IS NULL OR exact_outbox_event_id IS NULL
       OR exact_correlation_id IS NULL OR exact_trace_id IS NULL
       OR NULLIF(current_setting('app.lease_token_digest_key_id', true), '')
            IS DISTINCT FROM exact_lease_token_digest_key_id
       OR NULLIF(current_setting('app.lease_token_digest', true), '')
            IS DISTINCT FROM encode(exact_lease_token_digest,'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    -- Serialize a targetless idempotency identity before either receipt lookup
    -- or cross-organization job discovery.  Hash collisions only serialize
    -- unrelated claims; they cannot change authorization or results.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        exact_workload_id::text || ':' || exact_identity_key_id || ':'
            || encode(exact_identity_digest, 'hex'),
        0
    ));

    SELECT receipt.* INTO prior
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind='SYSTEM'
      AND receipt.principal_id=exact_workload_id
      AND receipt.operation='CLAIM_MATCH_JOB'
      AND receipt.command_version=1
      AND receipt.identity_key_id=exact_identity_key_id
      AND receipt.identity_digest=exact_identity_digest;
    IF FOUND THEN
        PERFORM set_config(
            'app.organization_id', prior.organization_id::text, true
        );
        SELECT receipt.* INTO STRICT prior
        FROM matching.command_receipts AS receipt
        WHERE receipt.id=prior.id
        FOR UPDATE;
        IF prior.payload_hash_key_id IS DISTINCT FROM exact_payload_hash_key_id
           OR prior.payload_hash IS DISTINCT FROM exact_payload_hash
           OR prior.principal_authority_marker_sha256
                IS DISTINCT FROM exact_authority_marker_sha256
           OR prior.status <> 'COMPLETED'
           OR prior.safe_response_body IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE=CASE WHEN prior.status='COMPLETED'
                    THEN 'IDEMPOTENCY_KEY_REUSED'
                    ELSE 'SERVICE_UNAVAILABLE' END;
        END IF;
        RETURN QUERY SELECT prior.safe_response_body, true;
        RETURN;
    END IF;

    SELECT job.* INTO job_row
    FROM matching.match_jobs AS job
    JOIN matching.match_runs AS run
      ON run.id=job.match_run_id
     AND run.organization_id=job.organization_id
     AND run.attempt_id=job.attempt_id
    WHERE job.workload_id=exact_workload_id
      AND job.authority_marker_sha256=exact_authority_marker_sha256
      AND job.job_kind='RUN_MATCH'
      AND (
          (job.status='AVAILABLE'
              AND job.available_at<=transaction_timestamp()
              AND run.status='QUEUED')
          OR (job.status='LEASED'
              AND job.lease_until<=transaction_timestamp()
              AND run.status IN ('QUEUED','RUNNING'))
      )
    ORDER BY CASE WHEN job.status='AVAILABLE'
        THEN job.available_at ELSE job.lease_until END,
        job.created_at,job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM set_config(
        'app.organization_id', job_row.organization_id::text, true
    );
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=job_row.match_run_id
      AND run.organization_id=job_row.organization_id
      AND run.attempt_id=job_row.attempt_id
    FOR UPDATE;
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=run_row.attempt_id
      AND attempt.organization_id=job_row.organization_id
      AND attempt.demand_id=run_row.demand_id
    FOR UPDATE;

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,job_row.organization_id,
        'CLAIM_MATCH_JOB',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/jobs/claim','MatchJob',job_row.id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;

    lease_deadline := transaction_timestamp()
        + make_interval(secs=>exact_lease_seconds);
    new_fence := job_row.fencing_generation+1;

    -- Three claims are the reviewed maximum.  A fourth pre-start reclaim must
    -- terminalize the poisoned lease instead of violating the CHECK and being
    -- selected forever.  No input set exists yet, so emit the dedicated
    -- forward event rather than fabricating a MatchRunFailed input digest.
    IF run_row.status='QUEUED'
       AND job_row.status='LEASED'
       AND job_row.attempt_count >= 3 THEN
        UPDATE matching.match_runs
        SET status='FAILED',aggregate_version=aggregate_version+1,
            fencing_generation=new_fence,
            failure_code='WORKER_CLAIM_RETRY_EXHAUSTED',
            updated_at=transaction_timestamp()
        WHERE id=run_row.id AND status='QUEUED'
          AND fencing_generation=run_row.fencing_generation;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
        END IF;
        UPDATE matching.match_jobs
        SET status='FAILED',fencing_generation=new_fence,
            lease_token_digest_key_id=NULL,lease_token_digest=NULL,
            lease_until=NULL,completed_at=transaction_timestamp()
        WHERE id=job_row.id AND status='LEASED'
          AND fencing_generation=job_row.fencing_generation
          AND lease_until<=transaction_timestamp()
          AND attempt_count=job_row.attempt_count;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
        END IF;
        response_body := jsonb_build_object(
            'organization_id',job_row.organization_id::text,
            'job_id',job_row.id::text,
            'attempt_id',run_row.attempt_id::text,
            'match_run_id',run_row.id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'matching_rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'selector_digest',encode(attempt_row.selector_digest,'hex'),
            'source_authorization_digest',encode(
                attempt_row.source_authorization_digest,'hex'
            ),
            'status','FAILED','run_status','FAILED',
            'aggregate_version',run_row.aggregate_version+1,
            'fencing_generation',new_fence,
            'run_attempt',run_row.run_no,'maximum_run_attempts',3,
            'recovery_status','REVIEW_REQUIRED',
            'failure_code','WORKER_CLAIM_RETRY_EXHAUSTED'
        );
        PERFORM matching.record_operational_audit_v1(
            exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
            'EXHAUST_MATCH_JOB_CLAIMS','MatchRun',run_row.id,
            job_row.organization_id,'QUEUED','FAILED',
            run_row.aggregate_version,run_row.aggregate_version+1,
            'WORKER_CLAIM_RETRY_EXHAUSTED',exact_command_id,
            exact_correlation_id,exact_trace_id,jsonb_build_object(
                'job_id',job_row.id::text,
                'claim_attempt_count',job_row.attempt_count,
                'terminal_fencing_generation',new_fence
            )
        );
        PERFORM matching.record_operational_outbox_v1(
            exact_outbox_event_id,'MatchRunFailedBeforeStart','MatchRun',
            run_row.id,run_row.aggregate_version+1,'SYSTEM',
            exact_workload_id,NULL,job_row.organization_id,exact_command_id,
            exact_correlation_id,exact_trace_id,jsonb_build_object(
                'run_id',run_row.id::text,
                'attempt_id',run_row.attempt_id::text,
                'run_no',run_row.run_no,
                'rule_bundle_id',run_row.matching_rule_bundle_id::text,
                'status','FAILED',
                'failure_code','WORKER_CLAIM_RETRY_EXHAUSTED'
            )
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,run_row.aggregate_version+1,
            'REVIEW_REQUIRED',ARRAY['MatchRunFailedBeforeStart']::text[]
        );
        RETURN QUERY SELECT response_body,false;
        RETURN;
    END IF;

    IF run_row.status='QUEUED' THEN
        audit_action := CASE WHEN job_row.status='AVAILABLE'
            THEN 'CLAIM_MATCH_JOB' ELSE 'RECOVER_MATCH_JOB_LEASE' END;
        UPDATE matching.match_jobs
        SET status='LEASED',
            lease_token_digest_key_id=exact_lease_token_digest_key_id,
            lease_token_digest=exact_lease_token_digest,
            fencing_generation=new_fence,
            lease_until=lease_deadline,
            attempt_count=attempt_count+1
        WHERE id=job_row.id
          AND fencing_generation=job_row.fencing_generation
          AND (
              (job_row.status='AVAILABLE' AND status='AVAILABLE'
                  AND available_at<=transaction_timestamp())
              OR (job_row.status='LEASED' AND status='LEASED'
                  AND lease_until<=transaction_timestamp())
          );
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SERVICE_UNAVAILABLE';
        END IF;
        response_body := jsonb_build_object(
            'organization_id',job_row.organization_id::text,
            'job_id',job_row.id::text,
            'attempt_id',job_row.attempt_id::text,
            'match_run_id',job_row.match_run_id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'matching_rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'selector_digest',encode(attempt_row.selector_digest,'hex'),
            'source_authorization_digest',encode(
                attempt_row.source_authorization_digest,'hex'
            ),
            'job_kind',job_row.job_kind,'status','LEASED',
            'run_status','QUEUED','fencing_generation',new_fence,
            'lease_until',lease_deadline,
            'attempt_count',job_row.attempt_count+1,
            'run_attempt',run_row.run_no,'maximum_run_attempts',3,
            'recovery_status',CASE WHEN job_row.status='LEASED'
                THEN 'QUEUED_LEASE_RECOVERED' ELSE 'CLAIMED' END
        );
        PERFORM matching.record_operational_audit_v1(
            exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
            audit_action,'MatchJob',job_row.id,job_row.organization_id,
            job_row.status,'LEASED',
            NULLIF(job_row.fencing_generation,0),new_fence,
            CASE WHEN job_row.status='LEASED'
                THEN 'WORKER_LEASE_EXPIRED' ELSE NULL END,
            exact_command_id,exact_correlation_id,exact_trace_id,
            jsonb_build_object(
                'match_run_id',job_row.match_run_id::text,
                'fencing_generation',new_fence,
                'recovered_expired_lease',job_row.status='LEASED'
            )
        );
        PERFORM matching.record_operational_outbox_v1(
            exact_outbox_event_id,'MatchJobClaimed','MatchJob',job_row.id,
            new_fence,'SYSTEM',exact_workload_id,NULL,
            job_row.organization_id,exact_command_id,exact_correlation_id,
            exact_trace_id,jsonb_build_object(
                'job_id',job_row.id::text,
                'attempt_id',job_row.attempt_id::text,
                'match_run_id',job_row.match_run_id::text,
                'status','LEASED','fencing_generation',new_fence,
                'recovery_status',response_body->>'recovery_status'
            )
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,new_fence,'LEASED',
            ARRAY['MatchJobClaimed']::text[]
        );
        RETURN QUERY SELECT response_body, false;
        RETURN;
    END IF;

    -- An expired lease on RUNNING means the prior worker may have executed
    -- arbitrary work.  Fence and terminalize it, then retry on a new run/job;
    -- never put the old job back into circulation.
    SELECT selection.* INTO selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
      AND selection.organization_id=job_row.organization_id
    FOR UPDATE;
    selection_found := FOUND;
    retry_allowed := run_row.run_no < 3
        AND attempt_row.status='OPEN'
        AND attempt_row.current_match_run_id=run_row.id
        AND selection_found
        AND selection_row.status='OPEN'
        AND selection_row.match_run_id=run_row.id;
    next_run_no := run_row.run_no+1;

    IF retry_allowed THEN
        successor_hex := encode(sha256(convert_to(
            'matching-recovery-run-v1:' || run_row.id::text || ':'
                || next_run_no::text,
            'UTF8'
        )), 'hex');
        successor_run_id := (
            substr(successor_hex,1,8) || '-'
            || substr(successor_hex,9,4) || '-4'
            || substr(successor_hex,14,3) || '-8'
            || substr(successor_hex,18,3) || '-'
            || substr(successor_hex,21,12)
        )::uuid;
        successor_hex := encode(sha256(convert_to(
            'matching-recovery-job-v1:' || job_row.id::text || ':'
                || successor_run_id::text,
            'UTF8'
        )), 'hex');
        successor_job_id := (
            substr(successor_hex,1,8) || '-'
            || substr(successor_hex,9,4) || '-4'
            || substr(successor_hex,14,3) || '-8'
            || substr(successor_hex,18,3) || '-'
            || substr(successor_hex,21,12)
        )::uuid;
    END IF;

    UPDATE matching.match_runs
    SET status='FAILED',aggregate_version=aggregate_version+1,
        fencing_generation=new_fence,
        lease_token_digest_key_id=NULL,lease_token_digest=NULL,
        lease_until=NULL,failure_code='WORKER_LEASE_EXPIRED',
        superseded_by_run_id=CASE WHEN retry_allowed
            THEN successor_run_id ELSE NULL END,
        updated_at=transaction_timestamp()
    WHERE id=run_row.id AND status='RUNNING'
      AND fencing_generation=job_row.fencing_generation
      AND lease_until<=transaction_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;
    UPDATE matching.match_jobs
    SET status='FAILED',fencing_generation=new_fence,
        lease_token_digest_key_id=NULL,lease_token_digest=NULL,
        lease_until=NULL,completed_at=transaction_timestamp()
    WHERE id=job_row.id AND status='LEASED'
      AND fencing_generation=job_row.fencing_generation
      AND lease_until<=transaction_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;

    IF retry_allowed THEN
        INSERT INTO matching.match_runs (
            id,organization_id,attempt_id,demand_id,run_no,status,
            aggregate_version,matching_rule_bundle_id,input_manifest_sha256,
            input_set_sha256,ordered_result_sha256,candidate_count,
            eligible_count,excluded_count,worker_id,
            lease_token_digest_key_id,lease_token_digest,
            fencing_generation,lease_until,supersedes_run_id,
            superseded_by_run_id,failure_code,created_at,updated_at
        ) VALUES (
            successor_run_id,job_row.organization_id,run_row.attempt_id,
            run_row.demand_id,next_run_no,'QUEUED',1,
            run_row.matching_rule_bundle_id,NULL,NULL,NULL,NULL,NULL,NULL,
            NULL,NULL,NULL,0,NULL,run_row.id,NULL,NULL,
            transaction_timestamp(),transaction_timestamp()
        );
        invitation_set_sha256 := matching.selection_invitation_set_sha256_v1(
            attempt_row.id,successor_run_id
        );
        UPDATE matching.matching_attempts
        SET current_match_run_id=successor_run_id,
            aggregate_version=aggregate_version+1,
            updated_at=transaction_timestamp()
        WHERE id=attempt_row.id AND status='OPEN'
          AND current_match_run_id=run_row.id;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='PRECONDITION_FAILED';
        END IF;
        UPDATE matching.selections
        SET match_run_id=successor_run_id,
            current_invitation_set_sha256=invitation_set_sha256,
            aggregate_version=aggregate_version+1,
            updated_at=transaction_timestamp()
        WHERE id=selection_row.id AND status='OPEN'
          AND match_run_id=run_row.id;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='PRECONDITION_FAILED';
        END IF;
        INSERT INTO matching.match_jobs (
            id,organization_id,attempt_id,match_run_id,job_kind,status,
            workload_id,authority_marker_sha256,lease_token_digest_key_id,
            lease_token_digest,fencing_generation,available_at,lease_until,
            attempt_count,created_at,completed_at
        ) VALUES (
            successor_job_id,job_row.organization_id,run_row.attempt_id,
            successor_run_id,'RUN_MATCH','LEASED',exact_workload_id,
            exact_authority_marker_sha256,
            exact_lease_token_digest_key_id,exact_lease_token_digest,1,
            transaction_timestamp(),lease_deadline,1,
            transaction_timestamp(),NULL
        );
        event_type := 'MatchRunRetryScheduled';
        response_body := jsonb_build_object(
            'organization_id',job_row.organization_id::text,
            'failed_job_id',job_row.id::text,
            'failed_match_run_id',run_row.id::text,
            'job_id',successor_job_id::text,
            'attempt_id',run_row.attempt_id::text,
            'match_run_id',successor_run_id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'matching_rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'selector_digest',encode(attempt_row.selector_digest,'hex'),
            'source_authorization_digest',encode(
                attempt_row.source_authorization_digest,'hex'
            ),
            'job_kind','RUN_MATCH','status','LEASED',
            'run_status','QUEUED','fencing_generation',1,
            'lease_until',lease_deadline,'attempt_count',1,
            'run_attempt',next_run_no,'maximum_run_attempts',3,
            'recovery_status','RUNNING_LEASE_RETRY_LEASED',
            'failure_code','WORKER_LEASE_EXPIRED'
        );
        event_payload := jsonb_build_object(
            'failed_run_id',run_row.id::text,
            'failed_run_version',run_row.aggregate_version+1,
            'successor_run_id',successor_run_id::text,
            'successor_job_id',successor_job_id::text,
            'attempt_id',run_row.attempt_id::text,
            'failure_code','WORKER_LEASE_EXPIRED',
            'status','QUEUED'
        );
    ELSE
        event_type := 'MatchRunFailed';
        response_body := jsonb_build_object(
            'organization_id',job_row.organization_id::text,
            'job_id',job_row.id::text,
            'attempt_id',run_row.attempt_id::text,
            'match_run_id',run_row.id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'matching_rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'selector_digest',encode(attempt_row.selector_digest,'hex'),
            'source_authorization_digest',encode(
                attempt_row.source_authorization_digest,'hex'
            ),
            'status','FAILED','run_status','FAILED',
            'aggregate_version',run_row.aggregate_version+1,
            'fencing_generation',new_fence,
            'run_attempt',run_row.run_no,'maximum_run_attempts',3,
            'recovery_status','REVIEW_REQUIRED',
            'failure_code','WORKER_LEASE_EXPIRED'
        );
        event_payload := jsonb_build_object(
            'run_id',run_row.id::text,
            'attempt_id',run_row.attempt_id::text,
            'run_no',run_row.run_no,
            'rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'input_set_sha256',encode(run_row.input_set_sha256,'hex'),
            'status','FAILED','candidate_count',NULL,
            'eligible_count',NULL,'excluded_count',NULL,
            'ordered_result_sha256',NULL,
            'failure_code','WORKER_LEASE_EXPIRED','successor_run_id',NULL
        );
    END IF;
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'RECOVER_EXPIRED_MATCH_RUN','MatchRun',run_row.id,
        job_row.organization_id,'RUNNING','FAILED',run_row.aggregate_version,
        run_row.aggregate_version+1,'WORKER_LEASE_EXPIRED',
        exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'failed_job_id',job_row.id::text,
            'stale_fencing_generation',job_row.fencing_generation,
            'terminal_fencing_generation',new_fence,
            'successor_run_id',successor_run_id::text,
            'successor_job_id',successor_job_id::text,
            'recovery_status',response_body->>'recovery_status'
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,event_type,'MatchRun',run_row.id,
        run_row.aggregate_version+1,'SYSTEM',exact_workload_id,NULL,
        job_row.organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,event_payload
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,
        CASE WHEN retry_allowed THEN 1 ELSE run_row.aggregate_version+1 END,
        CASE WHEN retry_allowed THEN 'LEASED' ELSE 'REVIEW_REQUIRED' END,
        ARRAY[event_type]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.claim_match_job_v1(
    uuid,bytea,text,bytea,integer,uuid,uuid,text,bytea,text,bytea,
    uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.claim_match_job_v1(
    uuid,bytea,text,bytea,integer,uuid,uuid,text,bytea,text,bytea,
    uuid,uuid,uuid,uuid
) TO matching_worker;

CREATE FUNCTION matching_api.start_match_run_v1(
    exact_workload_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_job_id uuid,
    exact_match_run_id uuid,
    exact_fencing_generation bigint,
    exact_lease_token_digest_key_id text,
    exact_lease_token_digest bytea,
    exact_canonical_manifest_bytes bytea,
    exact_manifest jsonb,
    exact_manifest_sha256 bytea,
    exact_canonical_run_input_bytes bytea,
    exact_run_input jsonb,
    exact_run_input_sha256 bytea,
    exact_canonical_input_set_bytes bytea,
    exact_input_set_sha256 bytea,
    exact_candidate_allowlist_sha256 bytea,
    exact_candidate_count integer,
    exact_canonical_source_capture_bytes bytea,
    exact_source_capture jsonb,
    exact_source_capture_sha256 bytea,
    exact_source_authorization_valid_until timestamptz,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    job_row matching.match_jobs%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    bundle_row matching.rule_bundles%ROWTYPE;
    source_snapshot jsonb;
    manifest_identity jsonb;
    derived_profile jsonb;
    response_body jsonb;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_worker','MATCHING_WORKER','START_MATCH_RUN',
        exact_workload_id,exact_organization_id,
        exact_authority_marker_sha256,exact_command_id
    );
    IF exact_job_id IS NULL OR exact_match_run_id IS NULL
       OR exact_fencing_generation < 1
       OR length(exact_lease_token_digest_key_id) NOT BETWEEN 1 AND 128
       OR octet_length(exact_lease_token_digest) <> 32
       OR sha256(exact_canonical_manifest_bytes)
            IS DISTINCT FROM exact_manifest_sha256
       OR sha256(exact_canonical_run_input_bytes)
            IS DISTINCT FROM exact_run_input_sha256
       OR sha256(exact_canonical_input_set_bytes)
            IS DISTINCT FROM exact_input_set_sha256
       OR sha256(exact_canonical_source_capture_bytes)
            IS DISTINCT FROM exact_source_capture_sha256
       OR octet_length(exact_candidate_allowlist_sha256) <> 32
       OR exact_candidate_count < 0
       OR jsonb_typeof(exact_manifest) <> 'object'
       OR jsonb_typeof(exact_run_input) <> 'object'
       OR jsonb_typeof(exact_source_capture) <> 'object'
       OR convert_from(exact_canonical_manifest_bytes,'UTF8')::jsonb
            IS DISTINCT FROM exact_manifest
       OR convert_from(exact_canonical_run_input_bytes,'UTF8')::jsonb
            IS DISTINCT FROM exact_run_input
       OR convert_from(exact_canonical_input_set_bytes,'UTF8')::jsonb
            IS DISTINCT FROM jsonb_build_object(
                'manifest_references',exact_manifest - ARRAY[
                    'schema_version','canonicalization_version',
                    'input_set_sha256'
                ]::text[],
                'run_input',exact_run_input - 'input_set_sha256'
            )
       OR convert_from(exact_canonical_source_capture_bytes,'UTF8')::jsonb
            IS DISTINCT FROM exact_source_capture
       OR (SELECT count(*) FROM jsonb_object_keys(exact_source_capture)) <> 7
       OR NOT exact_source_capture ?& ARRAY[
            'schema_version','canonicalization_version','match_run_id',
            'workload_id','authorization_digest','demand','profile'
       ]
       OR (exact_source_capture->>'schema_version')::integer <> 1
       OR (exact_source_capture->>'canonicalization_version')
            <> 'matching-source-capture-bundle-json-v1'
       OR (exact_source_capture->>'match_run_id')::uuid
            <> exact_match_run_id
       OR (exact_source_capture->>'workload_id')::uuid
            <> exact_workload_id
       OR octet_length(decode(
            exact_source_capture->>'authorization_digest','hex'
          )) <> 32
       OR jsonb_typeof(exact_source_capture->'demand') <> 'object'
       OR jsonb_typeof(exact_source_capture->'profile') <> 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(
            exact_source_capture->'demand'
          )) <> 7
       OR NOT (exact_source_capture->'demand') ?& ARRAY[
            'matching_request_id','demand_id','demand_version_id',
            'content_sha256','canonical_content_hex','content','captured_at'
       ]
       OR (SELECT count(*) FROM jsonb_object_keys(
            exact_source_capture->'profile'
          )) <> 7
       OR NOT (exact_source_capture->'profile') ?& ARRAY[
            'capture_contract_version','status','captured_at',
            'authorization_valid_until','candidate_count',
            'allowlist_sha256','snapshots'
       ]
       OR (exact_source_capture->'profile'->>'capture_contract_version')::integer
            NOT IN (1,2)
       OR (exact_source_capture->'profile'->>'status') <> 'COMPLETED'
       OR (exact_source_capture->'profile'->>'candidate_count')::integer
            <> exact_candidate_count
       OR decode(exact_source_capture->'profile'->>'allowlist_sha256','hex')
            <> exact_candidate_allowlist_sha256
       OR (exact_source_capture->'profile'->>'authorization_valid_until')
            ::timestamptz <> exact_source_authorization_valid_until
       OR jsonb_typeof(exact_source_capture->'profile'->'snapshots')
            <> 'array'
       OR jsonb_array_length(
            exact_source_capture->'profile'->'snapshots'
          ) <> exact_candidate_count
       OR (SELECT count(DISTINCT value->>'snapshot_ordinal')
           FROM jsonb_array_elements(
                exact_source_capture->'profile'->'snapshots'
           ) AS snapshots(value)) <> exact_candidate_count
       OR (SELECT count(DISTINCT value->>'creator_user_id')
           FROM jsonb_array_elements(
                exact_source_capture->'profile'->'snapshots'
           ) AS snapshots(value)) <> exact_candidate_count
       OR (SELECT count(DISTINCT value->>'profile_id')
           FROM jsonb_array_elements(
                exact_source_capture->'profile'->'snapshots'
           ) AS snapshots(value)) <> exact_candidate_count
       OR (exact_manifest->>'input_set_sha256')
            IS DISTINCT FROM encode(exact_input_set_sha256,'hex')
       OR (exact_run_input->>'input_set_sha256')
            IS DISTINCT FROM encode(exact_input_set_sha256,'hex')
       OR jsonb_typeof(exact_manifest->'ordered_candidates') <> 'array'
       OR jsonb_array_length(exact_manifest->'ordered_candidates')
            <> exact_candidate_count
       OR jsonb_typeof(exact_run_input->'profiles') <> 'array'
       OR jsonb_array_length(exact_run_input->'profiles')
            <> exact_candidate_count
       OR NULLIF(current_setting('app.lease_token_digest_key_id', true), '')
            IS DISTINCT FROM exact_lease_token_digest_key_id
       OR NULLIF(current_setting('app.lease_token_digest', true), '')
            IS DISTINCT FROM encode(exact_lease_token_digest,'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,exact_organization_id,
        'START_MATCH_RUN',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/runs/start','MatchRun',exact_match_run_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;
    IF exact_source_authorization_valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    SELECT job.* INTO STRICT job_row
    FROM matching.match_jobs AS job
    WHERE job.id=exact_job_id AND job.organization_id=exact_organization_id
      AND job.match_run_id=exact_match_run_id
      AND job.workload_id=exact_workload_id
    FOR UPDATE;
    IF job_row.status <> 'LEASED'
       OR job_row.fencing_generation <> exact_fencing_generation
       OR job_row.lease_token_digest_key_id
            <> exact_lease_token_digest_key_id
       OR job_row.lease_token_digest <> exact_lease_token_digest
       OR job_row.lease_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=exact_match_run_id
      AND run.organization_id=exact_organization_id
      AND run.attempt_id=job_row.attempt_id
    FOR UPDATE;
    IF run_row.status <> 'QUEUED'
       OR run_row.fencing_generation >= exact_fencing_generation THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='PRECONDITION_FAILED';
    END IF;
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=run_row.attempt_id
      AND attempt.organization_id=exact_organization_id;
    IF attempt_row.source_authorization_digest IS NULL
       OR decode(exact_source_capture->>'authorization_digest','hex')
            <> attempt_row.source_authorization_digest
       OR (exact_source_capture->'demand'->>'matching_request_id')::uuid
            <> attempt_row.matching_request_id
       OR (exact_source_capture->'demand'->>'demand_id')::uuid
            <> attempt_row.demand_id
       OR (exact_source_capture->'demand'->>'demand_version_id')::uuid
            <> attempt_row.demand_version_id
       OR decode(exact_source_capture->'demand'->>'content_sha256','hex')
            <> attempt_row.demand_content_sha256
       OR sha256(decode(
            exact_source_capture->'demand'->>'canonical_content_hex','hex'
          )) <> attempt_row.demand_content_sha256
       OR convert_from(decode(
            exact_source_capture->'demand'->>'canonical_content_hex','hex'
          ),'UTF8')::jsonb
            IS DISTINCT FROM exact_source_capture->'demand'->'content' THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='MATCH_INPUT_CHANGED';
    END IF;

    FOR source_snapshot IN
        SELECT value
        FROM jsonb_array_elements(
            exact_source_capture->'profile'->'snapshots'
        ) AS snapshots(value)
        ORDER BY (value->>'snapshot_ordinal')::integer
    LOOP
        IF jsonb_typeof(source_snapshot) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(source_snapshot)) <> 13
           OR NOT source_snapshot ?& ARRAY[
                'snapshot_ordinal','creator_user_id','profile_id',
                'profile_version_id','version_no','taxonomy_bundle_id',
                'canonical_content_hex','content','content_sha256',
                'canonical_derived_input_hex','derived_input',
                'derived_input_sha256','evidence_version_digest'
           ]
           OR (source_snapshot->>'snapshot_ordinal')::integer < 1
           OR (source_snapshot->>'version_no')::bigint < 1
           OR sha256(decode(
                source_snapshot->>'canonical_content_hex','hex'
              )) <> decode(source_snapshot->>'content_sha256','hex')
           OR convert_from(decode(
                source_snapshot->>'canonical_content_hex','hex'
              ),'UTF8')::jsonb IS DISTINCT FROM source_snapshot->'content'
           OR sha256(decode(
                source_snapshot->>'canonical_derived_input_hex','hex'
              )) <> decode(source_snapshot->>'derived_input_sha256','hex')
           OR convert_from(decode(
                source_snapshot->>'canonical_derived_input_hex','hex'
              ),'UTF8')::jsonb
                IS DISTINCT FROM source_snapshot->'derived_input'
           OR octet_length(decode(
                source_snapshot->>'evidence_version_digest','hex'
              )) <> 32 THEN
            RAISE EXCEPTION USING ERRCODE='22023',
                MESSAGE='INVALID_REQUEST';
        END IF;
        SELECT identity.value INTO manifest_identity
        FROM jsonb_array_elements(
            exact_manifest->'ordered_candidates'
        ) AS identity(value)
        WHERE identity.value->>'creator_user_id'
                = source_snapshot->>'creator_user_id'
          AND identity.value->>'profile_id'
                = source_snapshot->>'profile_id'
          AND identity.value->>'profile_version_id'
                = source_snapshot->>'profile_version_id';
        IF NOT FOUND
           OR manifest_identity->>'profile_content_sha256'
                <> source_snapshot->>'content_sha256'
           OR manifest_identity->>'evidence_version_digest'
                <> source_snapshot->>'evidence_version_digest' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='MATCH_INPUT_CHANGED';
        END IF;
        SELECT profile.value INTO derived_profile
        FROM jsonb_array_elements(exact_run_input->'profiles')
            AS profile(value)
        WHERE profile.value->>'creator_user_id'
                = source_snapshot->>'creator_user_id'
          AND profile.value->>'profile_id'
                = source_snapshot->>'profile_id'
          AND profile.value->>'profile_version_id'
                = source_snapshot->>'profile_version_id';
        IF NOT FOUND
           OR derived_profile IS DISTINCT FROM source_snapshot->'derived_input'
           OR derived_profile->>'profile_content_sha256'
                <> source_snapshot->>'content_sha256'
           OR derived_profile->>'evidence_version_digest'
                <> source_snapshot->>'evidence_version_digest' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='MATCH_INPUT_CHANGED';
        END IF;
    END LOOP;
    PERFORM set_config(
        'app.rule_bundle_id',run_row.matching_rule_bundle_id::text,true
    );
    SELECT bundle.* INTO bundle_row
    FROM matching.rule_bundles AS bundle
    WHERE bundle.id=run_row.matching_rule_bundle_id
      AND bundle.status='ACTIVE'
      AND bundle.effective_at <= transaction_timestamp()
      AND (bundle.effective_until IS NULL
           OR bundle.effective_until > transaction_timestamp());
    IF NOT FOUND
       OR bundle_row.canonical_manifest_bytes IS NULL
       OR bundle_row.manifest IS NULL
       OR bundle_row.invitation_limit IS NULL
       OR bundle_row.engine_identifier <> 'deterministic-matcher-v1'
       OR sha256(bundle_row.canonical_manifest_bytes)
            <> bundle_row.canonical_manifest_sha256
       OR (exact_manifest->>'matching_rule_bundle_id')::uuid
            <> bundle_row.id
       OR decode(exact_manifest->>'selector_digest','hex')
            <> bundle_row.selector_digest
       OR decode(exact_manifest->>'rule_manifest_sha256','hex')
            <> bundle_row.canonical_manifest_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
    END IF;
    INSERT INTO matching.match_run_inputs (
        match_run_id,attempt_id,organization_id,demand_id,demand_version_id,
        matching_rule_bundle_id,manifest_schema_version,
        manifest_canonicalization_version,canonical_manifest_bytes,manifest,
        manifest_sha256,run_input_schema_version,
        run_input_canonicalization_version,canonical_run_input_bytes,
        run_input,run_input_sha256,canonical_input_set_bytes,
        input_set_sha256,candidate_allowlist_sha256,
        candidate_count,captured_at,source_capture_schema_version,
        source_capture_canonicalization_version,
        canonical_source_capture_bytes,source_capture,source_capture_sha256,
        source_authorization_valid_until
    ) SELECT
        run_row.id,run_row.attempt_id,run_row.organization_id,run_row.demand_id,
        attempt.demand_version_id,run_row.matching_rule_bundle_id,1,
        'match-input-manifest-v1',exact_canonical_manifest_bytes,
        exact_manifest,exact_manifest_sha256,1,'match-run-input-json-v1',
        exact_canonical_run_input_bytes,exact_run_input,
        exact_run_input_sha256,exact_canonical_input_set_bytes,
        exact_input_set_sha256,exact_candidate_allowlist_sha256,
        exact_candidate_count,transaction_timestamp(),1,
        'matching-source-capture-bundle-json-v1',
        exact_canonical_source_capture_bytes,exact_source_capture,
        exact_source_capture_sha256,exact_source_authorization_valid_until
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=run_row.attempt_id;
    UPDATE matching.match_runs
    SET status='RUNNING',aggregate_version=aggregate_version+1,
        input_manifest_sha256=exact_manifest_sha256,
        input_set_sha256=exact_input_set_sha256,worker_id=exact_workload_id,
        lease_token_digest_key_id=exact_lease_token_digest_key_id,
        lease_token_digest=exact_lease_token_digest,
        fencing_generation=exact_fencing_generation,
        lease_until=job_row.lease_until,updated_at=transaction_timestamp()
    WHERE id=run_row.id;
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'START_MATCH_RUN','MatchRun',run_row.id,exact_organization_id,
        'QUEUED','RUNNING',run_row.aggregate_version,
        run_row.aggregate_version+1,NULL,exact_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('job_id',job_row.id::text,
            'fencing_generation',exact_fencing_generation,
            'input_set_sha256',encode(exact_input_set_sha256,'hex'))
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'MatchRunStarted','MatchRun',run_row.id,
        run_row.aggregate_version+1,'SYSTEM',exact_workload_id,NULL,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'run_id',run_row.id::text,
            'attempt_id',run_row.attempt_id::text,
            'run_no',run_row.run_no,
            'rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'input_set_sha256',encode(exact_input_set_sha256,'hex'),
            'status','RUNNING','candidate_count',NULL,
            'eligible_count',NULL,'excluded_count',NULL,
            'ordered_result_sha256',NULL,'failure_code',NULL,
            'successor_run_id',NULL)
    );
    response_body := jsonb_build_object(
        'match_run_id',run_row.id::text,'attempt_id',run_row.attempt_id::text,
        'status','RUNNING','aggregate_version',run_row.aggregate_version+1,
        'fencing_generation',exact_fencing_generation,
        'lease_until',job_row.lease_until,
        'input_set_sha256',encode(exact_input_set_sha256,'hex'),
        'run_input_sha256',encode(exact_run_input_sha256,'hex')
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,run_row.aggregate_version+1,'RUNNING',
        ARRAY['MatchRunStarted']::text[]
    );
    RETURN QUERY SELECT response_body, false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.start_match_run_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,bytea,jsonb,bytea,bytea,
    jsonb,bytea,bytea,bytea,bytea,integer,bytea,jsonb,bytea,timestamptz,
    uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.start_match_run_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,bytea,jsonb,bytea,bytea,
    jsonb,bytea,bytea,bytea,bytea,integer,bytea,jsonb,bytea,timestamptz,
    uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_worker;

CREATE FUNCTION matching_api.complete_match_run_v1(
    exact_workload_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_job_id uuid,
    exact_match_run_id uuid,
    exact_fencing_generation bigint,
    exact_lease_token_digest_key_id text,
    exact_lease_token_digest bytea,
    exact_canonical_result_bytes bytea,
    exact_result jsonb,
    exact_engine_result_sha256 bytea,
    exact_ordered_result_sha256 bytea,
    exact_system_close_intent_id uuid,
    exact_system_close_audit_event_id uuid,
    exact_selection_close_intent_event_id uuid,
    exact_attempt_close_event_id uuid,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    job_row matching.match_jobs%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    input_row matching.match_run_inputs%ROWTYPE;
    bundle_row matching.rule_bundles%ROWTYPE;
    candidate_item jsonb;
    captured_identity jsonb;
    actual_count integer;
    actual_eligible integer;
    actual_excluded integer;
    invitation_set_sha256 bytea;
    new_selection_version bigint;
    response_body jsonb;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_worker','MATCHING_WORKER','COMPLETE_MATCH_RUN',
        exact_workload_id,exact_organization_id,
        exact_authority_marker_sha256,exact_command_id
    );
    IF exact_job_id IS NULL OR exact_match_run_id IS NULL
       OR exact_fencing_generation < 1
       OR length(exact_lease_token_digest_key_id) NOT BETWEEN 1 AND 128
       OR octet_length(exact_lease_token_digest) <> 32
       OR sha256(exact_canonical_result_bytes)
            IS DISTINCT FROM exact_engine_result_sha256
       OR jsonb_typeof(exact_result) <> 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(exact_result)) <> 10
       OR NOT exact_result ?& ARRAY[
            'schema_version','canonicalization_version','attempt_id','run_id',
            'matching_rule_bundle_id','input_set_sha256','engine_identifier',
            'engine_artifact_sha256','ordered_result_sha256','candidates'
       ]
       OR (exact_result->>'schema_version')::integer <> 1
       OR (exact_result->>'canonicalization_version')
            <> 'deterministic-match-result-json-v1'
       OR (exact_result->>'run_id')::uuid <> exact_match_run_id
       OR jsonb_typeof(exact_result->'candidates') <> 'array'
       OR jsonb_array_length(exact_result->'candidates') > 500
       OR convert_from(exact_canonical_result_bytes,'UTF8')::jsonb
            IS DISTINCT FROM exact_result
       OR decode(exact_result->>'ordered_result_sha256','hex')
            IS DISTINCT FROM exact_ordered_result_sha256
       OR NOT (
            (exact_system_close_intent_id IS NULL
             AND exact_system_close_audit_event_id IS NULL
             AND exact_selection_close_intent_event_id IS NULL
             AND exact_attempt_close_event_id IS NULL)
            OR
            (exact_system_close_intent_id IS NOT NULL
             AND exact_system_close_audit_event_id IS NOT NULL
             AND exact_selection_close_intent_event_id IS NOT NULL
             AND exact_attempt_close_event_id IS NOT NULL
             AND exact_system_close_intent_id
                    <> exact_system_close_audit_event_id
             AND exact_system_close_audit_event_id
                    <> exact_selection_close_intent_event_id
             AND exact_system_close_audit_event_id
                    <> exact_attempt_close_event_id
             AND exact_system_close_audit_event_id <> exact_audit_event_id
             AND exact_system_close_audit_event_id <> exact_outbox_event_id
             AND exact_system_close_intent_id
                    <> exact_selection_close_intent_event_id
             AND exact_system_close_intent_id <> exact_attempt_close_event_id
             AND exact_selection_close_intent_event_id
                    <> exact_attempt_close_event_id
             AND exact_selection_close_intent_event_id
                    <> exact_outbox_event_id
             AND exact_attempt_close_event_id <> exact_outbox_event_id)
       )
       OR NULLIF(current_setting('app.lease_token_digest_key_id', true), '')
            IS DISTINCT FROM exact_lease_token_digest_key_id
       OR NULLIF(current_setting('app.lease_token_digest', true), '')
            IS DISTINCT FROM encode(exact_lease_token_digest,'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,exact_organization_id,
        'COMPLETE_MATCH_RUN',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/runs/complete','MatchRun',
        exact_match_run_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;
    SELECT job.* INTO STRICT job_row
    FROM matching.match_jobs AS job
    WHERE job.id=exact_job_id AND job.organization_id=exact_organization_id
      AND job.match_run_id=exact_match_run_id
      AND job.workload_id=exact_workload_id
    FOR UPDATE;
    IF job_row.status <> 'LEASED'
       OR job_row.fencing_generation <> exact_fencing_generation
       OR job_row.lease_token_digest_key_id
            <> exact_lease_token_digest_key_id
       OR job_row.lease_token_digest <> exact_lease_token_digest
       OR job_row.lease_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=exact_match_run_id
      AND run.organization_id=exact_organization_id
      AND run.attempt_id=job_row.attempt_id
    FOR UPDATE;
    IF run_row.status <> 'RUNNING'
       OR (exact_result->>'attempt_id')::uuid <> run_row.attempt_id
       OR run_row.fencing_generation <> exact_fencing_generation
       OR run_row.worker_id <> exact_workload_id
       OR run_row.lease_token_digest_key_id
            <> exact_lease_token_digest_key_id
       OR run_row.lease_token_digest <> exact_lease_token_digest
       OR run_row.lease_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=run_row.attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
      AND selection.organization_id=exact_organization_id
      AND selection.attempt_id=attempt_row.id
      AND selection.match_run_id=run_row.id
    FOR UPDATE;
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.current_match_run_id <> run_row.id
       OR attempt_row.original_actor_user_id IS NULL
       OR selection_row.status <> 'OPEN'
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_system_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='PRECONDITION_FAILED';
    END IF;
    SELECT input.* INTO STRICT input_row
    FROM matching.match_run_inputs AS input
    WHERE input.match_run_id=run_row.id;
    PERFORM set_config(
        'app.rule_bundle_id',run_row.matching_rule_bundle_id::text,true
    );
    SELECT bundle.* INTO bundle_row
    FROM matching.rule_bundles AS bundle
    WHERE bundle.id=run_row.matching_rule_bundle_id
      AND bundle.status='ACTIVE'
      AND bundle.effective_at <= transaction_timestamp()
      AND (bundle.effective_until IS NULL
           OR bundle.effective_until > transaction_timestamp());
    IF NOT FOUND
       OR bundle_row.canonical_manifest_bytes IS NULL
       OR bundle_row.engine_identifier <> 'deterministic-matcher-v1'
       OR (exact_result->>'matching_rule_bundle_id')::uuid
            <> bundle_row.id
       OR decode(exact_result->>'input_set_sha256','hex')
            <> input_row.input_set_sha256
       OR (exact_result->>'engine_identifier')
            <> bundle_row.engine_identifier
       OR decode(exact_result->>'engine_artifact_sha256','hex')
            <> bundle_row.engine_artifact_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
    END IF;
    actual_count := jsonb_array_length(exact_result->'candidates');
    IF actual_count <> input_row.candidate_count THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='MATCH_INPUT_CHANGED';
    END IF;

    FOR candidate_item IN
        SELECT value FROM jsonb_array_elements(
            exact_result->'candidates'
        ) AS candidates(value)
    LOOP
        BEGIN
            IF jsonb_typeof(candidate_item) <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(candidate_item)) <> 15
               OR NOT candidate_item ?& ARRAY[
                    'schema_version','canonicalization_version','attempt_id',
                    'run_id','creator_user_id','profile_id',
                    'profile_version_id','profile_content_sha256',
                    'eligibility','exclusion_reason_codes','components',
                    'total_score','rank','evidence_facts',
                    'candidate_result_sha256'
               ]
               OR (candidate_item->>'schema_version')::integer <> 1
               OR (candidate_item->>'canonicalization_version')
                    <> 'match-candidate-result-json-v1'
               OR (candidate_item->>'attempt_id')::uuid <> run_row.attempt_id
               OR (candidate_item->>'run_id')::uuid <> run_row.id THEN
                RAISE EXCEPTION USING ERRCODE='22023',
                    MESSAGE='INVALID_REQUEST';
            END IF;
            SELECT identity.value INTO captured_identity
            FROM jsonb_array_elements(
                input_row.manifest->'ordered_candidates'
            ) AS identity(value)
            WHERE identity.value->>'creator_user_id'
                    = candidate_item->>'creator_user_id'
              AND identity.value->>'profile_id'
                    = candidate_item->>'profile_id'
              AND identity.value->>'profile_version_id'
                    = candidate_item->>'profile_version_id'
              AND identity.value->>'profile_content_sha256'
                    = candidate_item->>'profile_content_sha256';
            IF NOT FOUND
               OR octet_length(decode(
                    captured_identity->>'evidence_version_digest','hex'
               )) <> 32 THEN
                RAISE EXCEPTION USING ERRCODE='P0001',
                    MESSAGE='MATCH_INPUT_CHANGED';
            END IF;
            INSERT INTO matching.match_candidates (
                attempt_id,match_run_id,creator_user_id,profile_id,
                profile_version_id,profile_content_sha256,
                evidence_version_digest,eligibility,exclusion_reason_codes,
                component_scores,total_score,rank,evidence_facts,
                candidate_result_sha256,created_at
            ) VALUES (
                run_row.attempt_id,run_row.id,
                (candidate_item->>'creator_user_id')::uuid,
                (candidate_item->>'profile_id')::uuid,
                (candidate_item->>'profile_version_id')::uuid,
                decode(candidate_item->>'profile_content_sha256','hex'),
                decode(captured_identity->>'evidence_version_digest','hex'),
                candidate_item->>'eligibility',
                ARRAY(SELECT value FROM jsonb_array_elements_text(
                    candidate_item->'exclusion_reason_codes'
                ) AS reasons(value)),
                candidate_item->'components',
                NULLIF(candidate_item->>'total_score','')::numeric,
                NULLIF(candidate_item->>'rank','')::integer,
                candidate_item->'evidence_facts',
                decode(candidate_item->>'candidate_result_sha256','hex'),
                transaction_timestamp()
            );
        EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
            OR not_null_violation THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
        END;
    END LOOP;
    SELECT count(*),count(*) FILTER (WHERE eligibility='ELIGIBLE'),
        count(*) FILTER (WHERE eligibility='EXCLUDED')
    INTO actual_count,actual_eligible,actual_excluded
    FROM matching.match_candidates AS candidate
    WHERE candidate.match_run_id=run_row.id;
    IF (actual_eligible = 0) IS DISTINCT FROM
       (exact_system_close_intent_id IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    INSERT INTO matching.match_run_results (
        match_run_id,attempt_id,organization_id,matching_rule_bundle_id,
        input_set_sha256,engine_identifier,engine_artifact_sha256,
        engine_result_sha256,schema_version,
        canonicalization_version,canonical_result_bytes,result,
        ordered_result_sha256,candidate_count,eligible_count,excluded_count,
        completed_at
    ) VALUES (
        run_row.id,run_row.attempt_id,exact_organization_id,
        run_row.matching_rule_bundle_id,input_row.input_set_sha256,
        bundle_row.engine_identifier,bundle_row.engine_artifact_sha256,
        exact_engine_result_sha256,1,
        'deterministic-match-result-json-v1',exact_canonical_result_bytes,
        exact_result,
        exact_ordered_result_sha256,actual_count,actual_eligible,
        actual_excluded,transaction_timestamp()
    );
    UPDATE matching.match_runs
    SET status='COMPLETED',aggregate_version=aggregate_version+1,
        ordered_result_sha256=exact_ordered_result_sha256,
        candidate_count=actual_count,eligible_count=actual_eligible,
        excluded_count=actual_excluded,updated_at=transaction_timestamp()
    WHERE id=run_row.id;
    UPDATE matching.match_jobs
    SET status='COMPLETED',completed_at=transaction_timestamp()
    WHERE id=job_row.id AND status='LEASED'
      AND fencing_generation=exact_fencing_generation;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='COMMAND_OUTCOME_UNKNOWN';
    END IF;
    IF actual_eligible = 0 THEN
        invitation_set_sha256 :=
            matching.selection_invitation_set_sha256_v1(
                attempt_row.id,run_row.id
            );
        IF invitation_set_sha256
                <> selection_row.current_invitation_set_sha256
           OR EXISTS (
                SELECT 1 FROM matching.invitations AS invitation
                WHERE invitation.attempt_id=attempt_row.id
                  AND invitation.match_run_id=run_row.id
           ) THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='PRECONDITION_FAILED';
        END IF;
        INSERT INTO matching.selection_system_close_intents (
            id,receipt_id,command_id,organization_id,selection_id,
            attempt_id,match_run_id,original_actor_user_id,demand_id,
            demand_version_id,demand_aggregate_version,
            matching_request_id,matching_request_version,funding_id,
            current_invitation_set_sha256,reason_code,
            attempt_close_event_id,status,recorded_at
        ) VALUES (
            exact_system_close_intent_id,exact_receipt_id,exact_command_id,
            exact_organization_id,selection_row.id,attempt_row.id,run_row.id,
            attempt_row.original_actor_user_id,attempt_row.demand_id,
            attempt_row.demand_version_id,
            attempt_row.demand_aggregate_version,
            attempt_row.matching_request_id,
            attempt_row.matching_request_version,attempt_row.funding_id,
            selection_row.current_invitation_set_sha256,
            'NO_ELIGIBLE_CANDIDATES',exact_attempt_close_event_id,
            'READY',transaction_timestamp()
        );
        INSERT INTO matching.selection_completion_jobs (
            id,organization_id,selection_id,attempt_id,match_run_id,
            intent_receipt_id,intent_kind,status,workload_id,
            authority_marker_sha256,lease_digest_key_id,lease_digest,
            fencing_generation,available_at,lease_until,attempt_count,
            last_failure_code,created_at,completed_at
        ) VALUES (
            selection_row.id,exact_organization_id,selection_row.id,
            attempt_row.id,run_row.id,exact_receipt_id,'SYSTEM_CLOSE',
            'AVAILABLE',selection_row.coordinator_workload_id,
            selection_row.coordinator_authority_marker_sha256,
            NULL,NULL,0,transaction_timestamp(),NULL,0,NULL,
            transaction_timestamp(),NULL
        );
        new_selection_version := selection_row.aggregate_version+1;
        UPDATE matching.selections
        SET aggregate_version=new_selection_version,
            updated_at=transaction_timestamp()
        WHERE id=selection_row.id AND status='OPEN'
          AND aggregate_version=selection_row.aggregate_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='COMMAND_OUTCOME_UNKNOWN';
        END IF;
        PERFORM matching.record_operational_audit_v1(
            exact_system_close_audit_event_id,'SYSTEM',exact_workload_id,
            attempt_row.original_actor_user_id,
            'RECORD_SELECTION_CLOSE_INTENT','Selection',selection_row.id,
            exact_organization_id,'OPEN','PENDING_CLOSE',
            selection_row.aggregate_version,new_selection_version,
            'NO_ELIGIBLE_CANDIDATES',exact_command_id,
            exact_correlation_id,exact_trace_id,
            jsonb_build_object('attempt_id',attempt_row.id::text,
                'match_run_id',run_row.id::text,
                'system_close_intent_id',
                    exact_system_close_intent_id::text)
        );
        PERFORM matching.record_operational_outbox_v1(
            exact_selection_close_intent_event_id,
            'SelectionCloseIntentRecorded','Selection',selection_row.id,
            new_selection_version,'SYSTEM',exact_workload_id,
            attempt_row.original_actor_user_id,exact_organization_id,
            exact_command_id,exact_correlation_id,exact_trace_id,
            jsonb_build_object(
                'selection_id',selection_row.id::text,
                'attempt_id',attempt_row.id::text,
                'status','PENDING_CLOSE',
                'current_invitation_set_sha256',encode(
                    selection_row.current_invitation_set_sha256,'hex'
                ),
                'chosen_invitation_id',NULL,
                'selection_basis_code',NULL,
                'reason_code','NO_ELIGIBLE_CANDIDATES')
        );
    END IF;
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'COMPLETE_MATCH_RUN','MatchRun',run_row.id,exact_organization_id,
        'RUNNING','COMPLETED',run_row.aggregate_version,
        run_row.aggregate_version+1,NULL,exact_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('job_id',job_row.id::text,
            'fencing_generation',exact_fencing_generation,
            'candidate_count',actual_count,'eligible_count',actual_eligible,
            'excluded_count',actual_excluded,
            'ordered_result_sha256',encode(exact_ordered_result_sha256,'hex'))
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'MatchRunCompleted','MatchRun',run_row.id,
        run_row.aggregate_version+1,'SYSTEM',exact_workload_id,NULL,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'run_id',run_row.id::text,
            'attempt_id',run_row.attempt_id::text,
            'run_no',run_row.run_no,
            'rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'input_set_sha256',encode(run_row.input_set_sha256,'hex'),
            'status','COMPLETED',
            'candidate_count',actual_count,'eligible_count',actual_eligible,
            'excluded_count',actual_excluded,
            'ordered_result_sha256',encode(exact_ordered_result_sha256,'hex'),
            'failure_code',NULL,'successor_run_id',NULL)
    );
    response_body := jsonb_build_object(
        'match_run_id',run_row.id::text,'attempt_id',run_row.attempt_id::text,
        'job_id',job_row.id::text,'status','COMPLETED',
        'aggregate_version',run_row.aggregate_version+1,
        'fencing_generation',exact_fencing_generation,
        'candidate_count',actual_count,'eligible_count',actual_eligible,
        'excluded_count',actual_excluded,
        'ordered_result_sha256',encode(exact_ordered_result_sha256,'hex'),
        'selection_status',CASE WHEN actual_eligible=0
            THEN 'PENDING_CLOSE' ELSE 'OPEN' END,
        'selection_version',CASE WHEN actual_eligible=0
            THEN new_selection_version ELSE selection_row.aggregate_version END
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,run_row.aggregate_version+1,
        'COMPLETED',CASE WHEN actual_eligible=0 THEN ARRAY[
            'MatchRunCompleted','SelectionCloseIntentRecorded'
        ]::text[] ELSE ARRAY['MatchRunCompleted']::text[] END
    );
    RETURN QUERY SELECT response_body, false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.complete_match_run_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,bytea,jsonb,bytea,bytea,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.complete_match_run_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,bytea,jsonb,bytea,bytea,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_worker;

ALTER FUNCTION matching_api.execute_candidate_selection_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,text,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) RENAME TO execute_candidate_selection_immediate_v2;
REVOKE ALL ON FUNCTION matching_api.execute_candidate_selection_immediate_v2(
    text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,text,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) FROM matching_selector, PUBLIC;

-- Preserve CHOOSE behavior, but make CLOSE a durable intent.  The coordinator
-- owns the only program that may atomically close Matching and Demand.
CREATE FUNCTION matching_api.execute_candidate_selection_v1(
    exact_operation text,
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_selection_id uuid,
    expected_selection_version bigint,
    expected_invitation_set_sha256 bytea,
    exact_selector_assignment_id uuid,
    expected_selector_assignment_version bigint,
    expected_authority_marker_sha256 bytea,
    exact_invitation_id uuid,
    exact_selection_basis_code text,
    exact_reason_code text,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_intent_id uuid,
    exact_audit_event_id uuid,
    exact_primary_event_id uuid,
    exact_secondary_event_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    assignment_row matching.candidate_selector_assignments%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    invitation_row matching.invitations%ROWTYPE;
    candidate_row matching.match_candidates%ROWTYPE;
    receipt_row record;
    authoritative_set_sha256 bytea;
    canonical_path text;
    response_body jsonb;
    new_selection_version bigint;
BEGIN
    IF exact_operation='CHOOSE_CREATOR' THEN
        IF session_user IS DISTINCT FROM 'matching_selector'
           OR current_user IS DISTINCT FROM 'matching_schema_owner'
           OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
           OR exact_organization_id IS NULL OR exact_selection_id IS NULL
           OR exact_selector_assignment_id IS NULL
           OR expected_selection_version < 1
           OR expected_selector_assignment_version < 1
           OR octet_length(expected_invitation_set_sha256) <> 32
           OR octet_length(expected_authority_marker_sha256) <> 32
           OR octet_length(exact_identity_digest) <> 32
           OR octet_length(exact_payload_hash) <> 32
           OR exact_identity_key_id = exact_payload_hash_key_id
           OR exact_invitation_id IS NULL OR exact_intent_id IS NULL
           OR exact_secondary_event_id IS NOT NULL
           OR exact_selection_basis_code IS NULL
           OR exact_selection_basis_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
           OR exact_reason_code IS NOT NULL
           OR NULLIF(current_setting('app.scope_kind', true), '')
                IS DISTINCT FROM 'CANDIDATE_SELECTOR'
           OR NULLIF(current_setting('app.operation', true), '')
                IS DISTINCT FROM exact_operation
           OR NULLIF(current_setting('app.actor_user_id', true), '')
                IS DISTINCT FROM exact_actor_user_id::text
           OR NULLIF(current_setting('app.session_id', true), '')
                IS DISTINCT FROM exact_session_id::text
           OR NULLIF(current_setting('app.organization_id', true), '')
                IS DISTINCT FROM exact_organization_id::text
           OR NULLIF(current_setting('app.selection_id', true), '')
                IS DISTINCT FROM exact_selection_id::text
           OR NULLIF(current_setting('app.selector_assignment_id', true), '')
                IS DISTINCT FROM exact_selector_assignment_id::text
           OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
                IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
           OR NULLIF(current_setting('app.command_id', true), '')
                IS DISTINCT FROM exact_command_id::text
           OR NULLIF(current_setting('app.target_id', true), '')
                IS DISTINCT FROM exact_selection_id::text
           OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
           OR COALESCE(current_setting('app.invitation_id', true), '') <> ''
           OR COALESCE(current_setting('app.demand_id', true), '') <> '' THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
        END IF;
        canonical_path := '/v1/organizations/'
            || exact_organization_id::text || '/selections/'
            || exact_selection_id::text || '/choose';
        SELECT * INTO STRICT receipt_row
        FROM matching.claim_command_receipt_v1(
            exact_receipt_id,exact_actor_user_id,exact_organization_id,
            exact_operation,exact_identity_key_id,exact_identity_digest,
            exact_payload_hash_key_id,exact_payload_hash,
            expected_authority_marker_sha256,canonical_path,'Selection',
            exact_selection_id,expected_selection_version
        );
        IF receipt_row.replayed THEN
            RETURN QUERY SELECT receipt_row.safe_response, true;
            RETURN;
        END IF;
        SELECT assignment.* INTO assignment_row
        FROM matching.candidate_selector_assignments AS assignment
        WHERE assignment.id=exact_selector_assignment_id
        FOR UPDATE;
        IF NOT FOUND
           OR assignment_row.assignment_version
                <> expected_selector_assignment_version
           OR assignment_row.status <> 'ACTIVE'
           OR assignment_row.expires_at <= transaction_timestamp()
           OR assignment_row.assignee_user_id <> exact_actor_user_id
           OR assignment_row.assignee_session_id <> exact_session_id
           OR assignment_row.organization_id <> exact_organization_id
           OR assignment_row.selection_id <> exact_selection_id
           OR assignment_row.authority_marker_sha256
                IS DISTINCT FROM expected_authority_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SELECTOR_ASSIGNMENT_REQUIRED';
        END IF;
        SELECT selection.* INTO selection_row
        FROM matching.selections AS selection
        WHERE selection.id=exact_selection_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
        END IF;
        PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
        PERFORM set_config('app.invitation_id',exact_invitation_id::text,true);
        SELECT attempt.* INTO STRICT attempt_row
        FROM matching.matching_attempts AS attempt
        WHERE attempt.id=selection_row.attempt_id
        FOR UPDATE;
        SELECT selection.* INTO STRICT selection_row
        FROM matching.selections AS selection
        WHERE selection.id=exact_selection_id
        FOR UPDATE;
        PERFORM set_config(
            'app.match_run_id',attempt_row.current_match_run_id::text,true
        );
        IF selection_row.status <> 'OPEN' OR attempt_row.status <> 'OPEN'
           OR assignment_row.demand_id <> attempt_row.demand_id
           OR selection_row.organization_id <> attempt_row.organization_id
           OR selection_row.attempt_id <> attempt_row.id THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='INVALID_STATE_TRANSITION';
        END IF;
        IF selection_row.aggregate_version <> expected_selection_version
           OR selection_row.current_invitation_set_sha256
                IS DISTINCT FROM expected_invitation_set_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='PRECONDITION_FAILED';
        END IF;
        SELECT run.* INTO STRICT run_row
        FROM matching.match_runs AS run
        WHERE run.id=attempt_row.current_match_run_id
        FOR SHARE;
        PERFORM invitation.id
        FROM matching.invitations AS invitation
        WHERE invitation.attempt_id=attempt_row.id
          AND invitation.match_run_id=attempt_row.current_match_run_id
        ORDER BY invitation.id
        FOR UPDATE;
        authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
            attempt_row.id,attempt_row.current_match_run_id
        );
        SELECT invitation.* INTO invitation_row
        FROM matching.invitations AS invitation
        WHERE invitation.id=exact_invitation_id;
        IF NOT FOUND
           OR authoritative_set_sha256 IS NULL
           OR authoritative_set_sha256
                IS DISTINCT FROM selection_row.current_invitation_set_sha256
           OR invitation_row.attempt_id <> attempt_row.id
           OR invitation_row.match_run_id <> attempt_row.current_match_run_id
           OR invitation_row.status <> 'ACCEPTED'
           OR run_row.status <> 'COMPLETED'
           OR run_row.superseded_by_run_id IS NOT NULL
           OR run_row.input_set_sha256 IS NULL
           OR run_row.ordered_result_sha256 IS NULL
           OR EXISTS (
                SELECT 1 FROM matching.selection_intents AS intent
                WHERE intent.selection_id=selection_row.id
           )
           OR EXISTS (
                SELECT 1 FROM matching.selection_close_intents AS close_intent
                WHERE close_intent.selection_id=selection_row.id
           ) THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SELECTION_NOT_READY';
        END IF;
        SELECT candidate.* INTO candidate_row
        FROM matching.match_candidates AS candidate
        WHERE candidate.match_run_id=run_row.id
          AND candidate.creator_user_id=invitation_row.creator_user_id;
        IF NOT FOUND
           OR candidate_row.eligibility <> 'ELIGIBLE'
           OR candidate_row.profile_id <> invitation_row.profile_id
           OR candidate_row.profile_version_id
                <> invitation_row.profile_version_id THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='SELECTION_NOT_READY';
        END IF;
        INSERT INTO matching.selection_intents (
            id,receipt_id,command_id,organization_id,selection_id,attempt_id,
            match_run_id,invitation_id,actor_user_id,
            candidate_selector_assignment_id,
            candidate_selector_assignment_version,
            candidate_selector_authority_marker_sha256,demand_id,
            demand_version_id,matching_request_id,matching_request_version,
            funding_id,matching_rule_bundle_id,input_set_sha256,
            ordered_result_sha256,candidate_result_sha256,
            current_invitation_set_sha256,selection_basis_code,
            payload_hash_key_id,payload_hash,status,recorded_at,
            invitation_status
        ) VALUES (
            exact_intent_id,exact_receipt_id,exact_command_id,
            exact_organization_id,selection_row.id,attempt_row.id,run_row.id,
            invitation_row.id,exact_actor_user_id,assignment_row.id,
            assignment_row.assignment_version,
            assignment_row.authority_marker_sha256,attempt_row.demand_id,
            attempt_row.demand_version_id,attempt_row.matching_request_id,
            attempt_row.matching_request_version,attempt_row.funding_id,
            run_row.matching_rule_bundle_id,run_row.input_set_sha256,
            run_row.ordered_result_sha256,candidate_row.candidate_result_sha256,
            selection_row.current_invitation_set_sha256,
            exact_selection_basis_code,exact_payload_hash_key_id,
            exact_payload_hash,'READY',transaction_timestamp(),'ACCEPTED'
        );
        INSERT INTO matching.selection_completion_jobs (
            id,organization_id,selection_id,attempt_id,match_run_id,
            intent_receipt_id,intent_kind,status,workload_id,
            authority_marker_sha256,lease_digest_key_id,lease_digest,
            fencing_generation,available_at,lease_until,attempt_count,
            last_failure_code,created_at,completed_at
        ) VALUES (
            selection_row.id,exact_organization_id,selection_row.id,
            attempt_row.id,run_row.id,exact_receipt_id,'CHOOSE','AVAILABLE',
            selection_row.coordinator_workload_id,
            selection_row.coordinator_authority_marker_sha256,
            NULL,NULL,0,transaction_timestamp(),NULL,0,NULL,
            transaction_timestamp(),NULL
        );
        new_selection_version := selection_row.aggregate_version+1;
        UPDATE matching.selections
        SET aggregate_version=new_selection_version,
            updated_at=transaction_timestamp()
        WHERE id=selection_row.id AND status='OPEN'
          AND aggregate_version=selection_row.aggregate_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='PRECONDITION_FAILED';
        END IF;
        PERFORM matching.record_audit_v1(
            exact_audit_event_id,exact_actor_user_id,'CHOOSE_CREATOR',
            'Selection',selection_row.id,exact_organization_id,
            'OPEN','PENDING_CHOICE',selection_row.aggregate_version,
            new_selection_version,NULL,exact_command_id,
            exact_correlation_id,exact_trace_id,jsonb_build_object(
                'intent_id',exact_intent_id::text,
                'invitation_id',invitation_row.id::text,
                'candidate_selector_assignment_id',assignment_row.id::text)
        );
        PERFORM matching.record_outbox_v1(
            exact_primary_event_id,'SelectionIntentRecorded','Selection',
            selection_row.id,new_selection_version,exact_actor_user_id,
            exact_organization_id,exact_command_id,exact_correlation_id,
            exact_trace_id,jsonb_build_object(
                'selection_id',selection_row.id::text,
                'attempt_id',selection_row.attempt_id::text,
                'status','PENDING_CHOICE',
                'current_invitation_set_sha256',
                    encode(selection_row.current_invitation_set_sha256,'hex'),
                'chosen_invitation_id',invitation_row.id::text,
                'selection_basis_code',exact_selection_basis_code,
                'reason_code',NULL)
        );
        response_body := matching.selection_projection_v1(
            selection_row.id,assignment_row.id,
            assignment_row.assignment_version
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,new_selection_version,
            'PENDING_CHOICE',ARRAY['SelectionIntentRecorded']::text[]
        );
        RETURN QUERY SELECT response_body,false;
        RETURN;
    END IF;
    IF session_user IS DISTINCT FROM 'matching_selector'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_operation <> 'CLOSE_SELECTION'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_selection_id IS NULL
       OR exact_selector_assignment_id IS NULL
       OR expected_selection_version < 1
       OR expected_selector_assignment_version < 1
       OR octet_length(expected_invitation_set_sha256) <> 32
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR exact_invitation_id IS NOT NULL OR exact_intent_id IS NOT NULL
       OR exact_selection_basis_code IS NOT NULL
       OR exact_reason_code IS NULL
       OR exact_reason_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
       OR exact_secondary_event_id IS NULL
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text
       OR NULLIF(current_setting('app.selector_assignment_id', true), '')
            IS DISTINCT FROM exact_selector_assignment_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_selection_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    canonical_path := '/v1/organizations/' || exact_organization_id::text
        || '/selections/' || exact_selection_id::text || '/close';
    SELECT * INTO STRICT receipt_row
    FROM matching.claim_command_receipt_v1(
        exact_receipt_id,exact_actor_user_id,exact_organization_id,
        exact_operation,exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        expected_authority_marker_sha256,canonical_path,'Selection',
        exact_selection_id,expected_selection_version
    );
    IF receipt_row.replayed THEN
        RETURN QUERY SELECT receipt_row.safe_response, true;
        RETURN;
    END IF;

    SELECT assignment.* INTO assignment_row
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.id=exact_selector_assignment_id
    FOR UPDATE;
    IF NOT FOUND
       OR assignment_row.assignment_version
            <> expected_selector_assignment_version
       OR assignment_row.status <> 'ACTIVE'
       OR assignment_row.expires_at <= transaction_timestamp()
       OR assignment_row.assignee_user_id <> exact_actor_user_id
       OR assignment_row.assignee_session_id <> exact_session_id
       OR assignment_row.organization_id <> exact_organization_id
       OR assignment_row.selection_id <> exact_selection_id
       OR assignment_row.authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='SELECTOR_ASSIGNMENT_REQUIRED';
    END IF;
    SELECT selection.* INTO selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
    FOR UPDATE;
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
    FOR UPDATE;
    PERFORM set_config(
        'app.match_run_id',attempt_row.current_match_run_id::text,true
    );
    IF selection_row.status <> 'OPEN' OR attempt_row.status <> 'OPEN'
       OR assignment_row.demand_id <> attempt_row.demand_id
       OR selection_row.organization_id <> attempt_row.organization_id
       OR selection_row.aggregate_version <> expected_selection_version
       OR selection_row.current_invitation_set_sha256
            IS DISTINCT FROM expected_invitation_set_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=attempt_row.current_match_run_id;
    PERFORM invitation.id FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=attempt_row.current_match_run_id
    ORDER BY invitation.id FOR UPDATE;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,attempt_row.current_match_run_id
    );
    IF authoritative_set_sha256 IS DISTINCT FROM
            selection_row.current_invitation_set_sha256
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
              AND invitation.match_run_id=attempt_row.current_match_run_id
              AND invitation.status IN ('CREATED','SENT')
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;

    INSERT INTO matching.selection_close_intents (
        id,receipt_id,command_id,organization_id,selection_id,attempt_id,
        match_run_id,actor_user_id,candidate_selector_assignment_id,
        candidate_selector_assignment_version,
        candidate_selector_authority_marker_sha256,demand_id,
        demand_version_id,demand_aggregate_version,matching_request_id,
        matching_request_version,funding_id,current_invitation_set_sha256,
        reason_code,attempt_close_event_id,payload_hash_key_id,payload_hash,
        status,recorded_at
    ) VALUES (
        exact_primary_event_id,exact_receipt_id,exact_command_id,
        exact_organization_id,selection_row.id,attempt_row.id,run_row.id,
        exact_actor_user_id,assignment_row.id,assignment_row.assignment_version,
        assignment_row.authority_marker_sha256,attempt_row.demand_id,
        attempt_row.demand_version_id,attempt_row.demand_aggregate_version,
        attempt_row.matching_request_id,attempt_row.matching_request_version,
        attempt_row.funding_id,selection_row.current_invitation_set_sha256,
        exact_reason_code,exact_secondary_event_id,exact_payload_hash_key_id,
        exact_payload_hash,'READY',transaction_timestamp()
    );
    INSERT INTO matching.selection_completion_jobs (
        id,organization_id,selection_id,attempt_id,match_run_id,
        intent_receipt_id,intent_kind,status,workload_id,
        authority_marker_sha256,lease_digest_key_id,lease_digest,
        fencing_generation,available_at,lease_until,attempt_count,
        last_failure_code,created_at,completed_at
    ) VALUES (
        selection_row.id,exact_organization_id,selection_row.id,
        attempt_row.id,run_row.id,exact_receipt_id,'CLOSE','AVAILABLE',
        selection_row.coordinator_workload_id,
        selection_row.coordinator_authority_marker_sha256,
        NULL,NULL,0,transaction_timestamp(),NULL,0,NULL,
        transaction_timestamp(),NULL
    );
    new_selection_version := selection_row.aggregate_version+1;
    UPDATE matching.selections
    SET aggregate_version=new_selection_version,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id AND status='OPEN'
      AND aggregate_version=selection_row.aggregate_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    PERFORM matching.record_audit_v1(
        exact_audit_event_id,exact_actor_user_id,'CLOSE_SELECTION_INTENT',
        'Selection',selection_row.id,exact_organization_id,
        'OPEN','PENDING_CLOSE',selection_row.aggregate_version,
        new_selection_version,
        exact_reason_code,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'close_intent_id',exact_primary_event_id::text,
            'attempt_id',attempt_row.id::text,
            'candidate_selector_assignment_id',assignment_row.id::text)
    );
    PERFORM matching.record_outbox_v1(
        exact_primary_event_id,'SelectionCloseIntentRecorded','Selection',
        selection_row.id,new_selection_version,exact_actor_user_id,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',attempt_row.id::text,'status','PENDING_CLOSE',
            'current_invitation_set_sha256',
                encode(selection_row.current_invitation_set_sha256,'hex'),
            'chosen_invitation_id',NULL,
            'selection_basis_code',NULL,
            'reason_code',exact_reason_code)
    );
    response_body := matching.selection_projection_v1(
        selection_row.id,assignment_row.id,assignment_row.assignment_version
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_selection_version,'PENDING_CLOSE',
        ARRAY['SelectionCloseIntentRecorded']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.execute_candidate_selection_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,text,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.execute_candidate_selection_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,text,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) TO matching_selector;

CREATE FUNCTION matching_api.fail_match_run_v1(
    exact_workload_id uuid,
    exact_organization_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_job_id uuid,
    exact_match_run_id uuid,
    exact_fencing_generation bigint,
    exact_lease_token_digest_key_id text,
    exact_lease_token_digest bytea,
    exact_failure_code text,
    exact_retry_run_id uuid,
    exact_retry_job_id uuid,
    exact_retry_available_at timestamptz,
    exact_receipt_id uuid,
    exact_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    job_row matching.match_jobs%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    retry_requested boolean;
    next_run_no integer;
    invitation_set_sha256 bytea;
    response_body jsonb;
    event_payload jsonb;
    result_event_type text;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_worker','MATCHING_WORKER','FAIL_MATCH_RUN',
        exact_workload_id,exact_organization_id,
        exact_authority_marker_sha256,exact_command_id
    );
    retry_requested := exact_retry_run_id IS NOT NULL;
    IF exact_job_id IS NULL OR exact_match_run_id IS NULL
       OR exact_fencing_generation < 1
       OR exact_failure_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
       OR length(exact_lease_token_digest_key_id) NOT BETWEEN 1 AND 128
       OR octet_length(exact_lease_token_digest) <> 32
       OR retry_requested IS DISTINCT FROM (exact_retry_job_id IS NOT NULL)
       OR retry_requested IS DISTINCT FROM (exact_retry_available_at IS NOT NULL)
       OR NULLIF(current_setting('app.lease_token_digest_key_id', true), '')
            IS DISTINCT FROM exact_lease_token_digest_key_id
       OR NULLIF(current_setting('app.lease_token_digest', true), '')
            IS DISTINCT FROM encode(exact_lease_token_digest,'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,exact_organization_id,
        'FAIL_MATCH_RUN',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/runs/fail','MatchRun',exact_match_run_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;
    IF retry_requested
       AND exact_retry_available_at < transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    SELECT job.* INTO STRICT job_row
    FROM matching.match_jobs AS job
    WHERE job.id=exact_job_id AND job.organization_id=exact_organization_id
      AND job.match_run_id=exact_match_run_id
      AND job.workload_id=exact_workload_id
    FOR UPDATE;
    IF job_row.status <> 'LEASED'
       OR job_row.fencing_generation <> exact_fencing_generation
       OR job_row.lease_token_digest_key_id
            <> exact_lease_token_digest_key_id
       OR job_row.lease_token_digest <> exact_lease_token_digest
       OR job_row.lease_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=exact_match_run_id AND run.attempt_id=job_row.attempt_id
      AND run.organization_id=exact_organization_id
    FOR UPDATE;
    IF run_row.status <> 'RUNNING'
       OR run_row.fencing_generation <> exact_fencing_generation
       OR run_row.input_set_sha256 IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;
    IF retry_requested AND run_row.run_no >= 3 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='RETRY_LIMIT_EXHAUSTED';
    END IF;
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=run_row.attempt_id
    FOR UPDATE;
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
    FOR UPDATE;
    IF attempt_row.status <> 'OPEN' OR selection_row.status <> 'OPEN'
       OR attempt_row.current_match_run_id <> run_row.id
       OR selection_row.match_run_id <> run_row.id
       OR EXISTS (
            SELECT 1 FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='PRECONDITION_FAILED';
    END IF;

    UPDATE matching.match_runs
    SET status='FAILED',aggregate_version=aggregate_version+1,
        failure_code=exact_failure_code,
        superseded_by_run_id=exact_retry_run_id,
        updated_at=transaction_timestamp()
    WHERE id=run_row.id;
    UPDATE matching.match_jobs
    SET status='FAILED',completed_at=transaction_timestamp()
    WHERE id=job_row.id AND status='LEASED'
      AND fencing_generation=exact_fencing_generation;
    IF retry_requested THEN
        SELECT COALESCE(max(run.run_no),0)+1 INTO next_run_no
        FROM matching.match_runs AS run
        WHERE run.attempt_id=attempt_row.id;
        INSERT INTO matching.match_runs (
            id,organization_id,attempt_id,demand_id,run_no,status,
            aggregate_version,matching_rule_bundle_id,input_manifest_sha256,
            input_set_sha256,ordered_result_sha256,candidate_count,
            eligible_count,excluded_count,worker_id,
            lease_token_digest_key_id,lease_token_digest,
            fencing_generation,lease_until,supersedes_run_id,
            superseded_by_run_id,failure_code,created_at,updated_at
        ) VALUES (
            exact_retry_run_id,exact_organization_id,attempt_row.id,
            attempt_row.demand_id,next_run_no,'QUEUED',1,
            run_row.matching_rule_bundle_id,NULL,NULL,NULL,NULL,NULL,NULL,
            NULL,NULL,NULL,0,NULL,run_row.id,NULL,NULL,
            transaction_timestamp(),transaction_timestamp()
        );
        invitation_set_sha256 := matching.selection_invitation_set_sha256_v1(
            attempt_row.id,exact_retry_run_id
        );
        UPDATE matching.matching_attempts
        SET current_match_run_id=exact_retry_run_id,
            aggregate_version=aggregate_version+1,
            updated_at=transaction_timestamp()
        WHERE id=attempt_row.id;
        UPDATE matching.selections
        SET match_run_id=exact_retry_run_id,
            current_invitation_set_sha256=invitation_set_sha256,
            aggregate_version=aggregate_version+1,
            updated_at=transaction_timestamp()
        WHERE id=selection_row.id;
        INSERT INTO matching.match_jobs (
            id,organization_id,attempt_id,match_run_id,job_kind,status,
            workload_id,authority_marker_sha256,lease_token_digest_key_id,
            lease_token_digest,fencing_generation,available_at,lease_until,
            attempt_count,created_at,completed_at
        ) VALUES (
            exact_retry_job_id,exact_organization_id,attempt_row.id,
            exact_retry_run_id,'RUN_MATCH','AVAILABLE',exact_workload_id,
            exact_authority_marker_sha256,NULL,NULL,0,
            exact_retry_available_at,NULL,0,transaction_timestamp(),NULL
        );
        result_event_type := 'MatchRunRetryScheduled';
        response_body := jsonb_build_object(
            'failed_match_run_id',run_row.id::text,
            'match_run_id',exact_retry_run_id::text,
            'job_id',exact_retry_job_id::text,'status','QUEUED',
            'aggregate_version',1,'failure_code',exact_failure_code,
            'available_at',exact_retry_available_at
        );
        event_payload := jsonb_build_object(
            'failed_run_id',run_row.id::text,
            'failed_run_version',run_row.aggregate_version+1,
            'successor_run_id',exact_retry_run_id::text,
            'successor_job_id',exact_retry_job_id::text,
            'attempt_id',run_row.attempt_id::text,
            'failure_code',exact_failure_code,
            'status','QUEUED'
        );
    ELSE
        result_event_type := 'MatchRunFailed';
        response_body := jsonb_build_object(
            'match_run_id',run_row.id::text,'job_id',job_row.id::text,
            'status','FAILED',
            'aggregate_version',run_row.aggregate_version+1,
            'failure_code',exact_failure_code
        );
        event_payload := jsonb_build_object(
            'run_id',run_row.id::text,
            'attempt_id',run_row.attempt_id::text,
            'run_no',run_row.run_no,
            'rule_bundle_id',run_row.matching_rule_bundle_id::text,
            'input_set_sha256',encode(run_row.input_set_sha256,'hex'),
            'status','FAILED','candidate_count',NULL,
            'eligible_count',NULL,'excluded_count',NULL,
            'ordered_result_sha256',NULL,
            'failure_code',exact_failure_code,'successor_run_id',NULL
        );
    END IF;
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'FAIL_MATCH_RUN','MatchRun',run_row.id,exact_organization_id,
        'RUNNING','FAILED',run_row.aggregate_version,
        run_row.aggregate_version+1,exact_failure_code,exact_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('job_id',job_row.id::text,
            'fencing_generation',exact_fencing_generation,
            'retry_run_id',exact_retry_run_id::text)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,result_event_type,'MatchRun',run_row.id,
        run_row.aggregate_version+1,'SYSTEM',exact_workload_id,NULL,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,event_payload
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,run_row.aggregate_version+1,
        CASE WHEN retry_requested THEN 'QUEUED' ELSE 'FAILED' END,
        ARRAY[result_event_type]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.fail_match_run_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,text,uuid,uuid,timestamptz,
    uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.fail_match_run_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,text,uuid,uuid,timestamptz,
    uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_worker;

-- Discover one pending selector intent without a caller-supplied organization
-- or selection.  The queue row itself carries the reviewed coordinator
-- workload and marker; RLS makes all other work invisible.  Expired leases are
-- fenced on reclaim and a third expired lease is terminalized deterministically.
CREATE FUNCTION matching_api.claim_selection_completion_v1(
    exact_workload_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_claim_command_id uuid,
    exact_receipt_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_lease_digest_key_id text,
    exact_lease_digest bytea,
    exact_lease_seconds integer,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_claim jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    prior_receipt matching.command_receipts%ROWTYPE;
    receipt_result record;
    job_row matching.selection_completion_jobs%ROWTYPE;
    response_body jsonb;
    old_fence bigint;
    old_status text;
    new_fence bigint;
    new_attempt_count integer;
    result_status text;
    result_event_type text;
    event_payload jsonb;
    completion_actor_user_id uuid;
    completion_demand_id uuid;
    completion_demand_version bigint;
    completion_demand_version_id uuid;
    completion_demand_content_sha256 bytea;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_coordinator'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_workload_id IS NULL
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR exact_claim_command_id IS NULL OR exact_receipt_id IS NULL
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR octet_length(exact_lease_digest) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR exact_lease_digest_key_id IN (
            exact_identity_key_id, exact_payload_hash_key_id
       )
       OR exact_lease_seconds NOT BETWEEN 15 AND 300
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_COORDINATOR_CLAIM'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_SELECTION_COMPLETION'
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM exact_workload_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_claim_command_id::text
       OR COALESCE(current_setting('app.organization_id', true), '') <> ''
       OR COALESCE(current_setting('app.selection_id', true), '') <> ''
       OR COALESCE(current_setting('app.target_id', true), '') <> ''
       OR COALESCE(current_setting('app.actor_user_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    -- Recover the frozen safe claim before consulting mutable queue state.
    SELECT receipt.* INTO prior_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind='SYSTEM'
      AND receipt.principal_id=exact_workload_id
      AND receipt.operation='CLAIM_SELECTION_COMPLETION'
      AND receipt.command_version=1
      AND receipt.identity_key_id=exact_identity_key_id
      AND receipt.identity_digest=exact_identity_digest;
    IF FOUND THEN
        IF prior_receipt.payload_hash_key_id <> exact_payload_hash_key_id
           OR prior_receipt.payload_hash <> exact_payload_hash
           OR prior_receipt.principal_authority_marker_sha256
                <> exact_authority_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF prior_receipt.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='COMMAND_OUTCOME_UNKNOWN';
        END IF;
        RETURN QUERY SELECT prior_receipt.safe_response_body,true;
        RETURN;
    END IF;

    SELECT job.* INTO job_row
    FROM matching.selection_completion_jobs AS job
    WHERE job.workload_id=exact_workload_id
      AND job.authority_marker_sha256=exact_authority_marker_sha256
      AND (
        (job.status='AVAILABLE'
         AND job.available_at <= transaction_timestamp())
        OR
        (job.status='LEASED'
         AND job.lease_until <= transaction_timestamp())
      )
    ORDER BY job.available_at,job.created_at,job.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM set_config('app.organization_id',job_row.organization_id::text,true);
    PERFORM set_config('app.selection_id',job_row.selection_id::text,true);
    PERFORM set_config('app.target_id',job_row.id::text,true);
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,
        job_row.organization_id,'CLAIM_SELECTION_COMPLETION',
        exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/selection-completions/claim',
        'SelectionCompletionJob',job_row.id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;

    old_fence := job_row.fencing_generation;
    old_status := job_row.status;
    new_fence := old_fence + 1;
    IF job_row.status='LEASED' AND job_row.attempt_count >= 3 THEN
        UPDATE matching.selection_completion_jobs
        SET status='FAILED',fencing_generation=new_fence,
            last_failure_code='LEASE_EXHAUSTED',
            completed_at=transaction_timestamp()
        WHERE id=job_row.id AND status='LEASED'
          AND fencing_generation=old_fence;
        result_status := 'FAILED';
        result_event_type := 'SelectionCompletionFailed';
        new_attempt_count := job_row.attempt_count;
    ELSE
        new_attempt_count := job_row.attempt_count + 1;
        UPDATE matching.selection_completion_jobs
        SET status='LEASED',lease_digest_key_id=exact_lease_digest_key_id,
            lease_digest=exact_lease_digest,fencing_generation=new_fence,
            lease_until=transaction_timestamp()
                + make_interval(secs => exact_lease_seconds),
            attempt_count=new_attempt_count,last_failure_code=NULL
        WHERE id=job_row.id
          AND fencing_generation=old_fence;
        result_status := 'LEASED';
        result_event_type := 'SelectionCompletionClaimed';
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='COMMAND_OUTCOME_UNKNOWN';
    END IF;

    SELECT job.* INTO STRICT job_row
    FROM matching.selection_completion_jobs AS job
    WHERE job.id=job_row.id;
    SELECT
        COALESCE(
            choice.actor_user_id,
            closing.actor_user_id,
            system_closing.original_actor_user_id
        ),
        attempt.demand_id,
        attempt.demand_aggregate_version,
        attempt.demand_version_id,
        attempt.demand_content_sha256
    INTO STRICT completion_actor_user_id,completion_demand_id,
        completion_demand_version,completion_demand_version_id,
        completion_demand_content_sha256
    FROM matching.matching_attempts AS attempt
    LEFT JOIN matching.selection_intents AS choice
      ON choice.selection_id=job_row.selection_id
     AND job_row.intent_kind='CHOOSE'
    LEFT JOIN matching.selection_close_intents AS closing
      ON closing.selection_id=job_row.selection_id
     AND job_row.intent_kind='CLOSE'
    LEFT JOIN matching.selection_system_close_intents AS system_closing
      ON system_closing.selection_id=job_row.selection_id
     AND job_row.intent_kind='SYSTEM_CLOSE'
    WHERE attempt.id=job_row.attempt_id
      AND attempt.organization_id=job_row.organization_id
      AND (
        (job_row.intent_kind='CHOOSE' AND choice.id IS NOT NULL
            AND closing.id IS NULL AND system_closing.id IS NULL)
        OR
        (job_row.intent_kind='CLOSE' AND closing.id IS NOT NULL
            AND choice.id IS NULL AND system_closing.id IS NULL)
        OR
        (job_row.intent_kind='SYSTEM_CLOSE'
            AND system_closing.id IS NOT NULL
            AND choice.id IS NULL AND closing.id IS NULL)
      );
    response_body := jsonb_build_object(
        'completion_job_id',job_row.id::text,
        'organization_id',job_row.organization_id::text,
        'selection_id',job_row.selection_id::text,
        'attempt_id',job_row.attempt_id::text,
        'match_run_id',job_row.match_run_id::text,
        'intent_receipt_id',job_row.intent_receipt_id::text,
        'intent_kind',job_row.intent_kind,
        'status',result_status,
        'fencing_generation',new_fence,
        'attempt_count',new_attempt_count,
        'lease_until',job_row.lease_until,
        'failure_code',job_row.last_failure_code,
        'original_actor_user_id',completion_actor_user_id::text,
        'demand_id',completion_demand_id::text,
        'prospective_demand_version',completion_demand_version+1,
        'demand_version_id',completion_demand_version_id::text,
        'demand_content_sha256',encode(
            completion_demand_content_sha256,'hex'
        )
    );
    event_payload := jsonb_build_object(
        'completion_job_id',job_row.id::text,
        'selection_id',job_row.selection_id::text,
        'intent_kind',job_row.intent_kind,'status',result_status,
        'fencing_generation',new_fence,
        'attempt_count',new_attempt_count,
        'failure_code',job_row.last_failure_code
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'CLAIM_SELECTION_COMPLETION','SelectionCompletionJob',job_row.id,
        job_row.organization_id,
        old_status,result_status,old_fence,new_fence,
        job_row.last_failure_code,exact_claim_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('selection_id',job_row.selection_id::text,
            'intent_kind',job_row.intent_kind,
            'attempt_count',new_attempt_count)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,result_event_type,'SelectionCompletionJob',
        job_row.id,new_fence,'SYSTEM',exact_workload_id,NULL,
        job_row.organization_id,exact_claim_command_id,
        exact_correlation_id,exact_trace_id,event_payload
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,GREATEST(new_fence,1),result_status,
        ARRAY[result_event_type]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.claim_selection_completion_v1(
    uuid,bytea,uuid,uuid,text,bytea,text,bytea,text,bytea,integer,
    uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.claim_selection_completion_v1(
    uuid,bytea,uuid,uuid,text,bytea,text,bytea,text,bytea,integer,
    uuid,uuid,uuid,uuid
) TO matching_coordinator;

CREATE FUNCTION matching_api.complete_selection_v1(
    exact_coordinator_workload_id uuid,
    exact_organization_id uuid,
    exact_coordinator_authority_marker_sha256 bytea,
    exact_selection_id uuid,
    exact_trust_evidence_sha256 bytea,
    exact_trust_evaluated_at timestamptz,
    exact_trust_valid_until timestamptz,
    exact_receipt_id uuid,
    exact_completion_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_selection_event_id uuid,
    exact_attempt_event_id uuid,
    exact_demand_matched_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    intent_row matching.selection_intents%ROWTYPE;
    choose_receipt matching.command_receipts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    invitation_row matching.invitations%ROWTYPE;
    assignment_row matching.candidate_selector_assignments%ROWTYPE;
    demand_result record;
    authoritative_set_sha256 bytea;
    response_body jsonb;
    new_selection_version bigint;
    new_attempt_version bigint;
    new_assignment_version bigint;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_coordinator','MATCHING_COORDINATOR','COMPLETE_SELECTION',
        exact_coordinator_workload_id,exact_organization_id,
        exact_coordinator_authority_marker_sha256,
        exact_completion_command_id
    );
    IF exact_selection_id IS NULL
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_coordinator_workload_id,
        exact_organization_id,'COMPLETE_SELECTION',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        exact_coordinator_authority_marker_sha256,
        '/v1/internal/matching/selections/complete','Selection',
        exact_selection_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;
    -- Trust freshness gates only a new completion.  Exact completed receipt
    -- recovery must remain available after the short evidence window closes.
    IF octet_length(exact_trust_evidence_sha256) <> 32
       OR exact_trust_evaluated_at > transaction_timestamp()
       OR exact_trust_valid_until <= transaction_timestamp()
       OR exact_trust_valid_until <= exact_trust_evaluated_at
       OR exact_trust_valid_until-exact_trust_evaluated_at
            > interval '15 seconds' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SAFETY_HOLD_BLOCKED';
    END IF;

    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
      AND selection.organization_id=exact_organization_id;
    IF selection_row.coordinator_workload_id
            <> exact_coordinator_workload_id
       OR selection_row.coordinator_authority_marker_sha256
            <> exact_coordinator_authority_marker_sha256
       OR selection_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
      AND attempt.organization_id=exact_organization_id;
    SELECT intent.* INTO STRICT intent_row
    FROM matching.selection_intents AS intent
    WHERE intent.selection_id=selection_row.id;
    SELECT receipt.* INTO STRICT choose_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.id=intent_row.receipt_id;
    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.id=intent_row.candidate_selector_assignment_id
      AND assignment.selection_id=selection_row.id;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=intent_row.match_run_id
      AND run.attempt_id=attempt_row.id;
    SELECT invitation.* INTO STRICT invitation_row
    FROM matching.invitations AS invitation
    WHERE invitation.id=intent_row.invitation_id
      AND invitation.attempt_id=attempt_row.id;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.selection_id <> selection_row.id
       OR attempt_row.current_match_run_id <> run_row.id
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR invitation_row.status <> 'ACCEPTED'
       OR invitation_row.match_run_id <> run_row.id
       OR NOT (
            (assignment_row.status = 'ACTIVE'
             AND assignment_row.assignment_version
                = intent_row.candidate_selector_assignment_version)
            OR
            (assignment_row.status = 'EXPIRED'
             AND assignment_row.assignment_version
                = intent_row.candidate_selector_assignment_version + 1
             AND assignment_row.completed_at IS NOT NULL
             AND assignment_row.completed_at >= assignment_row.expires_at)
       )
       OR assignment_row.assigned_at > intent_row.recorded_at
       OR assignment_row.expires_at <= intent_row.recorded_at
       OR assignment_row.assignee_user_id <> intent_row.actor_user_id
       OR assignment_row.authority_marker_sha256
            <> intent_row.candidate_selector_authority_marker_sha256
       OR assignment_row.demand_id <> attempt_row.demand_id
       OR intent_row.organization_id <> exact_organization_id
       OR intent_row.demand_id <> attempt_row.demand_id
       OR intent_row.demand_version_id <> attempt_row.demand_version_id
       OR intent_row.matching_request_id <> attempt_row.matching_request_id
       OR intent_row.matching_request_version
            <> attempt_row.matching_request_version
       OR intent_row.funding_id <> attempt_row.funding_id
       OR intent_row.matching_rule_bundle_id
            <> run_row.matching_rule_bundle_id
       OR intent_row.input_set_sha256 <> run_row.input_set_sha256
       OR intent_row.ordered_result_sha256 <> run_row.ordered_result_sha256
       OR intent_row.current_invitation_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR authoritative_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR choose_receipt.status <> 'COMPLETED'
       OR choose_receipt.operation <> 'CHOOSE_CREATOR'
       OR choose_receipt.principal_id <> intent_row.actor_user_id
       OR EXISTS (
            SELECT 1
            FROM matching.candidate_selector_assignments AS other_assignment
            WHERE other_assignment.selection_id=selection_row.id
              AND other_assignment.id<>assignment_row.id
              AND other_assignment.status='ACTIVE'
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS close_intent
            WHERE close_intent.selection_id=selection_row.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;

    -- Demand15 executes as a nested fixed program in this same transaction.
    -- A failure rolls back both contexts.  session_user remains the exact
    -- matching_coordinator while current_user switches inside Demand.
    PERFORM set_config('app.scope_kind','DEMAND_MATCHING_COORDINATOR',true);
    PERFORM set_config('app.actor_user_id',intent_row.actor_user_id::text,true);
    PERFORM set_config('app.demand_id',attempt_row.demand_id::text,true);
    SELECT * INTO STRICT demand_result
    FROM demand_api.execute_complete_selection_system_v1(
        exact_completion_command_id,intent_row.receipt_id,selection_row.id,
        attempt_row.id,invitation_row.id,run_row.id,exact_organization_id,
        attempt_row.demand_id,attempt_row.demand_aggregate_version,
        attempt_row.demand_version_id,attempt_row.matching_request_id,
        attempt_row.matching_request_version,attempt_row.funding_id,
        intent_row.actor_user_id,exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_demand_matched_event_id,exact_correlation_id,exact_trace_id
    );
    PERFORM set_config('app.scope_kind','MATCHING_COORDINATOR',true);
    PERFORM set_config('app.actor_user_id','',true);
    PERFORM set_config('app.selection_id',selection_row.id::text,true);

    -- Demand owns the cross-context lock order.  Only after its fixed program
    -- succeeds do we lock and revalidate every mutable Matching fact.  Any
    -- drift aborts this transaction and therefore the nested Demand change.
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
      AND selection.organization_id=exact_organization_id
    FOR UPDATE;
    IF selection_row.coordinator_workload_id
            <> exact_coordinator_workload_id
       OR selection_row.coordinator_authority_marker_sha256
            <> exact_coordinator_authority_marker_sha256
       OR selection_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT intent.* INTO STRICT intent_row
    FROM matching.selection_intents AS intent
    WHERE intent.selection_id=selection_row.id;
    SELECT receipt.* INTO STRICT choose_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.id=intent_row.receipt_id;
    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.id=intent_row.candidate_selector_assignment_id
      AND assignment.selection_id=selection_row.id
    FOR UPDATE;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=intent_row.match_run_id
      AND run.attempt_id=attempt_row.id
    FOR UPDATE;
    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=run_row.id
    ORDER BY invitation.id
    FOR SHARE;
    SELECT invitation.* INTO STRICT invitation_row
    FROM matching.invitations AS invitation
    WHERE invitation.id=intent_row.invitation_id
      AND invitation.attempt_id=attempt_row.id;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.selection_id <> selection_row.id
       OR attempt_row.current_match_run_id <> run_row.id
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR invitation_row.status <> 'ACCEPTED'
       OR invitation_row.match_run_id <> run_row.id
       OR NOT (
            (assignment_row.status = 'ACTIVE'
             AND assignment_row.assignment_version
                = intent_row.candidate_selector_assignment_version)
            OR
            (assignment_row.status = 'EXPIRED'
             AND assignment_row.assignment_version
                = intent_row.candidate_selector_assignment_version + 1
             AND assignment_row.completed_at IS NOT NULL
             AND assignment_row.completed_at >= assignment_row.expires_at)
       )
       OR assignment_row.assigned_at > intent_row.recorded_at
       OR assignment_row.expires_at <= intent_row.recorded_at
       OR assignment_row.assignee_user_id <> intent_row.actor_user_id
       OR assignment_row.authority_marker_sha256
            <> intent_row.candidate_selector_authority_marker_sha256
       OR assignment_row.demand_id <> attempt_row.demand_id
       OR intent_row.organization_id <> exact_organization_id
       OR intent_row.demand_id <> attempt_row.demand_id
       OR intent_row.demand_version_id <> attempt_row.demand_version_id
       OR intent_row.matching_request_id <> attempt_row.matching_request_id
       OR intent_row.matching_request_version
            <> attempt_row.matching_request_version
       OR intent_row.funding_id <> attempt_row.funding_id
       OR intent_row.matching_rule_bundle_id
            <> run_row.matching_rule_bundle_id
       OR intent_row.input_set_sha256 <> run_row.input_set_sha256
       OR intent_row.ordered_result_sha256 <> run_row.ordered_result_sha256
       OR intent_row.current_invitation_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR authoritative_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR choose_receipt.status <> 'COMPLETED'
       OR choose_receipt.operation <> 'CHOOSE_CREATOR'
       OR choose_receipt.principal_id <> intent_row.actor_user_id
       OR EXISTS (
            SELECT 1
            FROM matching.candidate_selector_assignments AS other_assignment
            WHERE other_assignment.selection_id=selection_row.id
              AND other_assignment.id<>assignment_row.id
              AND other_assignment.status='ACTIVE'
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS close_intent
            WHERE close_intent.selection_id=selection_row.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;
    IF demand_result.demand_id <> attempt_row.demand_id
       OR demand_result.demand_version
            <> attempt_row.demand_aggregate_version+1
       OR demand_result.matching_request_version
            <> attempt_row.matching_request_version+1
       OR demand_result.demand_status <> 'MATCHED'
       OR demand_result.matching_request_status <> 'CLOSED' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;

    new_selection_version := selection_row.aggregate_version+1;
    new_attempt_version := attempt_row.aggregate_version+1;
    new_assignment_version := assignment_row.assignment_version+1;
    UPDATE matching.selections
    SET status='SELECTED',aggregate_version=new_selection_version,
        chosen_invitation_id=invitation_row.id,
        chosen_invitation_status='ACCEPTED',
        selection_basis_code=intent_row.selection_basis_code,
        decision_actor_id=intent_row.actor_user_id,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id;
    UPDATE matching.matching_attempts
    SET status='SELECTED',aggregate_version=new_attempt_version,
        updated_at=transaction_timestamp(),terminal_at=transaction_timestamp()
    WHERE id=attempt_row.id;
    UPDATE matching.candidate_selector_assignments
    SET status='COMPLETED',assignment_version=new_assignment_version,
        completed_at=transaction_timestamp()
    WHERE id=assignment_row.id;
    INSERT INTO matching.complete_selection_records (
        choose_receipt_id,completion_command_id,organization_id,selection_id,
        attempt_id,invitation_id,match_run_id,demand_id,
        expected_demand_version,completed_demand_version,
        matching_request_id,expected_matching_request_version,
        completed_matching_request_version,funding_id,
        candidate_selector_assignment_id,
        candidate_selector_assignment_version,original_actor_user_id,
        coordinator_workload_id,coordinator_authority_marker_sha256,
        trust_evidence_sha256,trust_evaluated_at,trust_valid_until,
        demand_matched_event_id,matching_event_ids,status,completed_at
    ) VALUES (
        intent_row.receipt_id,exact_completion_command_id,
        exact_organization_id,selection_row.id,attempt_row.id,
        invitation_row.id,run_row.id,attempt_row.demand_id,
        attempt_row.demand_aggregate_version,
        demand_result.demand_version,attempt_row.matching_request_id,
        attempt_row.matching_request_version,
        demand_result.matching_request_version,attempt_row.funding_id,
        assignment_row.id,assignment_row.assignment_version,
        intent_row.actor_user_id,exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        exact_trust_evidence_sha256,exact_trust_evaluated_at,
        exact_trust_valid_until,exact_demand_matched_event_id,
        ARRAY[exact_selection_event_id,exact_attempt_event_id],
        'COMPLETED',transaction_timestamp()
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_coordinator_workload_id,
        intent_row.actor_user_id,'COMPLETE_SELECTION','Selection',
        selection_row.id,exact_organization_id,'PENDING_CHOICE','SELECTED',
        selection_row.aggregate_version,new_selection_version,NULL,
        exact_completion_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('attempt_id',attempt_row.id::text,
            'invitation_id',invitation_row.id::text,
            'candidate_selector_assignment_id',assignment_row.id::text,
            'trust_evidence_sha256',encode(exact_trust_evidence_sha256,'hex'))
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_selection_event_id,'SelectionMade','Selection',selection_row.id,
        new_selection_version,'SYSTEM',exact_coordinator_workload_id,
        intent_row.actor_user_id,exact_organization_id,
        exact_completion_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('selection_id',selection_row.id::text,
            'attempt_id',attempt_row.id::text,'status','SELECTED',
            'current_invitation_set_sha256',
                encode(selection_row.current_invitation_set_sha256,'hex'),
            'chosen_invitation_id',invitation_row.id::text,
            'selection_basis_code',intent_row.selection_basis_code,
            'reason_code',NULL)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_attempt_event_id,'MatchingAttemptSelected','MatchingAttempt',
        attempt_row.id,new_attempt_version,'SYSTEM',
        exact_coordinator_workload_id,intent_row.actor_user_id,
        exact_organization_id,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'attempt_id',attempt_row.id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'attempt_no',attempt_row.attempt_no,'status','SELECTED',
            'reason_code',NULL,'selection_id',selection_row.id::text,
            'chosen_invitation_id',invitation_row.id::text)
    );
    response_body := matching.selection_projection_v1(
        selection_row.id,assignment_row.id,new_assignment_version
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_selection_version,'SELECTED',
        ARRAY['SelectionMade','MatchingAttemptSelected']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.complete_selection_v1(
    uuid,uuid,bytea,uuid,bytea,timestamptz,timestamptz,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.complete_selection_v1(
    uuid,uuid,bytea,uuid,bytea,timestamptz,timestamptz,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,uuid
) TO matching_coordinator;

CREATE FUNCTION matching_api.complete_selection_close_v1(
    exact_coordinator_workload_id uuid,
    exact_organization_id uuid,
    exact_coordinator_authority_marker_sha256 bytea,
    exact_selection_id uuid,
    exact_receipt_id uuid,
    exact_completion_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_selection_closed_event_id uuid,
    exact_demand_closed_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    close_intent matching.selection_close_intents%ROWTYPE;
    close_receipt matching.command_receipts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    assignment_row matching.candidate_selector_assignments%ROWTYPE;
    demand_result record;
    authoritative_set_sha256 bytea;
    new_selection_version bigint;
    new_attempt_version bigint;
    new_assignment_version bigint;
    response_body jsonb;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_coordinator','MATCHING_COORDINATOR','COMPLETE_SELECTION',
        exact_coordinator_workload_id,exact_organization_id,
        exact_coordinator_authority_marker_sha256,
        exact_completion_command_id
    );
    IF exact_selection_id IS NULL
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_coordinator_workload_id,
        exact_organization_id,'COMPLETE_SELECTION',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        exact_coordinator_authority_marker_sha256,
        '/v1/internal/matching/selections/complete-close','Selection',
        exact_selection_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response, true;
        RETURN;
    END IF;
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
      AND selection.organization_id=exact_organization_id;
    IF selection_row.coordinator_workload_id
            <> exact_coordinator_workload_id
       OR selection_row.coordinator_authority_marker_sha256
            <> exact_coordinator_authority_marker_sha256
       OR selection_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id;
    SELECT intent.* INTO STRICT close_intent
    FROM matching.selection_close_intents AS intent
    WHERE intent.selection_id=selection_row.id;
    SELECT receipt.* INTO STRICT close_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.id=close_intent.receipt_id;
    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.id=close_intent.candidate_selector_assignment_id
      AND assignment.selection_id=selection_row.id;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=close_intent.match_run_id
      AND run.attempt_id=attempt_row.id;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.current_match_run_id <> run_row.id
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR NOT (
            (assignment_row.status = 'ACTIVE'
             AND assignment_row.assignment_version
                = close_intent.candidate_selector_assignment_version)
            OR
            (assignment_row.status = 'EXPIRED'
             AND assignment_row.assignment_version
                = close_intent.candidate_selector_assignment_version + 1
             AND assignment_row.completed_at IS NOT NULL
             AND assignment_row.completed_at >= assignment_row.expires_at)
       )
       OR assignment_row.assigned_at > close_intent.recorded_at
       OR assignment_row.expires_at <= close_intent.recorded_at
       OR assignment_row.assignee_user_id <> close_intent.actor_user_id
       OR assignment_row.authority_marker_sha256
            <> close_intent.candidate_selector_authority_marker_sha256
       OR close_intent.organization_id <> exact_organization_id
       OR close_intent.demand_id <> attempt_row.demand_id
       OR close_intent.demand_version_id <> attempt_row.demand_version_id
       OR close_intent.demand_aggregate_version
            <> attempt_row.demand_aggregate_version
       OR close_intent.matching_request_id <> attempt_row.matching_request_id
       OR close_intent.matching_request_version
            <> attempt_row.matching_request_version
       OR close_intent.funding_id <> attempt_row.funding_id
       OR close_intent.current_invitation_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR authoritative_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR close_receipt.status <> 'COMPLETED'
       OR close_receipt.operation <> 'CLOSE_SELECTION'
       OR close_receipt.principal_id <> close_intent.actor_user_id
       OR EXISTS (
            SELECT 1
            FROM matching.candidate_selector_assignments AS other_assignment
            WHERE other_assignment.selection_id=selection_row.id
              AND other_assignment.id<>assignment_row.id
              AND other_assignment.status='ACTIVE'
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;

    PERFORM set_config('app.scope_kind','DEMAND_MATCHING_COORDINATOR',true);
    PERFORM set_config(
        'app.actor_user_id',close_intent.actor_user_id::text,true
    );
    PERFORM set_config('app.demand_id',attempt_row.demand_id::text,true);
    SELECT * INTO STRICT demand_result
    FROM demand_api.execute_close_matching_without_selection_system_v1(
        exact_completion_command_id,close_intent.receipt_id,
        selection_row.id,attempt_row.id,run_row.id,exact_organization_id,
        attempt_row.demand_id,attempt_row.demand_aggregate_version,
        attempt_row.demand_version_id,attempt_row.matching_request_id,
        attempt_row.matching_request_version,attempt_row.funding_id,
        close_intent.actor_user_id,exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_demand_closed_event_id,exact_correlation_id,exact_trace_id,
        close_intent.reason_code
    );
    PERFORM set_config('app.scope_kind','MATCHING_COORDINATOR',true);
    PERFORM set_config('app.actor_user_id','',true);
    PERFORM set_config('app.selection_id',selection_row.id::text,true);
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
      AND selection.organization_id=exact_organization_id
    FOR UPDATE;
    IF selection_row.coordinator_workload_id
            <> exact_coordinator_workload_id
       OR selection_row.coordinator_authority_marker_sha256
            <> exact_coordinator_authority_marker_sha256
       OR selection_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT intent.* INTO STRICT close_intent
    FROM matching.selection_close_intents AS intent
    WHERE intent.selection_id=selection_row.id;
    SELECT receipt.* INTO STRICT close_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.id=close_intent.receipt_id;
    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.id=close_intent.candidate_selector_assignment_id
      AND assignment.selection_id=selection_row.id
    FOR UPDATE;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=close_intent.match_run_id
      AND run.attempt_id=attempt_row.id
    FOR UPDATE;
    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=run_row.id
    ORDER BY invitation.id
    FOR SHARE;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.selection_id <> selection_row.id
       OR attempt_row.current_match_run_id <> run_row.id
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR NOT (
            (assignment_row.status = 'ACTIVE'
             AND assignment_row.assignment_version
                = close_intent.candidate_selector_assignment_version)
            OR
            (assignment_row.status = 'EXPIRED'
             AND assignment_row.assignment_version
                = close_intent.candidate_selector_assignment_version + 1
             AND assignment_row.completed_at IS NOT NULL
             AND assignment_row.completed_at >= assignment_row.expires_at)
       )
       OR assignment_row.assigned_at > close_intent.recorded_at
       OR assignment_row.expires_at <= close_intent.recorded_at
       OR assignment_row.assignee_user_id <> close_intent.actor_user_id
       OR assignment_row.authority_marker_sha256
            <> close_intent.candidate_selector_authority_marker_sha256
       OR close_intent.organization_id <> exact_organization_id
       OR close_intent.demand_id <> attempt_row.demand_id
       OR close_intent.demand_version_id <> attempt_row.demand_version_id
       OR close_intent.demand_aggregate_version
            <> attempt_row.demand_aggregate_version
       OR close_intent.matching_request_id <> attempt_row.matching_request_id
       OR close_intent.matching_request_version
            <> attempt_row.matching_request_version
       OR close_intent.funding_id <> attempt_row.funding_id
       OR close_intent.current_invitation_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR authoritative_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR close_receipt.status <> 'COMPLETED'
       OR close_receipt.operation <> 'CLOSE_SELECTION'
       OR close_receipt.principal_id <> close_intent.actor_user_id
       OR EXISTS (
            SELECT 1
            FROM matching.candidate_selector_assignments AS other_assignment
            WHERE other_assignment.selection_id=selection_row.id
              AND other_assignment.id<>assignment_row.id
              AND other_assignment.status='ACTIVE'
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;
    IF demand_result.demand_id <> attempt_row.demand_id
       OR demand_result.demand_version
            <> attempt_row.demand_aggregate_version+1
       OR demand_result.matching_request_version
            <> attempt_row.matching_request_version+1
       OR demand_result.demand_status <> 'NO_MATCH'
       OR demand_result.matching_request_status <> 'CLOSED' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    new_selection_version := selection_row.aggregate_version+1;
    new_attempt_version := attempt_row.aggregate_version+1;
    new_assignment_version := assignment_row.assignment_version+1;
    UPDATE matching.selections
    SET status='CLOSED_NO_SELECTION',aggregate_version=new_selection_version,
        reason_code=close_intent.reason_code,
        decision_actor_id=close_intent.actor_user_id,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id;
    UPDATE matching.matching_attempts
    SET status='CLOSED_NO_SELECTION',aggregate_version=new_attempt_version,
        updated_at=transaction_timestamp(),terminal_at=transaction_timestamp()
    WHERE id=attempt_row.id;
    UPDATE matching.candidate_selector_assignments
    SET status='COMPLETED',assignment_version=new_assignment_version,
        completed_at=transaction_timestamp()
    WHERE id=assignment_row.id;
    INSERT INTO matching.complete_selection_close_records (
        close_receipt_id,completion_command_id,organization_id,selection_id,
        attempt_id,match_run_id,demand_id,expected_demand_version,
        completed_demand_version,matching_request_id,
        expected_matching_request_version,completed_matching_request_version,
        funding_id,candidate_selector_assignment_id,
        candidate_selector_assignment_version,original_actor_user_id,
        coordinator_workload_id,coordinator_authority_marker_sha256,
        reason_code,demand_closed_event_id,matching_event_ids,status,
        completed_at
    ) VALUES (
        close_intent.receipt_id,exact_completion_command_id,
        exact_organization_id,selection_row.id,attempt_row.id,run_row.id,
        attempt_row.demand_id,attempt_row.demand_aggregate_version,
        demand_result.demand_version,attempt_row.matching_request_id,
        attempt_row.matching_request_version,
        demand_result.matching_request_version,attempt_row.funding_id,
        assignment_row.id,assignment_row.assignment_version,
        close_intent.actor_user_id,exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,close_intent.reason_code,
        exact_demand_closed_event_id,
        ARRAY[exact_selection_closed_event_id,
            close_intent.attempt_close_event_id],
        'COMPLETED',transaction_timestamp()
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_coordinator_workload_id,
        close_intent.actor_user_id,'COMPLETE_SELECTION','Selection',
        selection_row.id,exact_organization_id,
        'PENDING_CLOSE','CLOSED_NO_SELECTION',
        selection_row.aggregate_version,new_selection_version,
        close_intent.reason_code,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('attempt_id',attempt_row.id::text,
            'close_intent_id',close_intent.id::text,
            'candidate_selector_assignment_id',assignment_row.id::text)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_selection_closed_event_id,'SelectionClosedWithoutChoice',
        'Selection',selection_row.id,new_selection_version,'SYSTEM',
        exact_coordinator_workload_id,close_intent.actor_user_id,
        exact_organization_id,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',attempt_row.id::text,'status','CLOSED_NO_SELECTION',
            'current_invitation_set_sha256',
                encode(selection_row.current_invitation_set_sha256,'hex'),
            'chosen_invitation_id',NULL,'selection_basis_code',NULL,
            'reason_code',close_intent.reason_code)
    );
    PERFORM matching.record_operational_outbox_v1(
        close_intent.attempt_close_event_id,
        'MatchingAttemptClosedWithoutSelection','MatchingAttempt',
        attempt_row.id,new_attempt_version,'SYSTEM',
        exact_coordinator_workload_id,close_intent.actor_user_id,
        exact_organization_id,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'attempt_id',attempt_row.id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'attempt_no',attempt_row.attempt_no,
            'status','CLOSED_NO_SELECTION','reason_code',NULL,
            'selection_id',selection_row.id::text,
            'chosen_invitation_id',NULL)
    );
    response_body := matching.selection_projection_v1(
        selection_row.id,assignment_row.id,new_assignment_version
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_selection_version,
        'CLOSED_NO_SELECTION',ARRAY[
            'SelectionClosedWithoutChoice',
            'MatchingAttemptClosedWithoutSelection'
        ]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.complete_selection_close_v1(
    uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,
    uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.complete_selection_close_v1(
    uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,
    uuid,uuid
) TO matching_coordinator;

-- Complete a zero-eligible-candidate result without inventing a selector.
-- Immutable Matching facts are inspected first without aggregate locks; the
-- Demand root is mutated first, then Matching aggregates are locked and
-- revalidated in the same transaction to preserve the global lock order.
CREATE FUNCTION matching_api.complete_selection_system_close_v1(
    exact_coordinator_workload_id uuid,
    exact_organization_id uuid,
    exact_coordinator_authority_marker_sha256 bytea,
    exact_selection_id uuid,
    exact_receipt_id uuid,
    exact_completion_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_selection_closed_event_id uuid,
    exact_demand_closed_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    system_intent matching.selection_system_close_intents%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    demand_result record;
    authoritative_set_sha256 bytea;
    new_selection_version bigint;
    new_attempt_version bigint;
    response_body jsonb;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_coordinator','MATCHING_COORDINATOR','COMPLETE_SELECTION',
        exact_coordinator_workload_id,exact_organization_id,
        exact_coordinator_authority_marker_sha256,
        exact_completion_command_id
    );
    IF exact_selection_id IS NULL
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_coordinator_workload_id,
        exact_organization_id,'COMPLETE_SELECTION',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        exact_coordinator_authority_marker_sha256,
        '/v1/internal/matching/selections/complete-system-close',
        'Selection',exact_selection_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;

    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
      AND selection.organization_id=exact_organization_id;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
      AND attempt.organization_id=exact_organization_id;
    SELECT intent.* INTO STRICT system_intent
    FROM matching.selection_system_close_intents AS intent
    WHERE intent.selection_id=selection_row.id;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=system_intent.match_run_id
      AND run.attempt_id=attempt_row.id;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    IF selection_row.coordinator_workload_id
            <> exact_coordinator_workload_id
       OR selection_row.coordinator_authority_marker_sha256
            <> exact_coordinator_authority_marker_sha256
       OR selection_row.status <> 'OPEN'
       OR attempt_row.status <> 'OPEN'
       OR attempt_row.selection_id <> selection_row.id
       OR attempt_row.current_match_run_id <> run_row.id
       OR attempt_row.original_actor_user_id
            <> system_intent.original_actor_user_id
       OR run_row.status <> 'COMPLETED'
       OR run_row.eligible_count <> 0
       OR run_row.superseded_by_run_id IS NOT NULL
       OR system_intent.organization_id <> exact_organization_id
       OR system_intent.attempt_id <> attempt_row.id
       OR system_intent.demand_id <> attempt_row.demand_id
       OR system_intent.demand_version_id <> attempt_row.demand_version_id
       OR system_intent.demand_aggregate_version
            <> attempt_row.demand_aggregate_version
       OR system_intent.matching_request_id
            <> attempt_row.matching_request_id
       OR system_intent.matching_request_version
            <> attempt_row.matching_request_version
       OR system_intent.funding_id <> attempt_row.funding_id
       OR system_intent.current_invitation_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR authoritative_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR system_intent.reason_code <> 'NO_ELIGIBLE_CANDIDATES'
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.candidate_selector_assignments AS assignment
            WHERE assignment.selection_id=selection_row.id
              AND assignment.status='ACTIVE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;

    PERFORM set_config('app.scope_kind','DEMAND_MATCHING_COORDINATOR',true);
    PERFORM set_config(
        'app.actor_user_id',system_intent.original_actor_user_id::text,true
    );
    PERFORM set_config('app.demand_id',attempt_row.demand_id::text,true);
    SELECT * INTO STRICT demand_result
    FROM demand_api.execute_close_matching_without_selection_system_v1(
        exact_completion_command_id,system_intent.receipt_id,
        selection_row.id,attempt_row.id,run_row.id,exact_organization_id,
        attempt_row.demand_id,attempt_row.demand_aggregate_version,
        attempt_row.demand_version_id,attempt_row.matching_request_id,
        attempt_row.matching_request_version,attempt_row.funding_id,
        system_intent.original_actor_user_id,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_demand_closed_event_id,exact_correlation_id,exact_trace_id,
        system_intent.reason_code
    );
    PERFORM set_config('app.scope_kind','MATCHING_COORDINATOR',true);
    PERFORM set_config('app.actor_user_id','',true);
    PERFORM set_config('app.selection_id',selection_row.id::text,true);

    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
      AND selection.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=system_intent.match_run_id
      AND run.attempt_id=attempt_row.id
    FOR UPDATE;
    SELECT intent.* INTO STRICT system_intent
    FROM matching.selection_system_close_intents AS intent
    WHERE intent.selection_id=selection_row.id;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    IF selection_row.status <> 'OPEN'
       OR attempt_row.status <> 'OPEN'
       OR attempt_row.selection_id <> selection_row.id
       OR attempt_row.current_match_run_id <> run_row.id
       OR attempt_row.original_actor_user_id
            <> system_intent.original_actor_user_id
       OR run_row.status <> 'COMPLETED'
       OR run_row.eligible_count <> 0
       OR run_row.superseded_by_run_id IS NOT NULL
       OR authoritative_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR system_intent.current_invitation_set_sha256
            <> selection_row.current_invitation_set_sha256
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.candidate_selector_assignments AS assignment
            WHERE assignment.selection_id=selection_row.id
              AND assignment.status='ACTIVE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
    END IF;
    IF demand_result.demand_id <> attempt_row.demand_id
       OR demand_result.demand_version
            <> attempt_row.demand_aggregate_version+1
       OR demand_result.matching_request_version
            <> attempt_row.matching_request_version+1
       OR demand_result.demand_status <> 'NO_MATCH'
       OR demand_result.matching_request_status <> 'CLOSED' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;

    new_selection_version := selection_row.aggregate_version+1;
    new_attempt_version := attempt_row.aggregate_version+1;
    UPDATE matching.selections
    SET status='CLOSED_NO_SELECTION',aggregate_version=new_selection_version,
        reason_code=system_intent.reason_code,
        decision_actor_id=system_intent.original_actor_user_id,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id;
    UPDATE matching.matching_attempts
    SET status='CLOSED_NO_SELECTION',aggregate_version=new_attempt_version,
        updated_at=transaction_timestamp(),terminal_at=transaction_timestamp()
    WHERE id=attempt_row.id;
    INSERT INTO matching.complete_selection_system_close_records (
        close_receipt_id,system_close_intent_id,completion_command_id,
        organization_id,selection_id,attempt_id,match_run_id,demand_id,
        expected_demand_version,completed_demand_version,
        matching_request_id,expected_matching_request_version,
        completed_matching_request_version,funding_id,
        original_actor_user_id,coordinator_workload_id,
        coordinator_authority_marker_sha256,reason_code,
        demand_closed_event_id,matching_event_ids,status,completed_at
    ) VALUES (
        system_intent.receipt_id,system_intent.id,
        exact_completion_command_id,exact_organization_id,selection_row.id,
        attempt_row.id,run_row.id,attempt_row.demand_id,
        attempt_row.demand_aggregate_version,demand_result.demand_version,
        attempt_row.matching_request_id,attempt_row.matching_request_version,
        demand_result.matching_request_version,attempt_row.funding_id,
        system_intent.original_actor_user_id,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        system_intent.reason_code,exact_demand_closed_event_id,
        ARRAY[exact_selection_closed_event_id,
            system_intent.attempt_close_event_id],
        'COMPLETED',transaction_timestamp()
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_coordinator_workload_id,
        system_intent.original_actor_user_id,
        'COMPLETE_SELECTION','Selection',selection_row.id,
        exact_organization_id,'PENDING_CLOSE','CLOSED_NO_SELECTION',
        selection_row.aggregate_version,new_selection_version,
        system_intent.reason_code,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('attempt_id',attempt_row.id::text,
            'system_close_intent_id',system_intent.id::text)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_selection_closed_event_id,'SelectionClosedWithoutChoice',
        'Selection',selection_row.id,new_selection_version,'SYSTEM',
        exact_coordinator_workload_id,system_intent.original_actor_user_id,
        exact_organization_id,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',attempt_row.id::text,
            'status','CLOSED_NO_SELECTION',
            'current_invitation_set_sha256',encode(
                selection_row.current_invitation_set_sha256,'hex'
            ),
            'chosen_invitation_id',NULL,'selection_basis_code',NULL,
            'reason_code',system_intent.reason_code)
    );
    PERFORM matching.record_operational_outbox_v1(
        system_intent.attempt_close_event_id,
        'MatchingAttemptClosedWithoutSelection','MatchingAttempt',
        attempt_row.id,new_attempt_version,'SYSTEM',
        exact_coordinator_workload_id,system_intent.original_actor_user_id,
        exact_organization_id,exact_completion_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'attempt_id',attempt_row.id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'attempt_no',attempt_row.attempt_no,
            'status','CLOSED_NO_SELECTION','reason_code',NULL,
            'selection_id',selection_row.id::text,
            'chosen_invitation_id',NULL)
    );
    response_body := matching.selection_projection_v1(
        selection_row.id,NULL,NULL
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_selection_version,
        'CLOSED_NO_SELECTION',ARRAY[
            'SelectionClosedWithoutChoice',
            'MatchingAttemptClosedWithoutSelection'
        ]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.complete_selection_system_close_v1(
    uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,
    uuid,uuid
) FROM PUBLIC, matching_coordinator;

-- The two aggregate coordinators above remain small internal building blocks.
-- Production receives only this lease-bound dispatcher, which derives intent
-- kind from the durable claim and makes bypassing queue fencing impossible.
CREATE FUNCTION matching_api.complete_claimed_selection_v1(
    exact_workload_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_completion_job_id uuid,
    exact_fencing_generation bigint,
    exact_lease_digest_key_id text,
    exact_lease_digest bytea,
    exact_trust_evidence_sha256 bytea,
    exact_trust_evaluated_at timestamptz,
    exact_trust_valid_until timestamptz,
    exact_receipt_id uuid,
    exact_completion_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_selection_event_id uuid,
    exact_attempt_event_id uuid,
    exact_demand_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_projection jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    prior_receipt matching.command_receipts%ROWTYPE;
    job_row matching.selection_completion_jobs%ROWTYPE;
    completion_result record;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_coordinator'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_workload_id IS NULL OR exact_completion_job_id IS NULL
       OR exact_fencing_generation < 1
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR octet_length(exact_lease_digest) <> 32
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_lease_digest_key_id IN (
            exact_identity_key_id, exact_payload_hash_key_id
       )
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_COORDINATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE_SELECTION'
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM exact_workload_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_completion_command_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_completion_job_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    -- Completed receipt recovery intentionally precedes lease and Trust
    -- freshness checks.  This is the only safe answer after an unknown commit.
    SELECT receipt.* INTO prior_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind='SYSTEM'
      AND receipt.principal_id=exact_workload_id
      AND receipt.organization_id=NULLIF(
            current_setting('app.organization_id', true), ''
          )::uuid
      AND receipt.operation='COMPLETE_SELECTION'
      AND receipt.command_version=1
      AND receipt.identity_key_id=exact_identity_key_id
      AND receipt.identity_digest=exact_identity_digest;
    IF FOUND THEN
        IF prior_receipt.payload_hash_key_id <> exact_payload_hash_key_id
           OR prior_receipt.payload_hash <> exact_payload_hash
           OR prior_receipt.principal_authority_marker_sha256
                <> exact_authority_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF prior_receipt.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='COMMAND_OUTCOME_UNKNOWN';
        END IF;
        RETURN QUERY SELECT prior_receipt.safe_response_body,true;
        RETURN;
    END IF;

    SELECT job.* INTO job_row
    FROM matching.selection_completion_jobs AS job
    WHERE job.id=exact_completion_job_id
    FOR UPDATE;
    IF NOT FOUND
       OR job_row.organization_id <> NULLIF(
            current_setting('app.organization_id', true), ''
          )::uuid
       OR job_row.selection_id <> NULLIF(
            current_setting('app.selection_id', true), ''
          )::uuid
       OR job_row.workload_id <> exact_workload_id
       OR job_row.authority_marker_sha256
            <> exact_authority_marker_sha256
       OR job_row.status <> 'LEASED'
       OR job_row.fencing_generation <> exact_fencing_generation
       OR job_row.lease_digest_key_id <> exact_lease_digest_key_id
       OR job_row.lease_digest <> exact_lease_digest
       OR job_row.lease_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;

    IF job_row.intent_kind='CHOOSE' THEN
        IF octet_length(exact_trust_evidence_sha256) <> 32
           OR exact_trust_evaluated_at IS NULL
           OR exact_trust_valid_until IS NULL
           OR exact_attempt_event_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
        END IF;
        SELECT * INTO STRICT completion_result
        FROM matching_api.complete_selection_v1(
            exact_workload_id,job_row.organization_id,
            exact_authority_marker_sha256,job_row.selection_id,
            exact_trust_evidence_sha256,exact_trust_evaluated_at,
            exact_trust_valid_until,exact_receipt_id,
            exact_completion_command_id,exact_identity_key_id,
            exact_identity_digest,exact_payload_hash_key_id,
            exact_payload_hash,exact_audit_event_id,
            exact_selection_event_id,exact_attempt_event_id,
            exact_demand_event_id,exact_correlation_id,exact_trace_id
        );
    ELSIF job_row.intent_kind='CLOSE' THEN
        IF exact_trust_evidence_sha256 IS NOT NULL
           OR exact_trust_evaluated_at IS NOT NULL
           OR exact_trust_valid_until IS NOT NULL
           OR exact_attempt_event_id IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
        END IF;
        SELECT * INTO STRICT completion_result
        FROM matching_api.complete_selection_close_v1(
            exact_workload_id,job_row.organization_id,
            exact_authority_marker_sha256,job_row.selection_id,
            exact_receipt_id,exact_completion_command_id,
            exact_identity_key_id,exact_identity_digest,
            exact_payload_hash_key_id,exact_payload_hash,
            exact_audit_event_id,exact_selection_event_id,
            exact_demand_event_id,exact_correlation_id,exact_trace_id
        );
    ELSIF job_row.intent_kind='SYSTEM_CLOSE' THEN
        IF exact_trust_evidence_sha256 IS NOT NULL
           OR exact_trust_evaluated_at IS NOT NULL
           OR exact_trust_valid_until IS NOT NULL
           OR exact_attempt_event_id IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
        END IF;
        SELECT * INTO STRICT completion_result
        FROM matching_api.complete_selection_system_close_v1(
            exact_workload_id,job_row.organization_id,
            exact_authority_marker_sha256,job_row.selection_id,
            exact_receipt_id,exact_completion_command_id,
            exact_identity_key_id,exact_identity_digest,
            exact_payload_hash_key_id,exact_payload_hash,
            exact_audit_event_id,exact_selection_event_id,
            exact_demand_event_id,exact_correlation_id,exact_trace_id
        );
    ELSE
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    UPDATE matching.selection_completion_jobs
    SET status='COMPLETED',completed_at=transaction_timestamp()
    WHERE id=job_row.id AND status='LEASED'
      AND fencing_generation=exact_fencing_generation
      AND lease_digest_key_id=exact_lease_digest_key_id
      AND lease_digest=exact_lease_digest;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='COMMAND_OUTCOME_UNKNOWN';
    END IF;
    RETURN QUERY SELECT completion_result.safe_projection,
        completion_result.replayed;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.complete_claimed_selection_v1(
    uuid,bytea,uuid,bigint,text,bytea,bytea,timestamptz,timestamptz,
    uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.complete_claimed_selection_v1(
    uuid,bytea,uuid,bigint,text,bytea,bytea,timestamptz,timestamptz,
    uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,uuid
) TO matching_coordinator;

CREATE FUNCTION matching_api.fail_claimed_selection_v1(
    exact_workload_id uuid,
    exact_authority_marker_sha256 bytea,
    exact_completion_job_id uuid,
    exact_fencing_generation bigint,
    exact_lease_digest_key_id text,
    exact_lease_digest bytea,
    exact_failure_code text,
    exact_retry_available_at timestamptz,
    exact_receipt_id uuid,
    exact_failure_command_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_result jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    job_row matching.selection_completion_jobs%ROWTYPE;
    response_body jsonb;
    event_payload jsonb;
    result_status text;
    event_type text;
BEGIN
    PERFORM matching.assert_operational_context_v1(
        'matching_coordinator','MATCHING_COORDINATOR',
        'FAIL_SELECTION_COMPLETION',exact_workload_id,
        NULLIF(current_setting('app.organization_id', true), '')::uuid,
        exact_authority_marker_sha256,exact_failure_command_id
    );
    IF exact_completion_job_id IS NULL
       OR exact_fencing_generation < 1
       OR octet_length(exact_lease_digest) <> 32
       OR exact_lease_digest_key_id IN (
            exact_identity_key_id, exact_payload_hash_key_id
       )
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR exact_failure_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_completion_job_id::text THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'SYSTEM',exact_workload_id,
        NULLIF(current_setting('app.organization_id', true), '')::uuid,
        'FAIL_SELECTION_COMPLETION',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,
        '/v1/internal/matching/selection-completions/fail',
        'SelectionCompletionJob',exact_completion_job_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;
    IF exact_retry_available_at < transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SELECT job.* INTO job_row
    FROM matching.selection_completion_jobs AS job
    WHERE job.id=exact_completion_job_id
    FOR UPDATE;
    IF NOT FOUND
       OR job_row.selection_id <> NULLIF(
            current_setting('app.selection_id', true), ''
          )::uuid
       OR job_row.workload_id <> exact_workload_id
       OR job_row.authority_marker_sha256
            <> exact_authority_marker_sha256
       OR job_row.status <> 'LEASED'
       OR job_row.fencing_generation <> exact_fencing_generation
       OR job_row.lease_digest_key_id <> exact_lease_digest_key_id
       OR job_row.lease_digest <> exact_lease_digest
       OR job_row.lease_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='LEASE_LOST';
    END IF;

    IF job_row.attempt_count >= 3 THEN
        result_status := 'FAILED';
        event_type := 'SelectionCompletionFailed';
        UPDATE matching.selection_completion_jobs
        SET status='FAILED',last_failure_code=exact_failure_code,
            completed_at=transaction_timestamp()
        WHERE id=job_row.id;
    ELSE
        result_status := 'AVAILABLE';
        event_type := 'SelectionCompletionRetryScheduled';
        UPDATE matching.selection_completion_jobs
        SET status='AVAILABLE',lease_digest_key_id=NULL,lease_digest=NULL,
            lease_until=NULL,available_at=exact_retry_available_at,
            last_failure_code=exact_failure_code
        WHERE id=job_row.id;
    END IF;
    response_body := jsonb_build_object(
        'completion_job_id',job_row.id::text,
        'organization_id',job_row.organization_id::text,
        'selection_id',job_row.selection_id::text,
        'intent_kind',job_row.intent_kind,'status',result_status,
        'fencing_generation',job_row.fencing_generation,
        'attempt_count',job_row.attempt_count,
        'failure_code',exact_failure_code,
        'available_at',CASE WHEN result_status='AVAILABLE'
            THEN exact_retry_available_at ELSE NULL END
    );
    event_payload := jsonb_build_object(
        'completion_job_id',job_row.id::text,
        'selection_id',job_row.selection_id::text,
        'intent_kind',job_row.intent_kind,'status',result_status,
        'fencing_generation',job_row.fencing_generation,
        'attempt_count',job_row.attempt_count,
        'failure_code',exact_failure_code
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'SYSTEM',exact_workload_id,NULL,
        'FAIL_SELECTION_COMPLETION','SelectionCompletionJob',job_row.id,
        job_row.organization_id,'LEASED',result_status,
        job_row.fencing_generation,job_row.fencing_generation,
        exact_failure_code,exact_failure_command_id,
        exact_correlation_id,exact_trace_id,
        jsonb_build_object('selection_id',job_row.selection_id::text,
            'attempt_count',job_row.attempt_count)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,event_type,'SelectionCompletionJob',job_row.id,
        GREATEST(job_row.fencing_generation,1),'SYSTEM',exact_workload_id,
        NULL,job_row.organization_id,exact_failure_command_id,
        exact_correlation_id,exact_trace_id,event_payload
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,GREATEST(job_row.fencing_generation,1),
        result_status,ARRAY[event_type]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.fail_claimed_selection_v1(
    uuid,bytea,uuid,bigint,text,bytea,text,timestamptz,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.fail_claimed_selection_v1(
    uuid,bytea,uuid,bigint,text,bytea,text,timestamptz,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_coordinator;

REVOKE EXECUTE ON FUNCTION matching_api.complete_selection_v1(
    uuid,uuid,bytea,uuid,bytea,timestamptz,timestamptz,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,uuid
) FROM matching_coordinator;
REVOKE EXECUTE ON FUNCTION matching_api.complete_selection_close_v1(
    uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,
    uuid,uuid
) FROM matching_coordinator;

-- A human reviewer supplies only their authenticated actor/session marker and
-- command material.  Matching discovers one exact target first, then IAM45
-- proves the current OPERATIONS_REVIEWER duty for that derived tuple.
CREATE FUNCTION matching_api.claim_matching_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_assignment_id uuid,
    exact_claim_command_id uuid,
    exact_receipt_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_assignment jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    prior_receipt matching.command_receipts%ROWTYPE;
    receipt_result record;
    iam_authority record;
    target_organization_id uuid;
    target_attempt_id uuid;
    target_run_id uuid;
    target_purpose_code text;
    response_body jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_assignment_id IS NULL OR exact_claim_command_id IS NULL
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW_CLAIM'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_MATCHING_REVIEW'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_principal_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_claim_command_id::text
       OR COALESCE(current_setting('app.organization_id', true), '') <> ''
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.match_run_id', true), '') <> ''
       OR COALESCE(current_setting('app.purpose_code', true), '') <> ''
       OR COALESCE(current_setting('app.target_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    -- Exact idempotent recovery remains possible after assignment expiry or a
    -- queue transition because it does not re-resolve either mutable fact.
    SELECT receipt.* INTO prior_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind='USER'
      AND receipt.principal_id=exact_actor_user_id
      AND receipt.operation='CLAIM_MATCHING_REVIEW'
      AND receipt.command_version=1
      AND receipt.identity_key_id=exact_identity_key_id
      AND receipt.identity_digest=exact_identity_digest;
    IF FOUND THEN
        IF prior_receipt.payload_hash_key_id <> exact_payload_hash_key_id
           OR prior_receipt.payload_hash <> exact_payload_hash
           OR prior_receipt.principal_authority_marker_sha256
                <> exact_principal_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF prior_receipt.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='COMMAND_OUTCOME_UNKNOWN';
        END IF;
        RETURN QUERY SELECT prior_receipt.safe_response_body,true;
        RETURN;
    END IF;

    UPDATE matching.matching_review_assignments
    SET status='EXPIRED',aggregate_version=aggregate_version+1,
        completed_at=transaction_timestamp()
    WHERE status='ACTIVE'
      AND expires_at <= transaction_timestamp();
    IF EXISTS (
        SELECT 1
        FROM matching.matching_review_assignments AS assignment
        WHERE assignment.reviewer_user_id=exact_actor_user_id
          AND assignment.status='ACTIVE'
          AND assignment.expires_at > transaction_timestamp()
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='INVALID_STATE_TRANSITION';
    END IF;

    SELECT attempt.organization_id,attempt.id,run.id,
        CASE
            WHEN run.status='FAILED' THEN 'MATCH_RETRY'
            WHEN result.eligible_count > 0 THEN 'INVITATION_REVIEW'
            ELSE 'ATTEMPT_REVIEW'
        END
    INTO target_organization_id,target_attempt_id,target_run_id,
        target_purpose_code
    FROM matching.matching_attempts AS attempt
    JOIN matching.match_runs AS run
      ON run.id=attempt.current_match_run_id
     AND run.attempt_id=attempt.id
    LEFT JOIN matching.match_run_results AS result
      ON result.match_run_id=run.id
    WHERE attempt.status='OPEN'
      AND run.status IN ('COMPLETED','FAILED')
      AND run.superseded_by_run_id IS NULL
      AND (run.status='FAILED' OR result.match_run_id IS NOT NULL)
      AND NOT EXISTS (
        SELECT 1
        FROM matching.matching_review_assignments AS active_assignment
        WHERE active_assignment.attempt_id=attempt.id
          AND active_assignment.purpose_code=CASE
                WHEN run.status='FAILED' THEN 'MATCH_RETRY'
                WHEN result.eligible_count > 0 THEN 'INVITATION_REVIEW'
                ELSE 'ATTEMPT_REVIEW'
              END
          AND active_assignment.status='ACTIVE'
          AND active_assignment.expires_at > transaction_timestamp()
      )
    ORDER BY attempt.updated_at,attempt.id,run.id
    FOR UPDATE OF attempt,run SKIP LOCKED
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind','MATCHING_REVIEW',true);
    PERFORM set_config('app.organization_id',target_organization_id::text,true);
    PERFORM set_config('app.attempt_id',target_attempt_id::text,true);
    PERFORM set_config('app.match_run_id',target_run_id::text,true);
    PERFORM set_config('app.purpose_code',target_purpose_code,true);
    PERFORM set_config('app.target_id',exact_assignment_id::text,true);
    SELECT * INTO STRICT iam_authority
    FROM iam_api.resolve_matching_reviewer_authority_marker_v1(
        exact_actor_user_id,exact_session_id,target_organization_id,
        target_attempt_id,target_run_id,target_purpose_code,
        exact_claim_command_id
    );
    IF iam_authority.actor_user_id <> exact_actor_user_id
       OR iam_authority.session_id <> exact_session_id
       OR iam_authority.organization_id <> target_organization_id
       OR iam_authority.attempt_id <> target_attempt_id
       OR iam_authority.match_run_id <> target_run_id
       OR iam_authority.purpose_code <> target_purpose_code
       OR iam_authority.role_code <> 'MATCHING_REVIEWER'
       OR iam_authority.duty_code <> 'OPERATIONS_REVIEWER'
       OR iam_authority.duty_grant_version < 1
       OR iam_authority.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR octet_length(iam_authority.evidence_sha256) <> 32
       OR iam_authority.valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'USER',exact_actor_user_id,
        target_organization_id,'CLAIM_MATCHING_REVIEW',
        exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_principal_marker_sha256,
        '/v1/app/matching-review/queue/claim',
        'MatchingReviewAssignment',exact_assignment_id,NULL
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;

    UPDATE matching.matching_review_assignments
    SET status='EXPIRED',aggregate_version=aggregate_version+1,
        completed_at=transaction_timestamp()
    WHERE attempt_id=target_attempt_id
      AND purpose_code=target_purpose_code
      AND status='ACTIVE'
      AND expires_at <= transaction_timestamp();
    IF EXISTS (
        SELECT 1
        FROM matching.matching_review_assignments AS active_assignment
        WHERE (
            active_assignment.reviewer_user_id=exact_actor_user_id
            OR (
                active_assignment.attempt_id=target_attempt_id
                AND active_assignment.purpose_code=target_purpose_code
            )
        )
          AND active_assignment.status='ACTIVE'
          AND active_assignment.expires_at > transaction_timestamp()
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='INVALID_STATE_TRANSITION';
    END IF;

    INSERT INTO matching.matching_review_assignments (
        id,organization_id,attempt_id,match_run_id,reviewer_user_id,
        duty_grant_id,duty_grant_version,purpose_code,
        conflict_attestation_sha256,authority_marker_sha256,status,
        aggregate_version,expires_at,created_at,completed_at,
        reviewer_session_id,claim_receipt_id,claim_command_id,
        role_code,duty_code
    ) VALUES (
        exact_assignment_id,target_organization_id,target_attempt_id,
        target_run_id,exact_actor_user_id,iam_authority.duty_grant_id,
        iam_authority.duty_grant_version,target_purpose_code,
        iam_authority.evidence_sha256,exact_principal_marker_sha256,
        'ACTIVE',1,iam_authority.valid_until,transaction_timestamp(),NULL,
        exact_session_id,exact_receipt_id,exact_claim_command_id,
        iam_authority.role_code,iam_authority.duty_code
    );
    response_body := jsonb_build_object(
        'assignment_id',exact_assignment_id::text,
        'organization_id',target_organization_id::text,
        'attempt_id',target_attempt_id::text,
        'match_run_id',target_run_id::text,
        'purpose_code',target_purpose_code,
        'role_code','MATCHING_REVIEWER',
        'status','ACTIVE','aggregate_version',1,
        'expires_at',iam_authority.valid_until
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'USER',exact_actor_user_id,NULL,
        'CLAIM_MATCHING_REVIEW','MatchingReviewAssignment',
        exact_assignment_id,target_organization_id,NULL,'ACTIVE',NULL,1,
        NULL,exact_claim_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('attempt_id',target_attempt_id::text,
            'match_run_id',target_run_id::text,
            'purpose_code',target_purpose_code,
            'duty_grant_id',iam_authority.duty_grant_id::text,
            'duty_grant_version',iam_authority.duty_grant_version)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'MatchingReviewAssignmentClaimed',
        'MatchingReviewAssignment',exact_assignment_id,1,'USER',
        exact_actor_user_id,NULL,target_organization_id,
        exact_claim_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'assignment_id',exact_assignment_id::text,
            'attempt_id',target_attempt_id::text,
            'match_run_id',target_run_id::text,
            'purpose_code',target_purpose_code,
            'status','ACTIVE','assignment_version',1
        )
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,1,'ACTIVE',
        ARRAY['MatchingReviewAssignmentClaimed']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.claim_matching_review_v1(
    uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.claim_matching_review_v1(
    uuid,uuid,bytea,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_review;

CREATE FUNCTION matching_api.read_matching_review_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea
)
RETURNS TABLE (safe_assignment jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    assignment_row matching.matching_review_assignments%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    result_row matching.match_run_results%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW_RESUME'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'READ_MATCHING_REVIEW_ASSIGNMENT'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_principal_marker_sha256,'hex')
       OR COALESCE(current_setting('app.organization_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT assignment.* INTO assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.reviewer_user_id=exact_actor_user_id
      AND assignment.reviewer_session_id=exact_session_id
      AND assignment.authority_marker_sha256=exact_principal_marker_sha256
      AND assignment.status='ACTIVE'
      AND assignment.expires_at > transaction_timestamp();
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM set_config('app.scope_kind','MATCHING_REVIEW',true);
    PERFORM set_config(
        'app.organization_id',assignment_row.organization_id::text,true
    );
    PERFORM set_config('app.attempt_id',assignment_row.attempt_id::text,true);
    PERFORM set_config(
        'app.match_run_id',assignment_row.match_run_id::text,true
    );
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=assignment_row.attempt_id
      AND attempt.organization_id=assignment_row.organization_id;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=assignment_row.match_run_id
      AND run.attempt_id=attempt_row.id;
    SELECT result.* INTO result_row
    FROM matching.match_run_results AS result
    WHERE result.match_run_id=run_row.id;

    RETURN QUERY SELECT jsonb_build_object(
        'assignment_id',assignment_row.id::text,
        'organization_id',assignment_row.organization_id::text,
        'attempt_id',assignment_row.attempt_id::text,
        'match_run_id',assignment_row.match_run_id::text,
        'purpose_code',assignment_row.purpose_code,
        'role_code',assignment_row.role_code,
        'status',assignment_row.status,
        'aggregate_version',assignment_row.aggregate_version,
        'expires_at',assignment_row.expires_at,
        'attempt',jsonb_build_object(
            'attempt_no',attempt_row.attempt_no,
            'status',attempt_row.status,
            'aggregate_version',attempt_row.aggregate_version,
            'updated_at',attempt_row.updated_at,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'demand_aggregate_version',
                attempt_row.demand_aggregate_version,
            'demand_content_sha256',encode(
                attempt_row.demand_content_sha256,'hex'
            ),
            'input_baseline_sha256',encode(
                attempt_row.input_baseline_sha256,'hex'
            )
        ),
        'run',jsonb_build_object(
            'status',run_row.status,
            'aggregate_version',run_row.aggregate_version,
            'ordered_result_sha256',CASE
                WHEN run_row.ordered_result_sha256 IS NULL THEN NULL
                ELSE encode(run_row.ordered_result_sha256,'hex') END,
            'candidate_count',run_row.candidate_count,
            'eligible_count',run_row.eligible_count,
            'excluded_count',run_row.excluded_count,
            'failure_code',run_row.failure_code
        ),
        'eligible_candidates',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'creator_user_id',candidate.creator_user_id::text,
                'creator_display_handle','creator_'
                    || substr(replace(candidate.creator_user_id::text,'-',''),1,16),
                'profile_id',candidate.profile_id::text,
                'profile_version_id',candidate.profile_version_id::text,
                'profile_content_sha256',encode(
                    candidate.profile_content_sha256,'hex'
                ),
                'evidence_version_digest',encode(
                    candidate.evidence_version_digest,'hex'
                ),
                'total_score',candidate.total_score::text,
                'rank',candidate.rank,
                'component_scores',COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'code',component.value->>'code',
                        'ordinal',(component.value->>'ordinal')::integer,
                        'score',(component.value->>'score')::numeric::text
                    ) ORDER BY (component.value->>'ordinal')::integer)
                    FROM jsonb_array_elements(
                        candidate.component_scores
                    ) AS component(value)
                ),'[]'::jsonb),
                'candidate_result_sha256',encode(
                    candidate.candidate_result_sha256,'hex'
                )
            ) ORDER BY candidate.rank,candidate.creator_user_id)
            FROM matching.match_candidates AS candidate
            WHERE candidate.match_run_id=run_row.id
              AND candidate.eligibility='ELIGIBLE'
        ),'[]'::jsonb),
        'invitations',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'invitation_id',invitation.id::text,
                'creator_user_id',invitation.creator_user_id::text,
                'status',invitation.status,
                'aggregate_version',invitation.aggregate_version,
                'snapshot_sha256',encode(invitation.snapshot_sha256,'hex'),
                'expires_at',invitation.expires_at,
                'updated_at',invitation.updated_at
            ) ORDER BY invitation.created_at,invitation.id)
            FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
              AND invitation.match_run_id=run_row.id
        ),'[]'::jsonb),
        'actions',jsonb_build_object(
            'can_create_invitation',
                assignment_row.purpose_code='INVITATION_REVIEW'
                AND run_row.status='COMPLETED',
            'can_publish_invitation',
                assignment_row.purpose_code='INVITATION_REVIEW'
                AND run_row.status='COMPLETED',
            'can_invalidate_attempt',
                assignment_row.purpose_code IN (
                    'INVITATION_REVIEW','ATTEMPT_REVIEW'
                ) AND attempt_row.status='OPEN'
        )
    );
END
$function$;

REVOKE ALL ON FUNCTION matching_api.read_matching_review_assignment_v1(
    uuid,uuid,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.read_matching_review_assignment_v1(
    uuid,uuid,bytea
) TO matching_review;

CREATE FUNCTION matching_api.resolve_matching_review_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_operation text,
    exact_target_id uuid
)
RETURNS TABLE (
    assignment_id uuid,
    organization_id uuid,
    attempt_id uuid,
    match_run_id uuid,
    purpose_code varchar,
    assignment_version bigint,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    assignment_row matching.matching_review_assignments%ROWTYPE;
    target_invitation matching.invitations%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_operation NOT IN (
            'CREATE_INVITATION','PUBLISH_INVITATION','INVALIDATE_ATTEMPT'
       )
       OR exact_target_id IS NULL
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW_RESOLVE'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_principal_marker_sha256,'hex')
       OR COALESCE(current_setting('app.organization_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT assignment.* INTO assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.reviewer_user_id=exact_actor_user_id
      AND assignment.reviewer_session_id=exact_session_id
      AND assignment.authority_marker_sha256=exact_principal_marker_sha256
      AND assignment.status='ACTIVE'
      AND assignment.expires_at > transaction_timestamp();
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM set_config('app.scope_kind','MATCHING_REVIEW',true);
    PERFORM set_config(
        'app.organization_id',assignment_row.organization_id::text,true
    );
    PERFORM set_config('app.attempt_id',assignment_row.attempt_id::text,true);
    PERFORM set_config(
        'app.match_run_id',assignment_row.match_run_id::text,true
    );
    IF exact_operation='CREATE_INVITATION' THEN
        IF assignment_row.purpose_code <> 'INVITATION_REVIEW'
           OR assignment_row.match_run_id <> exact_target_id THEN
            RETURN;
        END IF;
    ELSIF exact_operation='PUBLISH_INVITATION' THEN
        IF assignment_row.purpose_code <> 'INVITATION_REVIEW' THEN
            RETURN;
        END IF;
        SELECT invitation.* INTO target_invitation
        FROM matching.invitations AS invitation
        WHERE invitation.id=exact_target_id
          AND invitation.attempt_id=assignment_row.attempt_id
          AND invitation.match_run_id=assignment_row.match_run_id;
        IF NOT FOUND THEN RETURN; END IF;
    ELSE
        IF assignment_row.purpose_code NOT IN (
                'INVITATION_REVIEW','ATTEMPT_REVIEW'
            )
           OR assignment_row.attempt_id <> exact_target_id THEN
            RETURN;
        END IF;
    END IF;
    RETURN QUERY SELECT assignment_row.id,assignment_row.organization_id,
        assignment_row.attempt_id,assignment_row.match_run_id,
        assignment_row.purpose_code,assignment_row.aggregate_version,
        assignment_row.expires_at;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.resolve_matching_review_assignment_v1(
    uuid,uuid,bytea,text,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.resolve_matching_review_assignment_v1(
    uuid,uuid,bytea,text,uuid
) TO matching_review;

CREATE FUNCTION matching_api.release_matching_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    expected_assignment_version bigint,
    exact_release_command_id uuid,
    exact_receipt_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_assignment jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    prior_receipt matching.command_receipts%ROWTYPE;
    receipt_result record;
    assignment_row matching.matching_review_assignments%ROWTYPE;
    response_body jsonb;
    new_version bigint;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR expected_assignment_version < 1
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW_RESUME'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'RELEASE_MATCHING_REVIEW'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_principal_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_release_command_id::text
       OR COALESCE(current_setting('app.organization_id', true), '') <> ''
       OR COALESCE(current_setting('app.target_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT receipt.* INTO prior_receipt
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind='USER'
      AND receipt.principal_id=exact_actor_user_id
      AND receipt.operation='RELEASE_MATCHING_REVIEW'
      AND receipt.command_version=1
      AND receipt.identity_key_id=exact_identity_key_id
      AND receipt.identity_digest=exact_identity_digest;
    IF FOUND THEN
        IF prior_receipt.payload_hash_key_id <> exact_payload_hash_key_id
           OR prior_receipt.payload_hash <> exact_payload_hash
           OR prior_receipt.principal_authority_marker_sha256
                <> exact_principal_marker_sha256 THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF prior_receipt.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',
                MESSAGE='COMMAND_OUTCOME_UNKNOWN';
        END IF;
        RETURN QUERY SELECT prior_receipt.safe_response_body,true;
        RETURN;
    END IF;
    SELECT assignment.* INTO assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.reviewer_user_id=exact_actor_user_id
      AND assignment.reviewer_session_id=exact_session_id
      AND assignment.authority_marker_sha256=exact_principal_marker_sha256
      AND assignment.status='ACTIVE';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.scope_kind','MATCHING_REVIEW',true);
    PERFORM set_config(
        'app.organization_id',assignment_row.organization_id::text,true
    );
    PERFORM set_config('app.target_id',assignment_row.id::text,true);
    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'USER',exact_actor_user_id,
        assignment_row.organization_id,'RELEASE_MATCHING_REVIEW',
        exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_principal_marker_sha256,
        '/v1/app/matching-review/assignment/release',
        'MatchingReviewAssignment',assignment_row.id,
        expected_assignment_version
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;
    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.id=assignment_row.id
    FOR UPDATE;
    IF assignment_row.status <> 'ACTIVE'
       OR assignment_row.aggregate_version <> expected_assignment_version
       OR assignment_row.expires_at <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    new_version := assignment_row.aggregate_version+1;
    UPDATE matching.matching_review_assignments
    SET status='REVOKED',aggregate_version=new_version,
        completed_at=transaction_timestamp()
    WHERE id=assignment_row.id;
    response_body := jsonb_build_object(
        'assignment_id',assignment_row.id::text,
        'organization_id',assignment_row.organization_id::text,
        'attempt_id',assignment_row.attempt_id::text,
        'match_run_id',assignment_row.match_run_id::text,
        'purpose_code',assignment_row.purpose_code,
        'role_code',assignment_row.role_code,
        'status','REVOKED','aggregate_version',new_version,
        'expires_at',assignment_row.expires_at
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'USER',exact_actor_user_id,NULL,
        'RELEASE_MATCHING_REVIEW','MatchingReviewAssignment',
        assignment_row.id,assignment_row.organization_id,'ACTIVE','REVOKED',
        assignment_row.aggregate_version,new_version,NULL,
        exact_release_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('attempt_id',assignment_row.attempt_id::text,
            'match_run_id',assignment_row.match_run_id::text)
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'MatchingReviewAssignmentReleased',
        'MatchingReviewAssignment',assignment_row.id,new_version,'USER',
        exact_actor_user_id,NULL,assignment_row.organization_id,
        exact_release_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'assignment_id',assignment_row.id::text,
            'attempt_id',assignment_row.attempt_id::text,
            'match_run_id',assignment_row.match_run_id::text,
            'purpose_code',assignment_row.purpose_code,
            'status','REVOKED','assignment_version',new_version
        )
    );
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_version,'REVOKED',
        ARRAY['MatchingReviewAssignmentReleased']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.release_matching_review_v1(
    uuid,uuid,bytea,bigint,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.release_matching_review_v1(
    uuid,uuid,bytea,bigint,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_review;

-- Return only the closed Creator-facing disclosure that CREATE_INVITATION
-- will accept.  The browser cannot submit Demand/Profile content and the
-- reviewer cannot use this program to inspect an unassigned run or candidate.
CREATE FUNCTION matching_api.prepare_matching_invitation_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_organization_id uuid,
    exact_assignment_id uuid,
    expected_assignment_version bigint,
    exact_match_run_id uuid,
    expected_match_run_version bigint,
    exact_creator_user_id uuid,
    exact_invitation_id uuid,
    exact_expires_at timestamptz
)
RETURNS TABLE (safe_disclosure jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    assignment_row matching.matching_review_assignments%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    input_row matching.match_run_inputs%ROWTYPE;
    candidate_row matching.match_candidates%ROWTYPE;
    bundle_row matching.rule_bundles%ROWTYPE;
    expected_snapshot jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_assignment_id IS NULL
       OR exact_match_run_id IS NULL OR exact_creator_user_id IS NULL
       OR exact_invitation_id IS NULL
       OR expected_assignment_version < 1
       OR expected_match_run_version < 1
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR exact_expires_at <= transaction_timestamp()
       OR exact_expires_at > transaction_timestamp()+interval '30 days'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'PREPARE_INVITATION'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.match_run_id', true), '')
            IS DISTINCT FROM exact_match_run_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_match_run_id::text
       OR COALESCE(current_setting('app.command_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;
    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.id=exact_assignment_id
      AND assignment.organization_id=exact_organization_id;
    IF assignment_row.reviewer_user_id <> exact_actor_user_id
       OR assignment_row.reviewer_session_id <> exact_session_id
       OR assignment_row.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR assignment_row.role_code <> 'MATCHING_REVIEWER'
       OR assignment_row.duty_code <> 'OPERATIONS_REVIEWER'
       OR assignment_row.purpose_code <> 'INVITATION_REVIEW'
       OR assignment_row.status <> 'ACTIVE'
       OR assignment_row.aggregate_version <> expected_assignment_version
       OR assignment_row.expires_at <= transaction_timestamp()
       OR assignment_row.match_run_id <> exact_match_run_id THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',assignment_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=assignment_row.attempt_id
      AND attempt.organization_id=exact_organization_id;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=exact_match_run_id
      AND run.attempt_id=attempt_row.id;
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.current_match_run_id <> run_row.id
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR run_row.aggregate_version <> expected_match_run_version
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=attempt_row.selection_id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=attempt_row.selection_id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    SELECT input.* INTO STRICT input_row
    FROM matching.match_run_inputs AS input
    WHERE input.match_run_id=run_row.id
      AND input.attempt_id=attempt_row.id;
    SELECT candidate.* INTO STRICT candidate_row
    FROM matching.match_candidates AS candidate
    WHERE candidate.match_run_id=run_row.id
      AND candidate.creator_user_id=exact_creator_user_id;
    IF candidate_row.eligibility <> 'ELIGIBLE'
       OR candidate_row.rank IS NULL
       OR candidate_row.profile_content_sha256 IS NULL
       OR candidate_row.evidence_version_digest IS NULL
       OR input_row.source_capture_schema_version <> 1
       OR input_row.source_capture_canonicalization_version
            <> 'matching-source-capture-bundle-json-v1'
       OR input_row.source_capture_sha256
            <> sha256(input_row.canonical_source_capture_bytes)
       OR NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                input_row.source_capture->'profile'->'snapshots'
            ) AS snapshot(value)
            WHERE (snapshot.value->>'creator_user_id')::uuid
                    = candidate_row.creator_user_id
              AND (snapshot.value->>'profile_id')::uuid
                    = candidate_row.profile_id
              AND (snapshot.value->>'profile_version_id')::uuid
                    = candidate_row.profile_version_id
              AND decode(snapshot.value->>'content_sha256','hex')
                    = candidate_row.profile_content_sha256
              AND decode(snapshot.value->>'evidence_version_digest','hex')
                    = candidate_row.evidence_version_digest
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='MATCH_INPUT_CHANGED';
    END IF;
    PERFORM set_config(
        'app.rule_bundle_id',run_row.matching_rule_bundle_id::text,true
    );
    SELECT bundle.* INTO STRICT bundle_row
    FROM matching.rule_bundles AS bundle
    WHERE bundle.id=run_row.matching_rule_bundle_id;
    IF bundle_row.status <> 'ACTIVE'
       OR bundle_row.invitation_limit NOT BETWEEN 1 AND 100
       OR bundle_row.effective_at > transaction_timestamp()
       OR (bundle_row.effective_until IS NOT NULL
           AND bundle_row.effective_until <= transaction_timestamp())
       OR sha256(bundle_row.canonical_manifest_bytes)
            <> bundle_row.canonical_manifest_sha256
       OR (SELECT count(*) FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
              AND invitation.match_run_id=run_row.id)
            >= bundle_row.invitation_limit
       OR EXISTS (
            SELECT 1 FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
              AND invitation.creator_user_id=exact_creator_user_id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='INVITATION_ALREADY_EXISTS';
    END IF;
    expected_snapshot := matching.expected_invitation_disclosure_v1(
        exact_invitation_id,exact_organization_id,attempt_row.id,
        attempt_row.demand_id,attempt_row.demand_version_id,
        candidate_row.profile_id,candidate_row.profile_version_id,
        exact_expires_at,attempt_row.demand_content_sha256,
        candidate_row.profile_content_sha256,
        input_row.source_capture->'demand'->'content'
    );
    IF expected_snapshot IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    RETURN QUERY SELECT expected_snapshot;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.prepare_matching_invitation_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,uuid,uuid,timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.prepare_matching_invitation_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,uuid,uuid,timestamptz
) TO matching_review;

CREATE FUNCTION matching_api.create_matching_invitation_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_organization_id uuid,
    exact_assignment_id uuid,
    expected_assignment_version bigint,
    exact_match_run_id uuid,
    expected_match_run_version bigint,
    exact_creator_user_id uuid,
    exact_expires_at timestamptz,
    exact_canonical_snapshot_bytes bytea,
    exact_snapshot jsonb,
    exact_snapshot_sha256 bytea,
    exact_invitation_id uuid,
    exact_snapshot_id uuid,
    exact_hold_evidence_id uuid,
    exact_trust_evidence_sha256 bytea,
    exact_trust_evaluated_at timestamptz,
    exact_trust_valid_until timestamptz,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    assignment_row matching.matching_review_assignments%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    input_row matching.match_run_inputs%ROWTYPE;
    candidate_row matching.match_candidates%ROWTYPE;
    bundle_row matching.rule_bundles%ROWTYPE;
    expected_snapshot jsonb;
    response_body jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR expected_assignment_version < 1
       OR expected_match_run_version < 1
       OR sha256(exact_canonical_snapshot_bytes)
            <> exact_snapshot_sha256
       OR jsonb_typeof(exact_snapshot) <> 'object'
       OR octet_length(exact_trust_evidence_sha256) <> 32
       OR exact_trust_valid_until <= exact_trust_evaluated_at
       OR exact_trust_valid_until-exact_trust_evaluated_at
            > interval '15 seconds'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CREATE_INVITATION'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.match_run_id', true), '')
            IS DISTINCT FROM exact_match_run_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_match_run_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'USER',exact_actor_user_id,exact_organization_id,
        'CREATE_INVITATION',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_principal_marker_sha256,
        '/v1/operations/match-runs/'||exact_match_run_id::text
            ||'/invitations','MatchRun',exact_match_run_id,
        expected_match_run_version
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;
    IF exact_expires_at <= transaction_timestamp()
       OR exact_expires_at > transaction_timestamp()+interval '30 days'
       OR exact_trust_evaluated_at > transaction_timestamp()
       OR exact_trust_valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.id=exact_assignment_id
      AND assignment.organization_id=exact_organization_id
    FOR UPDATE;
    IF assignment_row.reviewer_user_id <> exact_actor_user_id
       OR assignment_row.reviewer_session_id <> exact_session_id
       OR assignment_row.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR assignment_row.role_code <> 'MATCHING_REVIEWER'
       OR assignment_row.duty_code <> 'OPERATIONS_REVIEWER'
       OR assignment_row.purpose_code <> 'INVITATION_REVIEW'
       OR assignment_row.status <> 'ACTIVE'
       OR assignment_row.aggregate_version <> expected_assignment_version
       OR assignment_row.expires_at <= transaction_timestamp()
       OR assignment_row.match_run_id <> exact_match_run_id THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',assignment_row.attempt_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=assignment_row.attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=exact_match_run_id
      AND run.attempt_id=attempt_row.id
    FOR UPDATE;
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.current_match_run_id <> run_row.id
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR run_row.aggregate_version <> expected_match_run_version THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    SELECT input.* INTO STRICT input_row
    FROM matching.match_run_inputs AS input
    WHERE input.match_run_id=run_row.id
      AND input.attempt_id=attempt_row.id;
    IF input_row.source_capture_schema_version <> 1
       OR input_row.source_capture_canonicalization_version
            <> 'matching-source-capture-bundle-json-v1'
       OR input_row.source_capture_sha256
            <> sha256(input_row.canonical_source_capture_bytes)
       OR input_row.source_authorization_valid_until
            <= input_row.captured_at THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='MATCH_INPUT_CHANGED';
    END IF;
    SELECT candidate.* INTO STRICT candidate_row
    FROM matching.match_candidates AS candidate
    WHERE candidate.match_run_id=run_row.id
      AND candidate.creator_user_id=exact_creator_user_id;
    IF candidate_row.eligibility <> 'ELIGIBLE'
       OR candidate_row.rank IS NULL
       OR candidate_row.profile_content_sha256 IS NULL
       OR candidate_row.evidence_version_digest IS NULL
       OR NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                input_row.source_capture->'profile'->'snapshots'
            ) AS snapshot(value)
            WHERE (snapshot.value->>'creator_user_id')::uuid
                    = candidate_row.creator_user_id
              AND (snapshot.value->>'profile_id')::uuid
                    = candidate_row.profile_id
              AND (snapshot.value->>'profile_version_id')::uuid
                    = candidate_row.profile_version_id
              AND decode(snapshot.value->>'content_sha256','hex')
                    = candidate_row.profile_content_sha256
              AND decode(snapshot.value->>'evidence_version_digest','hex')
                    = candidate_row.evidence_version_digest
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='MATCH_INPUT_CHANGED';
    END IF;
    PERFORM set_config(
        'app.rule_bundle_id',run_row.matching_rule_bundle_id::text,true
    );
    SELECT bundle.* INTO STRICT bundle_row
    FROM matching.rule_bundles AS bundle
    WHERE bundle.id=run_row.matching_rule_bundle_id;
    IF bundle_row.status <> 'ACTIVE'
       OR bundle_row.invitation_limit NOT BETWEEN 1 AND 100
       OR bundle_row.effective_at > transaction_timestamp()
       OR (bundle_row.effective_until IS NOT NULL
           AND bundle_row.effective_until <= transaction_timestamp())
       OR sha256(bundle_row.canonical_manifest_bytes)
            <> bundle_row.canonical_manifest_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='MATCH_RULE_BUNDLE_CHANGED';
    END IF;
    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=run_row.id
    ORDER BY invitation.id
    FOR UPDATE;
    IF (SELECT count(*) FROM matching.invitations AS invitation
        WHERE invitation.attempt_id=attempt_row.id
          AND invitation.match_run_id=run_row.id)
            >= bundle_row.invitation_limit
       OR EXISTS (
            SELECT 1 FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
              AND invitation.creator_user_id=exact_creator_user_id
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='INVITATION_ALREADY_EXISTS';
    END IF;

    expected_snapshot := matching.expected_invitation_disclosure_v1(
        exact_invitation_id,exact_organization_id,attempt_row.id,
        attempt_row.demand_id,attempt_row.demand_version_id,
        candidate_row.profile_id,candidate_row.profile_version_id,
        exact_expires_at,attempt_row.demand_content_sha256,
        candidate_row.profile_content_sha256,
        input_row.source_capture->'demand'->'content'
    );
    IF expected_snapshot IS NULL
       OR convert_from(exact_canonical_snapshot_bytes,'UTF8')::jsonb
            IS DISTINCT FROM expected_snapshot
       OR exact_snapshot - 'snapshot_sha256'
            IS DISTINCT FROM expected_snapshot
       OR exact_snapshot->>'snapshot_sha256'
            IS DISTINCT FROM encode(exact_snapshot_sha256,'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SET CONSTRAINTS ALL DEFERRED;
    INSERT INTO matching.invitations (
        id,organization_id,attempt_id,match_run_id,creator_user_id,
        profile_id,profile_version_id,profile_content_sha256,
        candidate_eligibility,demand_id,demand_version_id,funding_id,
        matching_rule_bundle_id,disclosure_snapshot_id,snapshot_sha256,
        creator_authority_marker_sha256,status,aggregate_version,expires_at,
        created_by_user_id,created_at,sent_at,responded_at,updated_at,
        candidate_evidence_version_digest
    ) VALUES (
        exact_invitation_id,exact_organization_id,attempt_row.id,run_row.id,
        candidate_row.creator_user_id,candidate_row.profile_id,
        candidate_row.profile_version_id,candidate_row.profile_content_sha256,
        'ELIGIBLE',attempt_row.demand_id,attempt_row.demand_version_id,
        attempt_row.funding_id,run_row.matching_rule_bundle_id,
        exact_snapshot_id,exact_snapshot_sha256,NULL,'CREATED',1,
        exact_expires_at,exact_actor_user_id,transaction_timestamp(),NULL,NULL,
        transaction_timestamp(),candidate_row.evidence_version_digest
    );
    INSERT INTO matching.invitation_disclosure_snapshots (
        id,invitation_id,organization_id,attempt_id,demand_id,
        demand_version_id,profile_id,profile_version_id,schema_version,
        canonicalization_version,canonical_snapshot_bytes,snapshot,
        demand_content_sha256,profile_content_sha256,snapshot_sha256,created_at
    ) VALUES (
        exact_snapshot_id,exact_invitation_id,exact_organization_id,
        attempt_row.id,attempt_row.demand_id,attempt_row.demand_version_id,
        candidate_row.profile_id,candidate_row.profile_version_id,1,
        'invitation-disclosure-json-v1',exact_canonical_snapshot_bytes,
        exact_snapshot,attempt_row.demand_content_sha256,
        candidate_row.profile_content_sha256,exact_snapshot_sha256,
        transaction_timestamp()
    );
    INSERT INTO matching.review_hold_evidence (
        id,command_id,operation,actor_user_id,organization_id,attempt_id,
        match_run_id,invitation_id,demand_id,demand_aggregate_version,
        demand_version_id,demand_content_sha256,policy_version,decision,
        evidence_sha256,evaluated_at,valid_until,recorded_at
    ) VALUES (
        exact_hold_evidence_id,exact_command_id,'CREATE_INVITATION',
        exact_actor_user_id,exact_organization_id,attempt_row.id,run_row.id,
        exact_invitation_id,attempt_row.demand_id,
        attempt_row.demand_aggregate_version,attempt_row.demand_version_id,
        attempt_row.demand_content_sha256,'demand-safety-hold-v1','ALLOW',
        exact_trust_evidence_sha256,exact_trust_evaluated_at,
        exact_trust_valid_until,transaction_timestamp()
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'USER',exact_actor_user_id,NULL,
        'CREATE_INVITATION','Invitation',exact_invitation_id,
        exact_organization_id,NULL,'CREATED',NULL,1,NULL,exact_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'attempt_id',attempt_row.id::text,
            'match_run_id',run_row.id::text,
            'review_assignment_id',assignment_row.id::text,
            'candidate_rank',candidate_row.rank,
            'trust_evidence_sha256',encode(
                exact_trust_evidence_sha256,'hex'
            )
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_outbox_event_id,'InvitationCreated','Invitation',
        exact_invitation_id,1,'USER',exact_actor_user_id,NULL,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'invitation_id',exact_invitation_id::text,
            'attempt_id',attempt_row.id::text,
            'run_id',run_row.id::text,
            'creator_user_id',candidate_row.creator_user_id::text,
            'profile_version_id',candidate_row.profile_version_id::text,
            'snapshot_sha256',encode(exact_snapshot_sha256,'hex'),
            'status','CREATED','expires_at',exact_expires_at,
            'reason_code',NULL
        )
    );
    response_body := matching.reviewer_invitation_projection_v1(
        exact_invitation_id
    );
    IF response_body IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,1,'CREATED',
        ARRAY['InvitationCreated']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.create_matching_invitation_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,uuid,timestamptz,bytea,
    jsonb,bytea,uuid,uuid,uuid,bytea,timestamptz,timestamptz,uuid,uuid,
    text,bytea,text,bytea,uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.create_matching_invitation_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,uuid,timestamptz,bytea,
    jsonb,bytea,uuid,uuid,uuid,bytea,timestamptz,timestamptz,uuid,uuid,
    text,bytea,text,bytea,uuid,uuid,uuid,uuid
) TO matching_review;

CREATE FUNCTION matching_api.publish_matching_invitation_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_organization_id uuid,
    exact_assignment_id uuid,
    expected_assignment_version bigint,
    exact_invitation_id uuid,
    expected_invitation_version bigint,
    expected_snapshot_sha256 bytea,
    exact_hold_evidence_id uuid,
    exact_trust_evidence_sha256 bytea,
    exact_trust_evaluated_at timestamptz,
    exact_trust_valid_until timestamptz,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_invitation_event_id uuid,
    exact_selection_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    assignment_row matching.matching_review_assignments%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    invitation_row matching.invitations%ROWTYPE;
    snapshot_row matching.invitation_disclosure_snapshots%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    candidate_row matching.match_candidates%ROWTYPE;
    new_invitation_version bigint;
    new_selection_version bigint;
    new_invitation_set_sha256 bytea;
    response_body jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR expected_assignment_version < 1
       OR expected_invitation_version < 1
       OR octet_length(expected_snapshot_sha256) <> 32
       OR octet_length(exact_trust_evidence_sha256) <> 32
       OR exact_trust_valid_until <= exact_trust_evaluated_at
       OR exact_trust_valid_until-exact_trust_evaluated_at
            > interval '15 seconds'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'PUBLISH_INVITATION'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'USER',exact_actor_user_id,exact_organization_id,
        'PUBLISH_INVITATION',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_principal_marker_sha256,
        '/v1/operations/matching-invitations/'
            ||exact_invitation_id::text||'/publish','Invitation',
        exact_invitation_id,expected_invitation_version
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;
    IF exact_trust_evaluated_at > transaction_timestamp()
       OR exact_trust_valid_until <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='INVALID_REQUEST';
    END IF;

    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.id=exact_assignment_id
      AND assignment.organization_id=exact_organization_id
    FOR UPDATE;
    IF assignment_row.reviewer_user_id <> exact_actor_user_id
       OR assignment_row.reviewer_session_id <> exact_session_id
       OR assignment_row.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR assignment_row.role_code <> 'MATCHING_REVIEWER'
       OR assignment_row.duty_code <> 'OPERATIONS_REVIEWER'
       OR assignment_row.purpose_code <> 'INVITATION_REVIEW'
       OR assignment_row.status <> 'ACTIVE'
       OR assignment_row.aggregate_version <> expected_assignment_version
       OR assignment_row.expires_at <= transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',assignment_row.attempt_id::text,true);
    PERFORM set_config('app.match_run_id',assignment_row.match_run_id::text,true);
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=assignment_row.attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
      AND selection.attempt_id=attempt_row.id
    FOR UPDATE;
    SELECT run.* INTO STRICT run_row
    FROM matching.match_runs AS run
    WHERE run.id=assignment_row.match_run_id
      AND run.attempt_id=attempt_row.id
    FOR SHARE;
    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=run_row.id
    ORDER BY invitation.id
    FOR UPDATE;
    SELECT invitation.* INTO STRICT invitation_row
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id
      AND invitation.attempt_id=attempt_row.id;
    SELECT snapshot.* INTO STRICT snapshot_row
    FROM matching.invitation_disclosure_snapshots AS snapshot
    WHERE snapshot.id=invitation_row.disclosure_snapshot_id
      AND snapshot.invitation_id=invitation_row.id;
    SELECT candidate.* INTO STRICT candidate_row
    FROM matching.match_candidates AS candidate
    WHERE candidate.match_run_id=run_row.id
      AND candidate.creator_user_id=invitation_row.creator_user_id;
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.current_match_run_id <> run_row.id
       OR selection_row.status <> 'OPEN'
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR run_row.status <> 'COMPLETED'
       OR run_row.superseded_by_run_id IS NOT NULL
       OR invitation_row.match_run_id <> run_row.id
       OR invitation_row.status <> 'CREATED'
       OR invitation_row.aggregate_version <> expected_invitation_version
       OR invitation_row.expires_at <= transaction_timestamp()
       OR invitation_row.snapshot_sha256 <> expected_snapshot_sha256
       OR snapshot_row.snapshot_sha256 <> expected_snapshot_sha256
       OR sha256(snapshot_row.canonical_snapshot_bytes)
            <> snapshot_row.snapshot_sha256
       OR snapshot_row.snapshot - 'snapshot_sha256'
            IS DISTINCT FROM convert_from(
                snapshot_row.canonical_snapshot_bytes,'UTF8'
            )::jsonb
       OR candidate_row.eligibility <> 'ELIGIBLE'
       OR candidate_row.profile_id <> invitation_row.profile_id
       OR candidate_row.profile_version_id
            <> invitation_row.profile_version_id
       OR candidate_row.profile_content_sha256
            <> invitation_row.profile_content_sha256
       OR candidate_row.evidence_version_digest
            <> invitation_row.candidate_evidence_version_digest
       OR invitation_row.creator_authority_marker_sha256 IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;

    new_invitation_version := invitation_row.aggregate_version+1;
    UPDATE matching.invitations
    SET status='SENT',aggregate_version=new_invitation_version,
        sent_at=transaction_timestamp(),updated_at=transaction_timestamp()
    WHERE id=invitation_row.id;
    new_invitation_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,run_row.id
    );
    new_selection_version := selection_row.aggregate_version+1;
    UPDATE matching.selections
    SET current_invitation_set_sha256=new_invitation_set_sha256,
        aggregate_version=new_selection_version,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id;
    INSERT INTO matching.review_hold_evidence (
        id,command_id,operation,actor_user_id,organization_id,attempt_id,
        match_run_id,invitation_id,demand_id,demand_aggregate_version,
        demand_version_id,demand_content_sha256,policy_version,decision,
        evidence_sha256,evaluated_at,valid_until,recorded_at
    ) VALUES (
        exact_hold_evidence_id,exact_command_id,'PUBLISH_INVITATION',
        exact_actor_user_id,exact_organization_id,attempt_row.id,run_row.id,
        invitation_row.id,attempt_row.demand_id,
        attempt_row.demand_aggregate_version,attempt_row.demand_version_id,
        attempt_row.demand_content_sha256,'demand-safety-hold-v1','ALLOW',
        exact_trust_evidence_sha256,exact_trust_evaluated_at,
        exact_trust_valid_until,transaction_timestamp()
    );
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'USER',exact_actor_user_id,NULL,
        'PUBLISH_INVITATION','Invitation',invitation_row.id,
        exact_organization_id,'CREATED','SENT',invitation_row.aggregate_version,
        new_invitation_version,NULL,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'attempt_id',attempt_row.id::text,
            'match_run_id',run_row.id::text,
            'selection_id',selection_row.id::text,
            'selection_version',new_selection_version,
            'review_assignment_id',assignment_row.id::text,
            'trust_evidence_sha256',encode(
                exact_trust_evidence_sha256,'hex'
            )
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_invitation_event_id,'InvitationSent','Invitation',
        invitation_row.id,new_invitation_version,'USER',exact_actor_user_id,
        NULL,exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'invitation_id',invitation_row.id::text,
            'attempt_id',attempt_row.id::text,
            'run_id',run_row.id::text,
            'creator_user_id',invitation_row.creator_user_id::text,
            'profile_version_id',invitation_row.profile_version_id::text,
            'snapshot_sha256',encode(invitation_row.snapshot_sha256,'hex'),
            'status','SENT','expires_at',invitation_row.expires_at,
            'reason_code',NULL
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_selection_event_id,'SelectionInvitationSetChanged','Selection',
        selection_row.id,new_selection_version,'USER',exact_actor_user_id,
        NULL,exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',attempt_row.id::text,'status','OPEN',
            'current_invitation_set_sha256',encode(
                new_invitation_set_sha256,'hex'
            ),'chosen_invitation_id',NULL,'selection_basis_code',NULL,
            'reason_code',NULL
        )
    );
    response_body := matching.reviewer_invitation_projection_v1(
        invitation_row.id
    );
    IF response_body IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_invitation_version,'SENT',
        ARRAY['InvitationSent','SelectionInvitationSetChanged']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.publish_matching_invitation_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,bytea,uuid,bytea,
    timestamptz,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,
    uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.publish_matching_invitation_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,bytea,uuid,bytea,
    timestamptz,timestamptz,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,
    uuid,uuid
) TO matching_review;

CREATE FUNCTION matching_api.invalidate_matching_attempt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_organization_id uuid,
    exact_assignment_id uuid,
    expected_assignment_version bigint,
    exact_attempt_id uuid,
    expected_attempt_version bigint,
    expected_input_baseline_sha256 bytea,
    exact_reason_code text,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_audit_event_id uuid,
    exact_attempt_event_id uuid,
    exact_selection_event_id uuid,
    exact_invitation_event_ids uuid[],
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    receipt_result record;
    assignment_row matching.matching_review_assignments%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    invitation_row matching.invitations%ROWTYPE;
    affected_invitation_count integer;
    invitation_index integer := 0;
    new_attempt_version bigint;
    new_selection_version bigint;
    new_invitation_set_sha256 bytea;
    response_body jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR expected_assignment_version < 1
       OR expected_attempt_version < 1
       OR octet_length(expected_input_baseline_sha256) <> 32
       OR exact_reason_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
       OR exact_invitation_event_ids IS NULL
       OR cardinality(exact_invitation_event_ids) > 100
       OR cardinality(exact_invitation_event_ids) <> cardinality(ARRAY(
            SELECT DISTINCT value
            FROM unnest(exact_invitation_event_ids) AS value
       ))
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'INVALIDATE_ATTEMPT'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.attempt_id', true), '')
            IS DISTINCT FROM exact_attempt_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_attempt_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    SELECT * INTO receipt_result
    FROM matching.claim_operational_receipt_v1(
        exact_receipt_id,'USER',exact_actor_user_id,exact_organization_id,
        'INVALIDATE_ATTEMPT',exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        exact_principal_marker_sha256,
        '/v1/operations/matching-attempts/'||exact_attempt_id::text
            ||'/invalidate','MatchingAttempt',exact_attempt_id,
        expected_attempt_version
    );
    IF receipt_result.replayed THEN
        RETURN QUERY SELECT receipt_result.safe_response,true;
        RETURN;
    END IF;

    SELECT assignment.* INTO STRICT assignment_row
    FROM matching.matching_review_assignments AS assignment
    WHERE assignment.id=exact_assignment_id
      AND assignment.organization_id=exact_organization_id
    FOR UPDATE;
    IF assignment_row.reviewer_user_id <> exact_actor_user_id
       OR assignment_row.reviewer_session_id <> exact_session_id
       OR assignment_row.authority_marker_sha256
            <> exact_principal_marker_sha256
       OR assignment_row.role_code <> 'MATCHING_REVIEWER'
       OR assignment_row.duty_code <> 'OPERATIONS_REVIEWER'
       OR assignment_row.purpose_code NOT IN (
            'INVITATION_REVIEW','ATTEMPT_REVIEW'
       )
       OR assignment_row.status <> 'ACTIVE'
       OR assignment_row.aggregate_version <> expected_assignment_version
       OR assignment_row.expires_at <= transaction_timestamp()
       OR assignment_row.attempt_id <> exact_attempt_id THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    SELECT attempt.* INTO STRICT attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=exact_attempt_id
      AND attempt.organization_id=exact_organization_id
    FOR UPDATE;
    SELECT selection.* INTO STRICT selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
      AND selection.attempt_id=attempt_row.id
    FOR UPDATE;
    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=attempt_row.current_match_run_id
    ORDER BY invitation.id
    FOR UPDATE;
    SELECT count(*) INTO affected_invitation_count
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=attempt_row.current_match_run_id
      AND invitation.status IN ('CREATED','SENT','ACCEPTED');
    IF attempt_row.status <> 'OPEN'
       OR attempt_row.aggregate_version <> expected_attempt_version
       OR attempt_row.input_baseline_sha256
            <> expected_input_baseline_sha256
       OR selection_row.status <> 'OPEN'
       OR cardinality(exact_invitation_event_ids)
            <> affected_invitation_count
       OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1 FROM matching.selection_close_intents AS intent
            WHERE intent.selection_id=selection_row.id
       )
       OR EXISTS (
            SELECT 1
            FROM matching.candidate_selector_assignments AS selector
            WHERE selector.selection_id=selection_row.id
              AND selector.status='ACTIVE'
              AND selector.expires_at > transaction_timestamp()
       ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;

    FOR invitation_row IN
        SELECT invitation.*
        FROM matching.invitations AS invitation
        WHERE invitation.attempt_id=attempt_row.id
          AND invitation.match_run_id=attempt_row.current_match_run_id
          AND invitation.status IN ('CREATED','SENT','ACCEPTED')
        ORDER BY invitation.id
    LOOP
        invitation_index := invitation_index+1;
        UPDATE matching.invitations
        SET status='REVOKED',aggregate_version=aggregate_version+1,
            updated_at=transaction_timestamp()
        WHERE id=invitation_row.id;
        PERFORM matching.record_operational_outbox_v1(
            exact_invitation_event_ids[invitation_index],
            'InvitationRevoked','Invitation',invitation_row.id,
            invitation_row.aggregate_version+1,'USER',exact_actor_user_id,
            NULL,exact_organization_id,exact_command_id,
            exact_correlation_id,exact_trace_id,jsonb_build_object(
                'invitation_id',invitation_row.id::text,
                'attempt_id',attempt_row.id::text,
                'run_id',invitation_row.match_run_id::text,
                'creator_user_id',invitation_row.creator_user_id::text,
                'profile_version_id',invitation_row.profile_version_id::text,
                'snapshot_sha256',encode(
                    invitation_row.snapshot_sha256,'hex'
                ),'status','REVOKED','expires_at',invitation_row.expires_at,
                'reason_code',exact_reason_code
            )
        );
    END LOOP;
    new_invitation_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,attempt_row.current_match_run_id
    );
    new_selection_version := selection_row.aggregate_version+1;
    UPDATE matching.selections
    SET status='CANCELLED',aggregate_version=new_selection_version,
        current_invitation_set_sha256=new_invitation_set_sha256,
        reason_code=exact_reason_code,updated_at=transaction_timestamp()
    WHERE id=selection_row.id;
    new_attempt_version := attempt_row.aggregate_version+1;
    UPDATE matching.matching_attempts
    SET status='INVALIDATED',aggregate_version=new_attempt_version,
        updated_at=transaction_timestamp(),terminal_at=transaction_timestamp()
    WHERE id=attempt_row.id;
    PERFORM matching.record_operational_audit_v1(
        exact_audit_event_id,'USER',exact_actor_user_id,NULL,
        'INVALIDATE_ATTEMPT','MatchingAttempt',attempt_row.id,
        exact_organization_id,'OPEN','INVALIDATED',
        attempt_row.aggregate_version,new_attempt_version,
        exact_reason_code,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'match_run_id',attempt_row.current_match_run_id::text,
            'selection_id',selection_row.id::text,
            'selection_version',new_selection_version,
            'revoked_invitation_count',affected_invitation_count,
            'review_assignment_id',assignment_row.id::text
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_selection_event_id,'SelectionCancelled','Selection',
        selection_row.id,new_selection_version,'USER',exact_actor_user_id,
        NULL,exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',attempt_row.id::text,'status','CANCELLED',
            'current_invitation_set_sha256',encode(
                new_invitation_set_sha256,'hex'
            ),'chosen_invitation_id',NULL,'selection_basis_code',NULL,
            'reason_code',exact_reason_code
        )
    );
    PERFORM matching.record_operational_outbox_v1(
        exact_attempt_event_id,'MatchingAttemptInvalidated',
        'MatchingAttempt',attempt_row.id,new_attempt_version,'USER',
        exact_actor_user_id,NULL,exact_organization_id,exact_command_id,
        exact_correlation_id,exact_trace_id,jsonb_build_object(
            'attempt_id',attempt_row.id::text,
            'demand_id',attempt_row.demand_id::text,
            'demand_version_id',attempt_row.demand_version_id::text,
            'matching_request_id',attempt_row.matching_request_id::text,
            'attempt_no',attempt_row.attempt_no,'status','INVALIDATED',
            'reason_code',exact_reason_code,
            'selection_id',selection_row.id::text,
            'chosen_invitation_id',NULL
        )
    );
    response_body := matching.reviewer_attempt_projection_v1(attempt_row.id);
    IF response_body IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_attempt_version,'INVALIDATED',
        ARRAY['InvitationRevoked','SelectionCancelled',
            'MatchingAttemptInvalidated']::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.invalidate_matching_attempt_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,bytea,text,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid[],uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.invalidate_matching_attempt_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,uuid,bigint,bytea,text,uuid,uuid,text,
    bytea,text,bytea,uuid,uuid,uuid,uuid[],uuid,uuid
) TO matching_review;

-- One closed, least-privileged dependency snapshot lets the worker and
-- coordinator prove exact schema metadata rather than accepting an ABI that
-- happens to remain callable at a stale dependency head.  The Matching
-- manifest is returned (not embedded) so the Python package can compare its
-- final reviewed self-hash without a circular SQL -> manifest -> SQL digest.
CREATE FUNCTION matching_api.read_runtime_dependency_snapshot_v1()
RETURNS TABLE (
    matching_current_schema_version integer,
    matching_schema_head_version integer,
    matching_min_app_compatible_version integer,
    matching_max_app_compatible_version integer,
    matching_required_iam_schema_version integer,
    matching_migration_manifest_sha256 bytea,
    iam_current_schema_version integer,
    iam_schema_head_version integer,
    iam_min_app_compatible_version integer,
    iam_max_app_compatible_version integer,
    iam_combined_contract_sha256 bytea,
    demand_current_schema_version integer,
    demand_schema_head_version integer,
    demand_min_app_compatible_version integer,
    demand_max_app_compatible_version integer,
    demand_required_iam_schema_version integer,
    demand_migration_manifest_sha256 bytea,
    profile_current_schema_version integer,
    profile_schema_head_version integer,
    profile_min_app_compatible_version integer,
    profile_max_app_compatible_version integer,
    profile_required_iam_schema_version integer,
    profile_migration_manifest_sha256 bytea,
    trust_current_schema_version integer,
    trust_schema_head_version integer,
    trust_min_app_compatible_version integer,
    trust_max_app_compatible_version integer,
    trust_required_iam_schema_version integer,
    trust_required_demand_schema_version integer,
    trust_required_iam_contract_sha256 bytea,
    trust_required_demand_contract_sha256 bytea,
    trust_combined_contract_sha256 bytea,
    trust_migration_manifest_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
BEGIN
    IF session_user NOT IN ('matching_worker', 'matching_coordinator')
       OR current_user IS DISTINCT FROM 'matching_schema_owner' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    RETURN QUERY
    SELECT
        matching_contract.current_schema_version,
        matching_contract.schema_head_version,
        matching_contract.min_app_compatible_version,
        matching_contract.max_app_compatible_version,
        matching_contract.required_iam_schema_version,
        matching_contract.migration_manifest_sha256,
        iam_contract.current_schema_version,
        iam_contract.schema_head_version,
        iam_contract.min_app_compatible_version,
        iam_contract.max_app_compatible_version,
        iam_contract.combined_contract_sha256,
        demand_contract.current_schema_version,
        demand_contract.schema_head_version,
        demand_contract.min_app_compatible_version,
        demand_contract.max_app_compatible_version,
        demand_contract.required_iam_schema_version,
        demand_contract.migration_manifest_sha256,
        profile_contract.current_schema_version,
        profile_contract.schema_head_version,
        profile_contract.min_app_compatible_version,
        profile_contract.max_app_compatible_version,
        46::integer,
        profile_contract.migration_manifest_sha256,
        trust_contract.current_schema_version,
        trust_contract.schema_head_version,
        trust_contract.min_app_compatible_version,
        trust_contract.max_app_compatible_version,
        trust_contract.required_iam_schema_version,
        trust_contract.required_demand_schema_version,
        trust_contract.required_iam_contract_sha256,
        trust_contract.required_demand_contract_sha256,
        trust_contract.combined_contract_sha256,
        trust_contract.migration_manifest_sha256
    FROM matching.schema_compatibility AS matching_contract
    CROSS JOIN infra.iam_schema_compatibility AS iam_contract
    CROSS JOIN demand.schema_compatibility AS demand_contract
    CROSS JOIN profile.schema_compatibility AS profile_contract
    CROSS JOIN trust.schema_compatibility AS trust_contract
    WHERE matching_contract.component = 'matching'
      AND iam_contract.component = 'iam'
      AND demand_contract.component = 'demand'
      AND profile_contract.component = 'profile'
      AND trust_contract.component = 'trust';
END
$function$;

REVOKE ALL ON FUNCTION
matching_api.read_runtime_dependency_snapshot_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
matching_api.read_runtime_dependency_snapshot_v1()
TO matching_worker, matching_coordinator;
