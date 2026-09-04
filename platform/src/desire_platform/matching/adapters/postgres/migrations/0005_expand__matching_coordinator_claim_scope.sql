-- Repair the exact-target dependent reads during coordinator job claim.
-- Matching1-4 remain byte exact. The locked job derives organization/selection
-- under the original workload and authority marker; only its detail reads use
-- the existing MATCHING_COORDINATOR scope. No policies or grants are widened.
-- Like worker claims, the first lease has no preceding audit version.

CREATE OR REPLACE FUNCTION matching_api.claim_selection_completion_v1(
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
    -- Only the locked, workload-authorized job supplies this target scope.
    -- The caller still cannot supply an organization or selection to claim.
    PERFORM set_config('app.scope_kind','MATCHING_COORDINATOR',true);
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
    PERFORM set_config('app.scope_kind','MATCHING_COORDINATOR_CLAIM',true);
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
        old_status,result_status,NULLIF(old_fence,0),new_fence,
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
