-- Repair the operational ingest procedure's local-variable/column ambiguity.
-- Matching1-3 remain byte exact. The signature, grants, actor checks, receipts,
-- immutable source binding and atomic request graph are unchanged.
-- A local block label makes SQL predicates explicit without changing the
-- database/session PL/pgSQL name-resolution policy.

CREATE OR REPLACE FUNCTION matching_api.ingest_matching_requested_v1(
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
<<ingest>>
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
      AND inbox.source_event_id=ingest.source_event_id
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
          AND attempt.demand_id=ingest.demand_id AND attempt.status='OPEN'
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',
            MESSAGE='PRECONDITION_FAILED';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM matching.rule_selectors AS selector
        JOIN matching.rule_bundles AS bundle
          ON bundle.id=selector.current_bundle_id
         AND bundle.selector_digest=selector.selector_digest
        WHERE selector.selector_digest=ingest.selector_digest
          AND bundle.id=ingest.matching_rule_bundle_id
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
      AND attempt.demand_id=ingest.demand_id;
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
    UPDATE matching.source_inbox AS inbox
    SET status='COMPLETED',target_attempt_id=exact_attempt_id,
        target_aggregate_version=1,
        result_event_types=ARRAY['MatchingAttemptOpened','MatchRunQueued'],
        completed_at=transaction_timestamp()
    WHERE inbox.consumer_name='matching-requested-v1'
      AND inbox.source_event_id=ingest.source_event_id
      AND inbox.status='IN_PROGRESS';

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
