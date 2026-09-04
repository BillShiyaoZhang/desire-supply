-- Recover only an exact completed CREATE_INVITATION receipt before preparing
-- another disclosure. Matching1-6 remain byte exact. New writes still use the
-- existing reviewer, rule, Trust, duplicate, and atomic receipt procedures.

CREATE FUNCTION matching_api.read_create_invitation_receipt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_principal_marker_sha256 bytea,
    exact_organization_id uuid,
    exact_match_run_id uuid,
    expected_match_run_version bigint,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    existing matching.command_receipts%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_match_run_id IS NULL
       OR expected_match_run_version IS NULL OR expected_match_run_version < 1
       OR exact_principal_marker_sha256 IS NULL
       OR octet_length(exact_principal_marker_sha256) <> 32
       OR exact_identity_key_id IS NULL
       OR length(exact_identity_key_id) NOT BETWEEN 1 AND 128
       OR exact_identity_digest IS NULL
       OR octet_length(exact_identity_digest) <> 32
       OR exact_payload_hash_key_id IS NULL
       OR length(exact_payload_hash_key_id) NOT BETWEEN 1 AND 128
       OR exact_payload_hash IS NULL OR octet_length(exact_payload_hash) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
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
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(exact_principal_marker_sha256,'hex')
       OR COALESCE(current_setting('app.command_id', true), '') <> ''
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.invitation_id', true), '') <> '' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    SELECT receipt.* INTO existing
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.organization_id = exact_organization_id
      AND receipt.operation = 'CREATE_INVITATION'
      AND receipt.command_version = 1
      AND receipt.identity_key_id = exact_identity_key_id
      AND receipt.identity_digest = exact_identity_digest;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    -- A completed receipt does not confer current reviewer authority. The
    -- existing restrictive policy also binds this read to actor/session/marker.
    IF NOT EXISTS (
        SELECT 1 FROM matching.matching_review_assignments AS assignment
        WHERE assignment.organization_id = exact_organization_id
          AND assignment.match_run_id = exact_match_run_id
          AND assignment.reviewer_user_id = exact_actor_user_id
          AND assignment.reviewer_session_id = exact_session_id
          AND assignment.authority_marker_sha256 = exact_principal_marker_sha256
          AND assignment.role_code = 'MATCHING_REVIEWER'
          AND assignment.duty_code = 'OPERATIONS_REVIEWER'
          AND assignment.purpose_code = 'INVITATION_REVIEW'
          AND assignment.status = 'ACTIVE'
          AND assignment.expires_at > transaction_timestamp()
    ) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;

    IF existing.payload_hash_key_id IS DISTINCT FROM exact_payload_hash_key_id
       OR existing.payload_hash IS DISTINCT FROM exact_payload_hash
       OR existing.principal_authority_marker_sha256
            IS DISTINCT FROM exact_principal_marker_sha256
       OR existing.canonical_path IS DISTINCT FROM
            '/v1/operations/match-runs/'||exact_match_run_id::text||'/invitations'
       OR existing.target_kind IS DISTINCT FROM 'MatchRun'
       OR existing.target_id IS DISTINCT FROM exact_match_run_id
       OR existing.if_match_version IS DISTINCT FROM expected_match_run_version
    THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='IDEMPOTENCY_KEY_REUSED';
    END IF;
    IF existing.status IS DISTINCT FROM 'COMPLETED'
       OR existing.canonicalization_version IS DISTINCT FROM 'matching-command-json-v1'
       OR existing.http_method IS DISTINCT FROM 'POST'
       OR existing.response_http_status IS DISTINCT FROM 200
       OR existing.response_schema_name IS DISTINCT FROM 'MatchingCommandResult'
       OR existing.response_schema_version IS DISTINCT FROM 1
       OR existing.result_status IS DISTINCT FROM 'CREATED'
       OR existing.target_version IS DISTINCT FROM 1
       OR existing.event_types IS DISTINCT FROM ARRAY['InvitationCreated']::text[]
       OR existing.safe_response_body IS NULL
       OR jsonb_typeof(existing.safe_response_body) IS DISTINCT FROM 'object'
       OR NOT (existing.safe_response_body ?& ARRAY[
            'invitation_id','attempt_id','match_run_id','creator_user_id',
            'status','aggregate_version','updated_at','expires_at','snapshot_sha256'
       ]::text[])
       OR (SELECT count(*) FROM jsonb_object_keys(existing.safe_response_body)) <> 9
       OR existing.safe_response_body->>'status' IS DISTINCT FROM 'CREATED'
       OR existing.safe_response_body->'aggregate_version' IS DISTINCT FROM '1'::jsonb
       OR existing.safe_response_body->>'match_run_id'
            IS DISTINCT FROM exact_match_run_id::text
    THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    RETURN QUERY SELECT existing.safe_response_body,true;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.read_create_invitation_receipt_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,text,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.read_create_invitation_receipt_v1(
    uuid,uuid,bytea,uuid,uuid,bigint,text,bytea,text,bytea
) TO matching_review;
