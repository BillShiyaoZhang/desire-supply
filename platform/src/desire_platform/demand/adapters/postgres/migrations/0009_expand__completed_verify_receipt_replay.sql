-- Exact completed VerifyDemand receipt recovery before ACTIVE target discovery.
-- This remains a demand_review SECURITY INVOKER program: IAM 0036 already
-- exposes the exact reviewer resolver and lock needed for current authority.

SET LOCAL ROLE demand_schema_owner;

DO $demand9_prerequisites$
DECLARE
    receipt_boundaries_are_exact boolean;
BEGIN
    SELECT
        count(*) = 2
        AND bool_and(
            owner_role.rolname = 'demand_schema_owner'
            AND relation.relrowsecurity
            AND relation.relforcerowsecurity
        )
    INTO STRICT receipt_boundaries_are_exact
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = relation.relowner
    WHERE relation.oid IN (
        'demand.command_receipts'::regclass,
        'demand.receipt_key_policy'::regclass
    );
    IF receipt_boundaries_are_exact IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_VERIFY_REPLAY_PREREQUISITE_DRIFTED';
    END IF;
END
$demand9_prerequisites$;

CREATE POLICY rls_demand_verify_replay_receipt_discovery
ON demand.command_receipts
FOR SELECT TO demand_review
USING (
    session_user = 'demand_review'
    AND current_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_VERIFY_REPLAY'
    AND NULLIF(current_setting('app.operation', true), '') = 'VERIFY'
    AND receipt_id::text
        = NULLIF(current_setting('app.command_id', true), '')
);

CREATE POLICY rls_demand_verify_replay_receipt_lock
ON demand.command_receipts
FOR UPDATE TO demand_review
USING (
    session_user = 'demand_review'
    AND current_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_VERIFY_REPLAY'
    AND NULLIF(current_setting('app.operation', true), '') = 'VERIFY'
    AND receipt_id::text
        = NULLIF(current_setting('app.command_id', true), '')
)
WITH CHECK (
    session_user = 'demand_review'
    AND current_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_VERIFY_REPLAY'
    AND NULLIF(current_setting('app.operation', true), '') = 'VERIFY'
    AND receipt_id::text
        = NULLIF(current_setting('app.command_id', true), '')
);

CREATE FUNCTION demand.reject_verify_replay_receipt_mutation_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    IF session_user = 'demand_review'
       AND current_user = 'demand_review'
       AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'DEMAND_VERIFY_REPLAY' THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_VERIFY_REPLAY_IS_READ_ONLY';
    END IF;
    RETURN NEW;
END
$function$;

REVOKE ALL ON FUNCTION demand.reject_verify_replay_receipt_mutation_v1()
FROM PUBLIC;

CREATE TRIGGER command_receipts_verify_replay_read_only
BEFORE UPDATE ON demand.command_receipts
FOR EACH ROW
EXECUTE FUNCTION demand.reject_verify_replay_receipt_mutation_v1();

CREATE FUNCTION demand_api.read_completed_verify_receipt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_receipt_id uuid,
    exact_demand_id uuid,
    exact_assignment_id uuid,
    exact_if_match_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (
    organization_id uuid,
    authority_marker_sha256 bytea,
    aggregate_version bigint,
    demand_version_id uuid
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    existing demand.command_receipts%ROWTYPE;
    key_policy demand.receipt_key_policy%ROWTYPE;
    current_authority_marker bytea;
    current_duty_grant_id uuid;
    current_duty_grant_version bigint;
    receipt_keys text[];
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'demand_review'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_assignment_id IS NULL OR exact_assignment_id = zero_uuid
       OR exact_if_match_version IS NULL OR exact_if_match_version < 1
       OR exact_idempotency_key_digest_key_ids IS NULL
       OR exact_idempotency_key_digests IS NULL
       OR exact_payload_hash_key_ids IS NULL
       OR exact_payload_hashes IS NULL
       OR array_ndims(exact_idempotency_key_digest_key_ids) <> 1
       OR array_ndims(exact_idempotency_key_digests) <> 1
       OR array_ndims(exact_payload_hash_key_ids) <> 1
       OR array_ndims(exact_payload_hashes) <> 1
       OR array_lower(exact_idempotency_key_digest_key_ids, 1) <> 1
       OR array_lower(exact_idempotency_key_digests, 1) <> 1
       OR array_lower(exact_payload_hash_key_ids, 1) <> 1
       OR array_lower(exact_payload_hashes, 1) <> 1
       OR cardinality(exact_idempotency_key_digest_key_ids)
            NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR EXISTS (
            SELECT 1
            FROM unnest(
                exact_idempotency_key_digest_key_ids
            ) AS key_id(value)
            WHERE key_id.value IS NULL
               OR key_id.value = ''
               OR octet_length(key_id.value) > 128
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hash_key_ids) AS key_id(value)
            WHERE key_id.value IS NULL
               OR key_id.value = ''
               OR octet_length(key_id.value) > 128
       )
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
            FROM unnest(
                exact_idempotency_key_digest_key_ids
            ) AS item(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_VERIFY_REPLAY'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'VERIFY'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '')
            IS DISTINCT FROM exact_assignment_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_receipt_id::text
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    SELECT receipt.* INTO existing
    FROM demand.command_receipts AS receipt
    WHERE receipt.receipt_id = exact_receipt_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT policy.* INTO STRICT key_policy
    FROM demand.receipt_key_policy AS policy
    WHERE policy.singleton_key;
    IF key_policy.active_canonicalization_version
            IS DISTINCT FROM 'demand-command-json-v1'
       OR array_ndims(key_policy.retained_idempotency_key_ids)
            IS DISTINCT FROM 1
       OR array_lower(key_policy.retained_idempotency_key_ids, 1)
            IS DISTINCT FROM 1
       OR cardinality(key_policy.retained_idempotency_key_ids)
            NOT BETWEEN 1 AND 4
       OR key_policy.retained_idempotency_key_ids[1]
            IS DISTINCT FROM key_policy.active_idempotency_key_id
       OR EXISTS (
            SELECT 1
            FROM unnest(
                key_policy.retained_idempotency_key_ids
            ) AS key_id(value)
            WHERE key_id.value IS NULL
               OR key_id.value = ''
               OR octet_length(key_id.value) > 128
       )
       OR (
            SELECT count(DISTINCT value) IS DISTINCT FROM count(*)
            FROM unnest(
                key_policy.retained_idempotency_key_ids
            ) AS key_id(value)
       )
       OR array_ndims(key_policy.retained_payload_key_ids)
            IS DISTINCT FROM 1
       OR array_lower(key_policy.retained_payload_key_ids, 1)
            IS DISTINCT FROM 1
       OR cardinality(key_policy.retained_payload_key_ids)
            NOT BETWEEN 1 AND 4
       OR key_policy.retained_payload_key_ids[1]
            IS DISTINCT FROM key_policy.active_payload_key_id
       OR EXISTS (
            SELECT 1
            FROM unnest(
                key_policy.retained_payload_key_ids
            ) AS key_id(value)
            WHERE key_id.value IS NULL
               OR key_id.value = ''
               OR octet_length(key_id.value) > 128
       )
       OR (
            SELECT count(DISTINCT value) IS DISTINCT FROM count(*)
            FROM unnest(
                key_policy.retained_payload_key_ids
            ) AS key_id(value)
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(
                key_policy.retained_idempotency_key_ids
            ) AS idempotency_key(key_id)
            JOIN unnest(
                key_policy.retained_payload_key_ids
            ) AS payload_key(key_id)
              ON idempotency_key.key_id = payload_key.key_id
       )
       OR exact_idempotency_key_digest_key_ids[1]
            IS DISTINCT FROM key_policy.active_idempotency_key_id
       OR exact_payload_hash_key_ids[1]
            IS DISTINCT FROM key_policy.active_payload_key_id
       OR EXISTS (
            SELECT 1
            FROM unnest(
                exact_idempotency_key_digest_key_ids
            ) AS candidate(key_id)
            WHERE NOT EXISTS (
                SELECT 1
                FROM unnest(
                    key_policy.retained_idempotency_key_ids
                ) AS retained(key_id)
                WHERE retained.key_id = candidate.key_id
            )
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hash_key_ids) AS candidate(key_id)
            WHERE NOT EXISTS (
                SELECT 1
                FROM unnest(
                    key_policy.retained_payload_key_ids
                ) AS retained(key_id)
                WHERE retained.key_id = candidate.key_id
            )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;

    IF existing.principal_kind IS DISTINCT FROM 'USER'
       OR existing.principal_id IS DISTINCT FROM exact_actor_user_id
       OR existing.command_name IS DISTINCT FROM 'VerifyDemand'
       OR existing.command_version IS DISTINCT FROM 1
       OR existing.canonicalization_version
            IS DISTINCT FROM 'demand-command-json-v1'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_VERIFY_RECEIPT_REPLAY_INVALID';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM generate_subscripts(
            exact_idempotency_key_digests, 1
        ) AS slot(index)
        WHERE exact_idempotency_key_digest_key_ids[slot.index]
                = existing.idempotency_key_digest_key_id
          AND exact_idempotency_key_digests[slot.index]
                = existing.idempotency_key_digest
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_RECEIPT_KEY_UNAVAILABLE';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
        WHERE exact_payload_hash_key_ids[slot.index]
                = existing.payload_hash_key_id
          AND exact_payload_hashes[slot.index] = existing.payload_hash
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'uq_demand_receipt_identity',
            MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
    END IF;

    IF existing.http_method IS DISTINCT FROM 'POST'
       OR existing.canonical_path IS DISTINCT FROM
            '/v1/operations/demand-review-assignments/' ||
            exact_assignment_id::text || '/verify'
       OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
       OR existing.retain_until <= transaction_timestamp()
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_VERIFY_RECEIPT_REPLAY_INVALID';
    END IF;

    IF existing.status = 'IN_PROGRESS' THEN
        IF existing.response_http_status IS NOT NULL
           OR existing.response_schema_name IS NOT NULL
           OR existing.response_schema_version IS NOT NULL
           OR existing.response_entity_tag IS NOT NULL
           OR existing.safe_response_body IS NOT NULL
           OR existing.target_id IS NOT NULL
           OR existing.target_version IS NOT NULL
           OR existing.result_status IS NOT NULL
           OR existing.event_types IS NOT NULL
           OR existing.completed_at IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'DEMAND_VERIFY_RECEIPT_REPLAY_INVALID';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;
    IF existing.status IS DISTINCT FROM 'COMPLETED' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_VERIFY_RECEIPT_REPLAY_INVALID';
    END IF;
    SELECT array_agg(key_name ORDER BY key_name) INTO receipt_keys
    FROM jsonb_object_keys(existing.safe_response_body) AS key_name;
    IF existing.target_id IS DISTINCT FROM exact_demand_id
       OR existing.response_http_status IS DISTINCT FROM 200
       OR existing.response_schema_name IS DISTINCT FROM 'DemandDto'
       OR existing.response_schema_version IS DISTINCT FROM 1
       OR existing.target_version IS NULL
       OR existing.target_version IS DISTINCT FROM exact_if_match_version + 1
       OR existing.result_status IS DISTINCT FROM 'VERIFIED'
       OR existing.event_types
            IS DISTINCT FROM ARRAY['DemandVerified']::text[]
       OR existing.completed_at IS NULL
       OR existing.response_entity_tag IS DISTINCT FROM
            '"v' || existing.target_version::text || '"'
       OR receipt_keys IS DISTINCT FROM ARRAY[
            'aggregate_version',
            'demand_id',
            'demand_version_id',
            'status'
       ]::text[]
       OR jsonb_typeof(existing.safe_response_body->'aggregate_version')
            IS DISTINCT FROM 'number'
       OR jsonb_typeof(existing.safe_response_body->'demand_id')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(existing.safe_response_body->'status')
            IS DISTINCT FROM 'string'
       OR existing.safe_response_body->>'aggregate_version'
            IS DISTINCT FROM existing.target_version::text
       OR existing.safe_response_body->>'demand_id'
            IS DISTINCT FROM exact_demand_id::text
       OR existing.safe_response_body->>'status' IS DISTINCT FROM 'VERIFIED'
       OR jsonb_typeof(existing.safe_response_body->'demand_version_id')
            IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;

    PERFORM set_config('app.scope_kind', 'DEMAND_REVIEW', true);
    PERFORM set_config(
        'app.organization_id', existing.organization_id::text, true
    );

    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT current_authority_marker
        FROM iam_api.resolve_demand_reviewer_authority_marker_v2(
            exact_actor_user_id,
            exact_session_id,
            existing.organization_id,
            'VERIFY',
            exact_demand_id,
            exact_assignment_id
        ) AS marker;

        SELECT authority.duty_grant_id, authority.duty_grant_version
        INTO STRICT current_duty_grant_id, current_duty_grant_version
        FROM iam_api.lock_demand_reviewer_authority_v2(
            exact_actor_user_id,
            exact_session_id,
            existing.organization_id,
            exact_demand_id,
            exact_assignment_id,
            'VERIFY',
            current_authority_marker
        ) AS authority;
        IF current_duty_grant_id IS NULL
           OR current_duty_grant_id = zero_uuid
           OR current_duty_grant_version IS NULL
           OR current_duty_grant_version < 1
           OR current_authority_marker IS NULL
           OR octet_length(current_authority_marker) <> 32 THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002';
        END IF;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'ACCESS_DENIED';
    END;

    PERFORM 1
    FROM demand.demands AS root
    JOIN demand.demand_versions AS version_row
      ON version_row.organization_id = root.organization_id
     AND version_row.demand_id = root.id
     AND version_row.id = root.current_version_id
    JOIN demand.demand_submissions AS submission
      ON submission.organization_id = root.organization_id
     AND submission.demand_id = root.id
     AND submission.id = root.current_submission_id
     AND submission.demand_version_id = version_row.id
     AND submission.content_sha256 = version_row.content_sha256
    JOIN demand.demand_review_assignments AS assignment
      ON assignment.organization_id = root.organization_id
     AND assignment.demand_id = root.id
     AND assignment.id = exact_assignment_id
     AND assignment.submission_id = submission.id
     AND assignment.demand_version_id = version_row.id
    JOIN demand.demand_reviews AS review_row
      ON review_row.organization_id = root.organization_id
     AND review_row.demand_id = root.id
     AND review_row.id = root.current_review_id
     AND review_row.submission_id = submission.id
     AND review_row.demand_version_id = version_row.id
     AND review_row.content_sha256 = version_row.content_sha256
     AND review_row.assignment_id = assignment.id
    WHERE root.organization_id = existing.organization_id
      AND root.id = exact_demand_id
      AND root.status = 'VERIFIED'
      AND root.aggregate_version = existing.target_version
      AND root.verified_version_id = version_row.id
      AND root.current_funding_marker_id IS NULL
      AND root.current_matching_request_id IS NULL
      AND root.updated_at = existing.completed_at
      AND assignment.reviewer_user_id = exact_actor_user_id
      AND assignment.purpose_code = 'DEMAND_REVIEW'
      AND assignment.duty_grant_id <> zero_uuid
      AND assignment.duty_grant_version >= 1
      AND octet_length(assignment.authority_marker_sha256) = 32
      AND assignment.status = 'COMPLETED'
      AND assignment.aggregate_version = 2
      AND assignment.completed_at = existing.completed_at
      AND review_row.reviewer_user_id = exact_actor_user_id
      AND review_row.decision = 'VERIFIED'
      AND cardinality(review_row.reason_codes) = 0
      AND cardinality(review_row.required_field_codes) = 0
      AND review_row.budget_health_code IN (
            'HEALTHY', 'APPROVED_EXCEPTION'
      )
      AND review_row.risk_code IN ('STANDARD', 'ELEVATED_APPROVED')
      AND octet_length(review_row.evidence_summary_sha256) = 32
      AND octet_length(review_row.rule_requirement_sha256) = 32
      AND review_row.reviewed_at = existing.completed_at
      AND version_row.id::text =
            existing.safe_response_body->>'demand_version_id';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;

    RETURN QUERY SELECT
        existing.organization_id,
        current_authority_marker,
        existing.target_version,
        (existing.safe_response_body->>'demand_version_id')::uuid;
END
$function$;

REVOKE ALL ON FUNCTION demand_api.read_completed_verify_receipt_v1(
    uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demand_api.read_completed_verify_receipt_v1(
    uuid, uuid, uuid, uuid, uuid, bigint,
    text[], bytea[], text[], bytea[]
) TO demand_review;

DO $demand9_assertions$
DECLARE
    function_is_exact boolean;
    function_acl_is_exact boolean;
    mutation_function_is_exact boolean;
    mutation_function_acl_is_exact boolean;
    discovery_policy_is_exact boolean;
    lock_policy_is_exact boolean;
    trigger_is_exact boolean;
    expected_policy_qual constant text :=
        '((SESSION_USER = ''demand_review''::name) AND '
        '(CURRENT_USER = ''demand_review''::name) AND '
        '(NULLIF(current_setting(''app.scope_kind''::text, true), '
        '''''::text) = ''DEMAND_VERIFY_REPLAY''::text) AND '
        '(NULLIF(current_setting(''app.operation''::text, true), '
        '''''::text) = ''VERIFY''::text) AND '
        '((receipt_id)::text = NULLIF(current_setting('
        '''app.command_id''::text, true), ''''::text)))';
BEGIN
    SELECT
        owner_role.rolname = 'demand_schema_owner'
        AND NOT procedure.prosecdef
        AND procedure.provolatile = 'v'
        AND procedure.proparallel = 'u'
        AND procedure.proconfig IS NOT DISTINCT FROM ARRAY[
            'search_path=pg_catalog, demand, iam_api'
        ]::text[]
    INTO STRICT function_is_exact
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE procedure.oid = (
        'demand_api.read_completed_verify_receipt_v1('
        'uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[])'
    )::regprocedure;

    SELECT
        count(*) = 2
        AND count(DISTINCT privilege.grantee) = 2
        AND count(DISTINCT privilege.grantor) = 1
        AND bool_and(
            privilege.privilege_type = 'EXECUTE'
            AND privilege.grantor = procedure.proowner
            AND NOT privilege.is_grantable
            AND privilege.grantee IN (
                procedure.proowner,
                (SELECT oid FROM pg_catalog.pg_roles
                 WHERE rolname = 'demand_review')
            )
        )
    INTO STRICT function_acl_is_exact
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(
            procedure.proacl,
            acldefault('f', procedure.proowner)
        )
    ) AS privilege
    WHERE procedure.oid = (
        'demand_api.read_completed_verify_receipt_v1('
        'uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[])'
    )::regprocedure
    GROUP BY procedure.proowner;

    SELECT
        owner_role.rolname = 'demand_schema_owner'
        AND NOT procedure.prosecdef
        AND procedure.provolatile = 'v'
        AND procedure.proparallel = 'u'
        AND procedure.proconfig IS NOT DISTINCT FROM ARRAY[
            'search_path=pg_catalog, demand'
        ]::text[]
    INTO STRICT mutation_function_is_exact
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE procedure.oid = (
        'demand.reject_verify_replay_receipt_mutation_v1()'
    )::regprocedure;

    SELECT
        count(*) = 1
        AND count(DISTINCT privilege.grantee) = 1
        AND count(DISTINCT privilege.grantor) = 1
        AND bool_and(
            privilege.privilege_type = 'EXECUTE'
            AND privilege.grantor = procedure.proowner
            AND NOT privilege.is_grantable
            AND privilege.grantee = procedure.proowner
        )
    INTO STRICT mutation_function_acl_is_exact
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(
            procedure.proacl,
            acldefault('f', procedure.proowner)
        )
    ) AS privilege
    WHERE procedure.oid = (
        'demand.reject_verify_replay_receipt_mutation_v1()'
    )::regprocedure
    GROUP BY procedure.proowner;

    SELECT
        policy.polcmd = 'r'
        AND policy.polpermissive
        AND policy.polroles = ARRAY[
            (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='demand_review')
        ]::oid[]
        AND pg_get_expr(policy.polqual, policy.polrelid)
            = expected_policy_qual
        AND policy.polwithcheck IS NULL
    INTO STRICT discovery_policy_is_exact
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polrelid = 'demand.command_receipts'::regclass
      AND policy.polname = 'rls_demand_verify_replay_receipt_discovery';

    SELECT
        policy.polcmd = 'w'
        AND policy.polpermissive
        AND policy.polroles = ARRAY[
            (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='demand_review')
        ]::oid[]
        AND pg_get_expr(policy.polqual, policy.polrelid)
            = expected_policy_qual
        AND pg_get_expr(policy.polwithcheck, policy.polrelid)
            = expected_policy_qual
    INTO STRICT lock_policy_is_exact
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polrelid = 'demand.command_receipts'::regclass
      AND policy.polname = 'rls_demand_verify_replay_receipt_lock';

    SELECT
        count(*) = 1
        AND bool_and(
            trigger.tgenabled = 'O'
            AND NOT trigger.tgisinternal
            AND trigger.tgtype = 19
            AND trigger.tgnargs = 0
            AND trigger.tgfoid = (
                'demand.reject_verify_replay_receipt_mutation_v1()'
            )::regprocedure
        )
    INTO STRICT trigger_is_exact
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgrelid = 'demand.command_receipts'::regclass
      AND trigger.tgname = 'command_receipts_verify_replay_read_only';

    IF function_is_exact IS NOT TRUE
       OR function_acl_is_exact IS NOT TRUE
       OR mutation_function_is_exact IS NOT TRUE
       OR mutation_function_acl_is_exact IS NOT TRUE
       OR discovery_policy_is_exact IS NOT TRUE
       OR lock_policy_is_exact IS NOT TRUE
       OR trigger_is_exact IS NOT TRUE
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand completed Verify replay boundary drifted';
    END IF;
END
$demand9_assertions$;
