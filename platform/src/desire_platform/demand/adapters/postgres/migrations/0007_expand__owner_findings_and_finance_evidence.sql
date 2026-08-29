-- Owner-safe review findings and human-readable INTERNAL_SANDBOX funding evidence.
-- The projections remain role-bound SECURITY DEFINER programs over canonical
-- Demand state.  They do not grant runtime roles direct table access and the
-- Finance projection cannot represent a provider, payment, or real funds.
-- IAM head 0033 supplies only demand_schema_owner's schema usage and EXECUTE
-- on the stable Demand-owner marker resolver; this migration never broadens
-- IAM table access or calls the volatile owner lock from its definer.

SET LOCAL ROLE demand_schema_owner;

CREATE POLICY rls_demand_owner_findings_root_definer
ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
);

CREATE POLICY rls_demand_owner_findings_review_definer
ON demand.demand_reviews
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
);

CREATE FUNCTION demand_api.read_demand_owner_findings_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_operation text,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    finding_id uuid,
    demand_version_id uuid,
    assignment_id uuid,
    decision text,
    reason_codes text[],
    required_field_codes text[],
    reviewed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    resolved_authority_marker_sha256 bytea;
BEGIN
    IF session_user IS DISTINCT FROM 'demand_self'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL
       OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL
       OR exact_demand_id = zero_uuid
       OR exact_operation NOT IN (
            'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
       )
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_OWNER'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text THEN
        RETURN;
    END IF;

    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT resolved_authority_marker_sha256
        FROM iam_api.resolve_demand_owner_authority_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_organization_id,
            exact_operation,
            exact_demand_id
        ) AS marker;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN
            RETURN;
    END;
    IF resolved_authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    PERFORM 1
    FROM demand.demands AS root
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        review.id,
        review.demand_version_id,
        review.assignment_id,
        review.decision::text,
        review.reason_codes,
        review.required_field_codes,
        review.reviewed_at
    FROM demand.demand_reviews AS review
    WHERE review.organization_id = exact_organization_id
      AND review.demand_id = exact_demand_id
    ORDER BY review.reviewed_at, review.id;
END
$function$;

CREATE FUNCTION demand_api.read_manual_funding_evidence_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_funding_review_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    target_content_sha256 bytea,
    planned_budget_currency text,
    planned_budget_minimum_amount_minor bigint,
    planned_budget_maximum_amount_minor bigint,
    planned_budget_direct_cost_amount_minor bigint,
    sandbox_funds_amount_minor bigint,
    provider_code text,
    payment_operation_code text,
    evidence_kind text,
    legal_effect text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    exact_operation text;
    review_row record;
    assignment_row record;
    authority_row record;
    version_row record;
    minimum_amount numeric;
    maximum_amount numeric;
    direct_cost_amount numeric;
BEGIN
    exact_operation := NULLIF(current_setting('app.operation', true), '');
    IF session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_funding_review_id IS NULL
       OR exact_funding_review_id = zero_uuid
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR exact_operation NOT IN (
            'GET_FUNDING_REVIEW',
            'CLAIM_FUNDING_REVIEW',
            'CONFIRM_FUNDING_REVIEW'
       )
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.funding_review_id', true), '')
            IS DISTINCT FROM exact_funding_review_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '') IS NULL THEN
        RETURN;
    END IF;

    IF exact_operation = 'GET_FUNDING_REVIEW' THEN
        IF NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
           OR NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL THEN
            RETURN;
        END IF;
        BEGIN
            SELECT * INTO STRICT authority_row
            FROM iam_api.authorize_finance_funding_queue_v1(
                exact_actor_user_id,
                exact_session_id,
                expected_principal_marker_sha256
            );
        EXCEPTION
            WHEN no_data_found OR too_many_rows THEN
                RETURN;
        END;
    END IF;

    SELECT
        review.id,
        review.organization_id,
        review.demand_id,
        review.demand_version_id,
        review.evidence_kind,
        review.sandbox_funds_amount_minor,
        review.legal_effect
    INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        assignment.id,
        assignment.duty_grant_id,
        assignment.duty_grant_version,
        assignment.authority_marker_sha256,
        assignment.status,
        assignment.expires_at
    INTO assignment_row
    FROM demand.manual_funding_review_assignments AS assignment
    WHERE assignment.organization_id = review_row.organization_id
      AND assignment.demand_id = review_row.demand_id
      AND assignment.funding_review_id = review_row.id
      AND assignment.actor_user_id = exact_actor_user_id
      AND assignment.id::text
            = NULLIF(current_setting('app.assignment_id', true), '');
    IF NOT FOUND
       OR assignment_row.status NOT IN ('ACTIVE', 'COMPLETED')
       OR (
            assignment_row.status = 'ACTIVE'
            AND transaction_timestamp() >= assignment_row.expires_at
       ) THEN
        RETURN;
    END IF;

    IF exact_operation = 'GET_FUNDING_REVIEW' THEN
        IF assignment_row.duty_grant_id <> authority_row.duty_grant_id
           OR assignment_row.duty_grant_version
                <> authority_row.duty_grant_version THEN
            RETURN;
        END IF;
        PERFORM set_config(
            'app.organization_id', review_row.organization_id::text, true
        );
        PERFORM set_config('app.demand_id', review_row.demand_id::text, true);
    ELSE
        IF NULLIF(current_setting('app.organization_id', true), '')
                IS DISTINCT FROM review_row.organization_id::text
           OR NULLIF(current_setting('app.demand_id', true), '')
                IS DISTINCT FROM review_row.demand_id::text THEN
            RETURN;
        END IF;
        BEGIN
            SELECT * INTO STRICT authority_row
            FROM iam_api.lock_finance_funding_authority_v1(
                exact_actor_user_id,
                exact_session_id,
                review_row.organization_id,
                review_row.demand_id,
                exact_operation,
                expected_principal_marker_sha256
            );
        EXCEPTION
            WHEN no_data_found OR too_many_rows THEN
                RETURN;
        END;
        IF assignment_row.duty_grant_id <> authority_row.duty_grant_id
           OR assignment_row.duty_grant_version
                <> authority_row.duty_grant_version
           OR (
                exact_operation = 'CLAIM_FUNDING_REVIEW'
                AND assignment_row.authority_marker_sha256
                    <> authority_row.authority_marker_sha256
           ) THEN
            RETURN;
        END IF;
    END IF;

    PERFORM 1
    FROM demand.demands AS root
    WHERE root.organization_id = review_row.organization_id
      AND root.id = review_row.demand_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT version.content, version.content_sha256
    INTO version_row
    FROM demand.demand_versions AS version
    WHERE version.organization_id = review_row.organization_id
      AND version.demand_id = review_row.demand_id
      AND version.id = review_row.demand_version_id;
    IF NOT FOUND
       OR octet_length(version_row.content_sha256) <> 32
       OR jsonb_typeof(version_row.content->'budget')
            IS DISTINCT FROM 'object'
       OR (
            SELECT array_agg(budget_key.key ORDER BY budget_key.key)
            FROM jsonb_object_keys(
                version_row.content->'budget'
            ) AS budget_key(key)
       ) IS DISTINCT FROM ARRAY[
            'currency',
            'direct_cost_amount_minor',
            'maximum_amount_minor',
            'minimum_amount_minor'
       ]::text[]
       OR version_row.content#>>'{budget,currency}' IS DISTINCT FROM 'CNY'
       OR jsonb_typeof(version_row.content#>'{budget,minimum_amount_minor}')
            IS DISTINCT FROM 'number'
       OR jsonb_typeof(version_row.content#>'{budget,maximum_amount_minor}')
            IS DISTINCT FROM 'number'
       OR jsonb_typeof(version_row.content#>'{budget,direct_cost_amount_minor}')
            IS DISTINCT FROM 'number'
       OR version_row.content#>>'{budget,minimum_amount_minor}'
            !~ '^(0|[1-9][0-9]{0,15})$'
       OR version_row.content#>>'{budget,maximum_amount_minor}'
            !~ '^(0|[1-9][0-9]{0,15})$'
       OR version_row.content#>>'{budget,direct_cost_amount_minor}'
            !~ '^(0|[1-9][0-9]{0,15})$' THEN
        RETURN;
    END IF;

    minimum_amount := (version_row.content#>>'{budget,minimum_amount_minor}')::numeric;
    maximum_amount := (version_row.content#>>'{budget,maximum_amount_minor}')::numeric;
    direct_cost_amount := (
        version_row.content#>>'{budget,direct_cost_amount_minor}'
    )::numeric;
    IF minimum_amount > maximum_amount
       OR minimum_amount > 9007199254740991
       OR maximum_amount > 9007199254740991
       OR direct_cost_amount > 9007199254740991
       OR review_row.evidence_kind
            <> 'INTERNAL_SANDBOX_ZERO_FUNDS_V1'
       OR review_row.sandbox_funds_amount_minor <> 0
       OR review_row.legal_effect <> 'NO_REAL_FUNDS_OR_PAYMENT' THEN
        RETURN;
    END IF;

    RETURN QUERY SELECT
        version_row.content_sha256,
        'CNY'::text,
        minimum_amount::bigint,
        maximum_amount::bigint,
        direct_cost_amount::bigint,
        review_row.sandbox_funds_amount_minor,
        'NONE'::text,
        'NONE'::text,
        review_row.evidence_kind::text,
        review_row.legal_effect::text;
END
$function$;

REVOKE ALL ON FUNCTION demand_api.read_demand_owner_findings_v1(
    uuid, uuid, uuid, uuid, text, bytea
) FROM PUBLIC, demand_review, demand_finance;
REVOKE ALL ON FUNCTION demand_api.read_manual_funding_evidence_v1(
    uuid, uuid, uuid, bytea
) FROM PUBLIC, demand_self, demand_review;

GRANT EXECUTE ON FUNCTION demand_api.read_demand_owner_findings_v1(
    uuid, uuid, uuid, uuid, text, bytea
) TO demand_self;
GRANT EXECUTE ON FUNCTION demand_api.read_manual_funding_evidence_v1(
    uuid, uuid, uuid, bytea
) TO demand_finance;

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'demand_api'
      AND procedure.proname IN (
          'read_demand_owner_findings_v1',
          'read_manual_funding_evidence_v1'
      )
      AND (
          owner_role.rolname <> 'demand_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 'v'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, demand, iam_api']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.read_demand_owner_findings_v1(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.read_demand_owner_findings_v1(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.read_manual_funding_evidence_v1(uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_table_privilege(
            'demand_self',
            'demand.demand_reviews',
            'SELECT'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Owner findings and Finance evidence assertion failed';
    END IF;
END
$assert$;
