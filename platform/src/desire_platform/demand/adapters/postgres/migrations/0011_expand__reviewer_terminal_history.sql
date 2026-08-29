-- Reviewer-owned terminal Demand decisions with stable keyset pagination.

SET LOCAL search_path = pg_catalog, demand;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_migration_runner'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

CREATE INDEX ix_demand_review_reviewer_history
ON demand.demand_reviews (reviewer_user_id, reviewed_at DESC, id DESC);

CREATE POLICY rls_demand_review_history_review_definer
ON demand.demand_reviews
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_REVIEW_HISTORY'
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND decision IN ('NEEDS_CHANGES', 'VERIFIED')
);

CREATE POLICY rls_demand_review_history_assignment_definer
ON demand.demand_review_assignments
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_REVIEW_HISTORY'
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND purpose_code = 'DEMAND_REVIEW'
    AND status = 'COMPLETED'
    AND completed_at IS NOT NULL
);

CREATE FUNCTION demand_api.list_own_demand_review_history_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea,
    maximum_items integer,
    cursor_reviewed_at timestamptz,
    cursor_review_id uuid
)
RETURNS TABLE (
    review_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    decision text,
    reason_codes text[],
    required_field_codes text[],
    budget_health_code text,
    risk_code text,
    reviewed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR maximum_items IS NULL
       OR maximum_items NOT BETWEEN 1 AND 100
       OR (cursor_reviewed_at IS NULL)
            IS DISTINCT FROM (cursor_review_id IS NULL)
       OR cursor_review_id = zero_uuid
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_REVIEW_QUEUE'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NOT EXISTS (
            SELECT 1
            FROM iam_api.authorize_demand_review_queue_v1(
                exact_actor_user_id,
                exact_session_id,
                expected_principal_marker_sha256
            )
       )
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.operation', 'LIST_REVIEW_HISTORY', true);

    IF cursor_reviewed_at IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
            FROM demand.demand_reviews AS cursor_review
            JOIN demand.demand_review_assignments AS cursor_assignment
              ON cursor_assignment.organization_id
                    = cursor_review.organization_id
             AND cursor_assignment.demand_id = cursor_review.demand_id
             AND cursor_assignment.id = cursor_review.assignment_id
             AND cursor_assignment.reviewer_user_id = exact_actor_user_id
             AND cursor_assignment.purpose_code = 'DEMAND_REVIEW'
             AND cursor_assignment.status = 'COMPLETED'
            WHERE cursor_review.id = cursor_review_id
              AND cursor_review.reviewer_user_id = exact_actor_user_id
              AND cursor_review.reviewed_at = cursor_reviewed_at
              AND cursor_review.decision IN ('NEEDS_CHANGES', 'VERIFIED')
       )
    THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        review.id,
        review.demand_id,
        review.demand_version_id,
        review.decision::text,
        review.reason_codes,
        review.required_field_codes,
        review.budget_health_code::text,
        review.risk_code::text,
        review.reviewed_at
    FROM demand.demand_reviews AS review
    JOIN demand.demand_review_assignments AS assignment
      ON assignment.organization_id = review.organization_id
     AND assignment.demand_id = review.demand_id
     AND assignment.id = review.assignment_id
     AND assignment.reviewer_user_id = exact_actor_user_id
     AND assignment.purpose_code = 'DEMAND_REVIEW'
     AND assignment.status = 'COMPLETED'
     AND assignment.completed_at IS NOT NULL
    WHERE review.reviewer_user_id = exact_actor_user_id
      AND review.decision IN ('NEEDS_CHANGES', 'VERIFIED')
      AND (
        cursor_reviewed_at IS NULL
        OR review.reviewed_at < cursor_reviewed_at
        OR (
            review.reviewed_at = cursor_reviewed_at
            AND review.id < cursor_review_id
        )
      )
    ORDER BY review.reviewed_at DESC, review.id DESC
    LIMIT maximum_items + 1;
END
$function$;

ALTER FUNCTION demand_api.list_own_demand_review_history_v1(
    uuid, uuid, bytea, integer, timestamptz, uuid
) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.list_own_demand_review_history_v1(
    uuid, uuid, bytea, integer, timestamptz, uuid
) FROM PUBLIC, demand_self, demand_finance, demand_matching, demand_system;
GRANT EXECUTE ON FUNCTION demand_api.list_own_demand_review_history_v1(
    uuid, uuid, bytea, integer, timestamptz, uuid
) TO demand_review;

DO $assert$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.list_own_demand_review_history_v1(uuid,uuid,bytea,integer,timestamptz,uuid)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.list_own_demand_review_history_v1(uuid,uuid,bytea,integer,timestamptz,uuid)',
            'EXECUTE'
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand11 reviewer terminal history assertion failed';
    END IF;
END
$assert$;
