-- Finance-operator-owned terminal funding-review discovery with keyset paging.

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

CREATE INDEX ix_manual_funding_assignment_actor_terminal_history
ON demand.manual_funding_review_assignments (
    actor_user_id, completed_at DESC, funding_review_id DESC
)
WHERE status = 'COMPLETED' AND completed_at IS NOT NULL;

CREATE POLICY rls_finance_funding_history_assignment_definer
ON demand.manual_funding_review_assignments
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_FUNDING_REVIEW_HISTORY'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND status = 'COMPLETED'
    AND completed_at IS NOT NULL
);

CREATE POLICY rls_finance_funding_history_case_definer
ON demand.manual_funding_review_cases
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_FUNDING_REVIEW_HISTORY'
    AND status IN ('SECURED', 'DISCREPANCY', 'REJECTED')
    AND EXISTS (
        SELECT 1
        FROM demand.manual_funding_review_assignments AS own_assignment
        WHERE own_assignment.funding_review_id
                = manual_funding_review_cases.id
          AND own_assignment.actor_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
          AND own_assignment.status = 'COMPLETED'
          AND own_assignment.completed_at IS NOT NULL
    )
);

CREATE POLICY rls_finance_funding_history_confirmation_definer
ON demand.manual_funding_confirmations
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_FUNDING_REVIEW_HISTORY'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_finance_funding_history_finding_definer
ON demand.manual_funding_findings
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_FUNDING_REVIEW_HISTORY'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE FUNCTION demand_api.list_manual_funding_review_history_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea,
    maximum_items integer,
    cursor_completed_at timestamptz,
    cursor_funding_review_id uuid
)
RETURNS TABLE (
    funding_review_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    status text,
    completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    authority_row record;
BEGIN
    IF session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR maximum_items IS NULL
       OR maximum_items NOT BETWEEN 1 AND 100
       OR (cursor_completed_at IS NULL)
            IS DISTINCT FROM (cursor_funding_review_id IS NULL)
       OR cursor_funding_review_id = zero_uuid
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_FUNDING_REVIEWS'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
    THEN
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
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

    -- IAM31 closes queue authorization over LIST_FUNDING_REVIEWS.  Switch to
    -- the narrower local operation only after that current-duty check passes.
    PERFORM set_config(
        'app.operation', 'LIST_FUNDING_REVIEW_HISTORY', true
    );

    IF cursor_completed_at IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
            FROM demand.manual_funding_review_assignments AS cursor_assignment
            JOIN demand.manual_funding_review_cases AS cursor_review
              ON cursor_review.id = cursor_assignment.funding_review_id
            WHERE cursor_assignment.actor_user_id = exact_actor_user_id
              AND cursor_assignment.status = 'COMPLETED'
              AND cursor_assignment.completed_at = cursor_completed_at
              AND cursor_assignment.funding_review_id
                    = cursor_funding_review_id
              AND cursor_review.status IN (
                    'SECURED', 'DISCREPANCY', 'REJECTED'
              )
              AND (
                    EXISTS (
                        SELECT 1
                        FROM demand.manual_funding_confirmations AS confirmation
                        WHERE confirmation.funding_review_id = cursor_review.id
                          AND confirmation.actor_user_id = exact_actor_user_id
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM demand.manual_funding_findings AS finding
                        WHERE finding.funding_review_id = cursor_review.id
                          AND finding.actor_user_id = exact_actor_user_id
                    )
              )
       )
    THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        review.id,
        review.demand_id,
        review.demand_version_id,
        review.status::text,
        assignment.completed_at
    FROM demand.manual_funding_review_assignments AS assignment
    JOIN demand.manual_funding_review_cases AS review
      ON review.id = assignment.funding_review_id
    WHERE assignment.actor_user_id = exact_actor_user_id
      AND assignment.status = 'COMPLETED'
      AND assignment.completed_at IS NOT NULL
      AND review.status IN ('SECURED', 'DISCREPANCY', 'REJECTED')
      AND (
            EXISTS (
                SELECT 1
                FROM demand.manual_funding_confirmations AS confirmation
                WHERE confirmation.funding_review_id = review.id
                  AND confirmation.actor_user_id = exact_actor_user_id
            )
            OR EXISTS (
                SELECT 1
                FROM demand.manual_funding_findings AS finding
                WHERE finding.funding_review_id = review.id
                  AND finding.actor_user_id = exact_actor_user_id
            )
      )
      AND (
            cursor_completed_at IS NULL
            OR assignment.completed_at < cursor_completed_at
            OR (
                assignment.completed_at = cursor_completed_at
                AND review.id < cursor_funding_review_id
            )
      )
    ORDER BY assignment.completed_at DESC, review.id DESC
    LIMIT maximum_items + 1;
END
$function$;

ALTER FUNCTION demand_api.list_manual_funding_review_history_v1(
    uuid, uuid, bytea, integer, timestamptz, uuid
) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.list_manual_funding_review_history_v1(
    uuid, uuid, bytea, integer, timestamptz, uuid
) FROM PUBLIC, demand_self, demand_review, demand_matching, demand_system;
GRANT EXECUTE ON FUNCTION demand_api.list_manual_funding_review_history_v1(
    uuid, uuid, bytea, integer, timestamptz, uuid
) TO demand_finance;

DO $assert$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.list_manual_funding_review_history_v1(uuid,uuid,bytea,integer,timestamptz,uuid)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.list_manual_funding_review_history_v1(uuid,uuid,bytea,integer,timestamptz,uuid)',
            'EXECUTE'
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand12 Finance funding terminal history assertion failed';
    END IF;
END
$assert$;
