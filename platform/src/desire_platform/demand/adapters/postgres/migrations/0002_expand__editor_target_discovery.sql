-- Separate owner and independent-reviewer target discovery for the editor.

CREATE SCHEMA demand_api AUTHORIZATION demand_schema_owner;
REVOKE ALL ON SCHEMA demand_api FROM PUBLIC;

CREATE FUNCTION demand_api.list_owned_demand_targets_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (demand_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_self'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_OWNER'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_DEMAND_TARGETS'
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR NOT iam_api.verify_editor_principal_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            expected_principal_marker_sha256
       ) THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT root.id
    FROM demand.demands AS root
    WHERE root.organization_id = exact_organization_id
      AND root.creator_user_id = exact_actor_user_id
    ORDER BY root.id;
END
$function$;

CREATE FUNCTION demand_api.list_reviewer_demand_targets_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    organization_id uuid,
    demand_id uuid,
    assignment_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_REVIEW_TARGETS'
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR NOT iam_api.verify_editor_principal_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            expected_principal_marker_sha256
       ) THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT assignment.organization_id, assignment.demand_id, assignment.id
    FROM demand.demand_review_assignments AS assignment
    WHERE assignment.reviewer_user_id = exact_actor_user_id
      AND assignment.status = 'ACTIVE'
      AND transaction_timestamp() < assignment.expires_at
    ORDER BY assignment.organization_id, assignment.demand_id, assignment.id;
END
$function$;

ALTER FUNCTION demand_api.list_owned_demand_targets_v1(
    uuid, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.list_reviewer_demand_targets_v1(
    uuid, uuid, bytea
) OWNER TO demand_schema_owner;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA demand_api FROM PUBLIC;
GRANT USAGE ON SCHEMA demand_api TO demand_self, demand_review;
GRANT EXECUTE ON FUNCTION demand_api.list_owned_demand_targets_v1(
    uuid, uuid, uuid, bytea
) TO demand_self;
GRANT EXECUTE ON FUNCTION demand_api.list_reviewer_demand_targets_v1(
    uuid, uuid, bytea
) TO demand_review;

CREATE POLICY rls_demand_owner_discovery_definer
ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_DEMAND_TARGETS'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND creator_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_reviewer_discovery_definer
ON demand.demand_review_assignments
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_REVIEW_TARGETS'
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

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
          'list_owned_demand_targets_v1',
          'list_reviewer_demand_targets_v1'
      )
      AND (
          owner_role.rolname <> 'demand_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 's'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, demand, iam_api']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.list_owned_demand_targets_v1(uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.list_owned_demand_targets_v1(uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.list_reviewer_demand_targets_v1(uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.list_reviewer_demand_targets_v1(uuid,uuid,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand editor target discovery assertion failed';
    END IF;
END
$assert$;
