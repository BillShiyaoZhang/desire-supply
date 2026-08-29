-- Narrow Profile target discovery for the authenticated INTERNAL_SANDBOX editor.

ALTER TABLE profile.schema_contracts
DROP CONSTRAINT ck_profile_schema_contract_version;
ALTER TABLE profile.schema_contracts
ADD CONSTRAINT ck_profile_schema_contract_version CHECK (
    schema_head_version >= 1
    AND min_app_compatible_version >= 1
    AND max_app_compatible_version >= min_app_compatible_version
);

-- Expose only the reviewed compatibility projection.  The v1 view was an
-- invoker view, which would require widening profile_app onto the private
-- migration ledger and contract row.
ALTER VIEW profile.schema_compatibility
SET (security_invoker = false);

CREATE FUNCTION profile_api.list_owned_profile_targets_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (profile_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, profile, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'profile_app'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'PROFILE_SELF'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_PROFILE_TARGETS'
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
    FROM profile.creator_profiles AS root
    WHERE root.owner_user_id = exact_actor_user_id
    ORDER BY root.id;
END
$function$;

ALTER FUNCTION profile_api.list_owned_profile_targets_v1(uuid, uuid, bytea)
OWNER TO profile_schema_owner;
REVOKE ALL ON FUNCTION profile_api.list_owned_profile_targets_v1(
    uuid, uuid, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION profile_api.list_owned_profile_targets_v1(
    uuid, uuid, bytea
) TO profile_app;
GRANT SELECT ON profile.schema_compatibility TO profile_app;
GRANT SELECT ON profile.schema_compatibility TO profile_matcher;

CREATE POLICY rls_profile_editor_discovery_definer
ON profile.creator_profiles
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_PROFILE_TARGETS'
    AND owner_user_id::text
        = NULLIF(current_setting('app.actor_user_id', true), '')
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
    WHERE namespace.nspname = 'profile_api'
      AND procedure.proname = 'list_owned_profile_targets_v1'
      AND (
          owner_role.rolname <> 'profile_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 's'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, profile, iam_api']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'profile_app',
            'profile_api.list_owned_profile_targets_v1(uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self',
            'profile_api.list_owned_profile_targets_v1(uuid,uuid,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Profile editor target discovery assertion failed';
    END IF;
END
$assert$;
