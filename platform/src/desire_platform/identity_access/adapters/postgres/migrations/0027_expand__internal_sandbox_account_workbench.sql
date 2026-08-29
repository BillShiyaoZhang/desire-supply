-- IAM 0027: closed, read-only INTERNAL_SANDBOX account administration view.
--
-- The workbench enumerates only accounts owned by the one active synthetic
-- bootstrap.  It never returns external identity, contact, digest, or tenant
-- authority material, and it revalidates the exact IAM User, Session,
-- SessionFamily, and ACCESS_ADMIN duty inside the database on every call.

CREATE FUNCTION iam.internal_sandbox_account_workbench_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
SELECT
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'INTERNAL_SANDBOX_ACCOUNT_ADMIN_READ'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'LIST_ACCOUNTS', 'GET_ACCOUNT'
    )
    AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND current_setting('transaction_read_only') = 'on'
    AND current_setting('transaction_isolation') = 'repeatable read'
$function$;

ALTER FUNCTION iam.internal_sandbox_account_workbench_context_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam.internal_sandbox_account_workbench_context_v1()
FROM PUBLIC;

-- FORCE RLS remains in force for the definer.  These policies admit rows only
-- while the exact closed workbench context is active; no online role receives
-- a new direct table privilege.
CREATE POLICY rls_sandbox_account_workbench_bootstrap_state
ON infra.iam_sandbox_bootstrap_state
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_bootstrap_accounts
ON infra.iam_sandbox_bootstrap_accounts
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_users
ON iam.users
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_families
ON iam.session_families
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_sessions
ON iam.sessions
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_user_roles
ON iam.user_role_grants
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_membership_roles
ON iam.membership_role_grants
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE POLICY rls_sandbox_account_workbench_duties
ON iam.platform_duty_grants
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_account_workbench_context_v1());

CREATE FUNCTION iam_api.read_internal_sandbox_account_workbench_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_user_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    operation_name text;
    active_state_count integer;
    active_account_count integer;
    stored_account_count integer;
    expected_result_count integer;
    actor_authorized boolean;
    result_document jsonb;
BEGIN
    operation_name := NULLIF(current_setting('app.operation', true), '');
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'INTERNAL_SANDBOX_ACCOUNT_ADMIN_READ'
       OR operation_name NOT IN ('LIST_ACCOUNTS', 'GET_ACCOUNT')
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
       OR current_setting('transaction_read_only') IS DISTINCT FROM 'on'
       OR current_setting('transaction_isolation')
            IS DISTINCT FROM 'repeatable read'
       OR (
            operation_name = 'LIST_ACCOUNTS'
            AND (
                exact_target_user_id IS NOT NULL
                OR NULLIF(
                    current_setting('app.target_user_id', true), ''
                ) IS NOT NULL
            )
       )
       OR (
            operation_name = 'GET_ACCOUNT'
            AND (
                exact_target_user_id IS NULL
                OR exact_target_user_id = zero_uuid
                OR NULLIF(
                    current_setting('app.target_user_id', true), ''
                ) IS DISTINCT FROM exact_target_user_id::text
            )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_sandbox_account_workbench_context',
            MESSAGE = 'internal sandbox account workbench context is invalid';
    END IF;

    SELECT count(*), COALESCE(sum(state.account_count), 0)
    INTO active_state_count, active_account_count
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.status = 'ACTIVE';

    SELECT count(*)
    INTO stored_account_count
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision;

    IF active_state_count <> 1
       OR active_account_count NOT BETWEEN 1 AND 16
       OR stored_account_count <> active_account_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_sandbox_account_workbench_bootstrap',
            MESSAGE = 'internal sandbox account workbench bootstrap is invalid';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM iam.users AS actor_user
        JOIN infra.iam_sandbox_bootstrap_accounts AS actor_account
          ON actor_account.user_id = actor_user.id
        JOIN infra.iam_sandbox_bootstrap_state AS actor_state
          ON actor_state.bootstrap_id = actor_account.bootstrap_id
         AND actor_state.status = 'ACTIVE'
         AND actor_state.revision = actor_account.manifest_revision
        JOIN iam.sessions AS actor_session
          ON actor_session.id = exact_session_id
         AND actor_session.user_id = actor_user.id
        JOIN iam.session_families AS actor_family
          ON actor_family.id = actor_session.family_id
         AND actor_family.user_id = actor_session.user_id
        JOIN iam.platform_duty_grants AS actor_duty
          ON actor_duty.user_id = actor_user.id
         AND actor_duty.duty_code = 'ACCESS_ADMIN'
        WHERE actor_user.id = exact_actor_user_id
          AND actor_user.status = 'ACTIVE'
          AND actor_session.status = 'ACTIVE'
          AND actor_session.generation = actor_family.current_generation
          AND actor_session.auth_time <= transaction_timestamp()
          AND actor_session.last_activity_at <= transaction_timestamp()
          AND actor_session.last_activity_at < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.absolute_expires_at
          AND actor_family.status = 'ACTIVE'
          AND actor_duty.granted_at <= transaction_timestamp()
          AND actor_duty.revoked_at IS NULL
          AND (
              actor_duty.expires_at IS NULL
              OR transaction_timestamp() < actor_duty.expires_at
          )
    ) INTO actor_authorized;

    IF NOT actor_authorized THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_sandbox_account_workbench_authority',
            MESSAGE = 'internal sandbox account workbench authority is unavailable';
    END IF;

    SELECT count(*)
    INTO expected_result_count
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision
    WHERE exact_target_user_id IS NULL
       OR account.user_id = exact_target_user_id;

    WITH active_accounts AS (
        SELECT account.account_code, account.user_id
        FROM infra.iam_sandbox_bootstrap_accounts AS account
        JOIN infra.iam_sandbox_bootstrap_state AS state
          ON state.bootstrap_id = account.bootstrap_id
         AND state.status = 'ACTIVE'
         AND state.revision = account.manifest_revision
        WHERE exact_target_user_id IS NULL
           OR account.user_id = exact_target_user_id
    ),
    role_edges AS (
        SELECT account.user_id, grant_row.role_code
        FROM active_accounts AS account
        JOIN iam.user_role_grants AS grant_row
          ON grant_row.user_id = account.user_id
         AND grant_row.revoked_at IS NULL
        UNION ALL
        SELECT account.user_id, grant_row.role_code
        FROM active_accounts AS account
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.user_id = account.user_id
         AND grant_row.revoked_at IS NULL
        UNION ALL
        SELECT account.user_id, grant_row.duty_code
        FROM active_accounts AS account
        JOIN iam.platform_duty_grants AS grant_row
          ON grant_row.user_id = account.user_id
         AND grant_row.revoked_at IS NULL
         AND grant_row.granted_at <= transaction_timestamp()
         AND (
             grant_row.expires_at IS NULL
             OR transaction_timestamp() < grant_row.expires_at
         )
    ),
    effective_roles AS (
        SELECT
            edge.user_id,
            pg_catalog.array_agg(
                DISTINCT edge.role_code ORDER BY edge.role_code
            ) AS role_codes
        FROM role_edges AS edge
        GROUP BY edge.user_id
        HAVING count(DISTINCT edge.role_code) BETWEEN 1 AND 4
    ),
    projected_accounts AS (
        SELECT
            account.account_code,
            exact_user.id AS user_id,
            exact_user.display_handle,
            exact_user.status,
            exact_user.aggregate_version,
            roles.role_codes,
            session_count.active_session_count,
            exact_user.created_at,
            exact_user.updated_at
        FROM active_accounts AS account
        JOIN iam.users AS exact_user
          ON exact_user.id = account.user_id
         AND exact_user.status IN ('ACTIVE', 'SUSPENDED')
        JOIN effective_roles AS roles ON roles.user_id = exact_user.id
        CROSS JOIN LATERAL (
            SELECT count(*)::integer AS active_session_count
            FROM iam.sessions AS exact_session
            JOIN iam.session_families AS exact_family
              ON exact_family.id = exact_session.family_id
             AND exact_family.user_id = exact_session.user_id
            WHERE exact_session.user_id = exact_user.id
              AND exact_session.status = 'ACTIVE'
              AND exact_session.generation = exact_family.current_generation
              AND exact_session.last_activity_at <= transaction_timestamp()
              AND exact_session.last_activity_at < exact_session.idle_expires_at
              AND transaction_timestamp() < exact_session.idle_expires_at
              AND transaction_timestamp() < exact_session.absolute_expires_at
              AND exact_family.status = 'ACTIVE'
        ) AS session_count
        WHERE session_count.active_session_count BETWEEN 0 AND 64
    ),
    account_documents AS (
        SELECT
            account.account_code,
            pg_catalog.jsonb_build_object(
                'account_code', account.account_code,
                'user_id', account.user_id::text,
                'display_handle', account.display_handle,
                'status', account.status,
                'aggregate_version', account.aggregate_version,
                'entity_tag', '"v' || account.aggregate_version::text || '"',
                'role_codes', pg_catalog.to_jsonb(account.role_codes),
                'active_session_count', account.active_session_count,
                'created_at', pg_catalog.to_jsonb(account.created_at),
                'updated_at', pg_catalog.to_jsonb(account.updated_at),
                'is_self', account.user_id = exact_actor_user_id
            ) AS document
        FROM projected_accounts AS account
    )
    SELECT pg_catalog.jsonb_build_object(
        'schema_version', 'internal-sandbox-account-admin-v1',
        'evaluated_at', pg_catalog.to_jsonb(transaction_timestamp()),
        'accounts', COALESCE(
            pg_catalog.jsonb_agg(
                account.document ORDER BY account.account_code
            ),
            '[]'::jsonb
        )
    )
    INTO result_document
    FROM account_documents AS account;

    IF pg_catalog.jsonb_typeof(result_document) <> 'object'
       OR pg_catalog.jsonb_typeof(result_document->'accounts') <> 'array'
       OR pg_catalog.jsonb_array_length(result_document->'accounts')
            <> expected_result_count
       OR (
            operation_name = 'LIST_ACCOUNTS'
            AND expected_result_count NOT BETWEEN 1 AND 16
       )
       OR (
            operation_name = 'GET_ACCOUNT'
            AND expected_result_count NOT BETWEEN 0 AND 1
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_sandbox_account_workbench_projection',
            MESSAGE = 'internal sandbox account workbench projection is invalid';
    END IF;

    RETURN result_document;
END
$function$;

ALTER FUNCTION iam_api.read_internal_sandbox_account_workbench_v1(
    uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam_api.read_internal_sandbox_account_workbench_v1(uuid, uuid, uuid)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam_api.read_internal_sandbox_account_workbench_v1(uuid, uuid, uuid)
TO iam_app;

DO $assertions$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.read_internal_sandbox_account_workbench_v1(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_onboarding',
        'iam_api.read_internal_sandbox_account_workbench_v1(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_session_authenticator',
        'iam_api.read_internal_sandbox_account_workbench_v1(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_system',
        'iam_api.read_internal_sandbox_account_workbench_v1(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_sandbox_bootstrap',
        'iam_api.read_internal_sandbox_account_workbench_v1(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam_api.read_internal_sandbox_account_workbench_v1(uuid,uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sandbox account workbench EXECUTE assertion failed';
    END IF;
END
$assertions$;
