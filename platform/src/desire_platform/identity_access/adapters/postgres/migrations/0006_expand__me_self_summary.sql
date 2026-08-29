GRANT SELECT (id, status, display_handle, aggregate_version)
    ON iam.users TO iam_self_summary_reader;
GRANT SELECT (
    id,
    user_id,
    status,
    idle_expires_at,
    absolute_expires_at
) ON iam.sessions TO iam_self_summary_reader;
GRANT SELECT (
    id,
    organization_id,
    user_id,
    status,
    aggregate_version
) ON iam.memberships TO iam_self_summary_reader;
GRANT SELECT (
    membership_id,
    organization_id,
    user_id,
    role_code,
    revoked_at
) ON iam.membership_role_grants TO iam_self_summary_reader;
GRANT SELECT (
    id,
    public_name,
    organization_type,
    status,
    aggregate_version
) ON iam.organizations TO iam_self_summary_reader;
GRANT USAGE ON SCHEMA iam_api TO iam_self_summary_reader;

CREATE POLICY rls_user_self_summary_reader ON iam.users
FOR SELECT TO iam_self_summary_reader
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_SELF_SUMMARY'
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status IN ('PENDING_ENROLLMENT', 'ACTIVE')
);

CREATE POLICY rls_session_self_summary_reader ON iam.sessions
FOR SELECT TO iam_self_summary_reader
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_SELF_SUMMARY'
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
    AND transaction_timestamp() < idle_expires_at
    AND transaction_timestamp() < absolute_expires_at
);

CREATE POLICY rls_membership_self_summary_reader ON iam.memberships
FOR SELECT TO iam_self_summary_reader
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_SELF_SUMMARY'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
);

CREATE POLICY rls_membership_role_self_summary_reader ON iam.membership_role_grants
FOR SELECT TO iam_self_summary_reader
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_SELF_SUMMARY'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND revoked_at IS NULL
    AND EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.id = membership_role_grants.membership_id
          AND membership.organization_id = membership_role_grants.organization_id
          AND membership.user_id = membership_role_grants.user_id
    )
);

CREATE POLICY rls_organization_self_summary_reader ON iam.organizations
FOR SELECT TO iam_self_summary_reader
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_SELF_SUMMARY'
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.organization_id = organizations.id
          AND membership.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
          AND membership.status = 'ACTIVE'
    )
);

CREATE FUNCTION iam_api.read_me_self_summary()
RETURNS TABLE (
    user_id uuid,
    user_status text,
    display_handle varchar(80),
    user_aggregate_version bigint,
    membership_id uuid,
    membership_status text,
    membership_aggregate_version bigint,
    membership_role_codes text[],
    organization_id uuid,
    organization_public_name varchar(160),
    organization_type text,
    organization_status text,
    organization_aggregate_version bigint
)
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SECURITY DEFINER
SET search_path = pg_catalog, iam, pg_temp
AS $function$
    WITH actor_context AS (
        SELECT
            NULLIF(current_setting('app.actor_user_id', true), '')::uuid AS actor_user_id,
            NULLIF(current_setting('app.session_id', true), '')::uuid AS actor_session_id
        WHERE NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
          AND NULLIF(current_setting('app.operation', true), '') = 'ME_SELF_SUMMARY'
    ),
    valid_actor AS (
        SELECT context.actor_user_id
        FROM actor_context AS context
        WHERE EXISTS (
            SELECT 1
            FROM iam.sessions AS session
            WHERE session.id = context.actor_session_id
              AND session.user_id = context.actor_user_id
              AND session.status = 'ACTIVE'
              AND transaction_timestamp() < session.idle_expires_at
              AND transaction_timestamp() < session.absolute_expires_at
        )
    )
    SELECT
        actor.id AS user_id,
        actor.status AS user_status,
        actor.display_handle,
        actor.aggregate_version AS user_aggregate_version,
        membership.id AS membership_id,
        membership.status AS membership_status,
        membership.aggregate_version AS membership_aggregate_version,
        COALESCE(role_summary.role_codes, ARRAY[]::text[]) AS membership_role_codes,
        organization.id AS organization_id,
        organization.public_name AS organization_public_name,
        organization.organization_type,
        organization.status AS organization_status,
        organization.aggregate_version AS organization_aggregate_version
    FROM valid_actor
    JOIN iam.users AS actor
      ON actor.id = valid_actor.actor_user_id
     AND actor.status IN ('PENDING_ENROLLMENT', 'ACTIVE')
    LEFT JOIN (
        iam.memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
         AND organization.status = 'ACTIVE'
    ) ON membership.user_id = actor.id
     AND membership.status = 'ACTIVE'
    LEFT JOIN LATERAL (
        SELECT array_agg(grant_row.role_code ORDER BY grant_row.role_code) AS role_codes
        FROM iam.membership_role_grants AS grant_row
        WHERE grant_row.membership_id = membership.id
          AND grant_row.organization_id = membership.organization_id
          AND grant_row.user_id = actor.id
          AND grant_row.revoked_at IS NULL
          AND membership.status = 'ACTIVE'
          AND organization.status = 'ACTIVE'
    ) AS role_summary ON true
    ORDER BY organization.id NULLS FIRST, membership.id NULLS FIRST
$function$;

REVOKE ALL ON FUNCTION iam_api.read_me_self_summary() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.read_me_self_summary() TO iam_app;

GRANT CREATE ON SCHEMA iam_api TO iam_self_summary_reader;
ALTER FUNCTION iam_api.read_me_self_summary() OWNER TO iam_self_summary_reader;
REVOKE CREATE ON SCHEMA iam_api FROM iam_self_summary_reader;
