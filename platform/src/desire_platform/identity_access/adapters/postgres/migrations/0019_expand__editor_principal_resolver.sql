-- Authoritative editor workspace facts without runtime table scans.

CREATE FUNCTION iam_api.editor_principal_context_valid_v1()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT CASE
    WHEN session_user = 'iam_app' THEN
        NULLIF(current_setting('app.scope_kind', true), '')
            = 'EDITOR_PRINCIPAL'
        AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    WHEN session_user = 'profile_app' THEN
        NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
        AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    WHEN session_user = 'demand_self' THEN
        NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
        AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    WHEN session_user = 'demand_review' THEN
        NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
        AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    ELSE false
END
$function$;

CREATE POLICY rls_editor_principal_user_definer
ON iam.users
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_editor_principal_family_definer
ON iam.session_families
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND user_id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_editor_principal_session_definer
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_editor_principal_organization_definer
ON iam.organizations
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.memberships AS candidate_membership
        WHERE candidate_membership.organization_id = organizations.id
          AND candidate_membership.user_id::text = COALESCE(
              NULLIF(current_setting('app.actor_user_id', true), ''),
              NULLIF(current_setting('app.actor_id', true), '')
          )
    )
);

CREATE POLICY rls_editor_principal_membership_definer
ON iam.memberships
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND user_id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_editor_principal_user_role_definer
ON iam.user_role_grants
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND user_id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_editor_principal_membership_role_definer
ON iam.membership_role_grants
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND user_id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_editor_principal_platform_duty_definer
ON iam.platform_duty_grants
FOR SELECT TO schema_owner
USING (
    iam_api.editor_principal_context_valid_v1()
    AND user_id::text = COALESCE(
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE FUNCTION iam_api.editor_principal_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid
)
RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    principal record;
    user_role_facts text;
    platform_duty_facts text;
    organization_facts text;
BEGIN
    IF exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR NOT iam_api.editor_principal_context_valid_v1()
       OR COALESCE(
            NULLIF(current_setting('app.actor_user_id', true), ''),
            NULLIF(current_setting('app.actor_id', true), '')
       ) IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN NULL;
    END IF;

    SELECT
        actor_user.aggregate_version AS user_version,
        actor_session.aggregate_version AS session_version,
        actor_session.family_id,
        actor_session.generation AS session_generation,
        actor_family.aggregate_version AS family_version,
        actor_family.current_generation AS family_generation
    INTO principal
    FROM iam.users AS actor_user
    JOIN iam.sessions AS actor_session
      ON actor_session.user_id = actor_user.id
    JOIN iam.session_families AS actor_family
      ON actor_family.id = actor_session.family_id
     AND actor_family.user_id = actor_session.user_id
    WHERE actor_user.id = exact_actor_user_id
      AND actor_user.status = 'ACTIVE'
      AND actor_session.id = exact_session_id
      AND actor_session.status = 'ACTIVE'
      AND actor_session.generation = actor_family.current_generation
      AND transaction_timestamp() < actor_session.idle_expires_at
      AND transaction_timestamp() < actor_session.absolute_expires_at
      AND actor_family.status = 'ACTIVE';
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT COALESCE(
        string_agg(
            role_grant.id::text || ':' || role_grant.role_code || ':'
                || role_grant.aggregate_version::text,
            ',' ORDER BY role_grant.id
        ),
        ''
    )
    INTO user_role_facts
    FROM iam.user_role_grants AS role_grant
    WHERE role_grant.user_id = exact_actor_user_id
      AND role_grant.granted_at <= transaction_timestamp()
      AND role_grant.revoked_at IS NULL;

    SELECT COALESCE(
        string_agg(
            duty_grant.id::text || ':' || duty_grant.duty_code || ':'
                || duty_grant.aggregate_version::text || ':'
                || COALESCE(
                    extract(epoch FROM duty_grant.expires_at)::text,
                    'none'
                ),
            ',' ORDER BY duty_grant.id
        ),
        ''
    )
    INTO platform_duty_facts
    FROM iam.platform_duty_grants AS duty_grant
    WHERE duty_grant.user_id = exact_actor_user_id
      AND duty_grant.granted_at <= transaction_timestamp()
      AND duty_grant.revoked_at IS NULL
      AND (
          duty_grant.expires_at IS NULL
          OR transaction_timestamp() < duty_grant.expires_at
      );

    SELECT COALESCE(
        string_agg(
            membership.organization_id::text || ':'
                || organization.aggregate_version::text || ':'
                || membership.id::text || ':'
                || membership.aggregate_version::text || ':'
                || role_grant.id::text || ':' || role_grant.role_code || ':'
                || role_grant.aggregate_version::text,
            ',' ORDER BY membership.organization_id, role_grant.id
        ),
        ''
    )
    INTO organization_facts
    FROM iam.memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'ACTIVE'
    JOIN iam.membership_role_grants AS role_grant
      ON role_grant.membership_id = membership.id
     AND role_grant.organization_id = membership.organization_id
     AND role_grant.user_id = membership.user_id
     AND role_grant.granted_at <= transaction_timestamp()
     AND role_grant.revoked_at IS NULL
    WHERE membership.user_id = exact_actor_user_id
      AND membership.status = 'ACTIVE';

    RETURN sha256(
        convert_to(
            concat_ws(
                E'\n',
                'editor-principal-marker-v1',
                exact_actor_user_id::text,
                exact_session_id::text,
                principal.user_version::text,
                principal.session_version::text,
                principal.family_id::text,
                principal.session_generation::text,
                principal.family_version::text,
                principal.family_generation::text,
                user_role_facts,
                platform_duty_facts,
                organization_facts
            ),
            'UTF8'
        )
    );
END
$function$;

CREATE FUNCTION iam_api.resolve_editor_principal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid
)
RETURNS TABLE (
    workspace_id text,
    workspace_kind text,
    user_id uuid,
    session_id uuid,
    organization_id uuid,
    membership_id uuid,
    organization_role_codes text[],
    user_role_codes text[],
    platform_duty_codes text[],
    principal_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    marker bytea;
    active_user_roles text[];
    active_platform_duties text[];
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'EDITOR_PRINCIPAL'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN;
    END IF;

    marker := iam_api.editor_principal_marker_v1(
        exact_actor_user_id,
        exact_session_id
    );
    IF marker IS NULL OR octet_length(marker) <> 32 THEN
        RETURN;
    END IF;

    SELECT ARRAY(
        SELECT DISTINCT role_grant.role_code
        FROM iam.user_role_grants AS role_grant
        WHERE role_grant.user_id = exact_actor_user_id
          AND role_grant.granted_at <= transaction_timestamp()
          AND role_grant.revoked_at IS NULL
        ORDER BY role_grant.role_code
    )
    INTO active_user_roles;

    SELECT ARRAY(
        SELECT DISTINCT duty_grant.duty_code
        FROM iam.platform_duty_grants AS duty_grant
        WHERE duty_grant.user_id = exact_actor_user_id
          AND duty_grant.granted_at <= transaction_timestamp()
          AND duty_grant.revoked_at IS NULL
          AND (
              duty_grant.expires_at IS NULL
              OR transaction_timestamp() < duty_grant.expires_at
          )
        ORDER BY duty_grant.duty_code
    )
    INTO active_platform_duties;

    RETURN QUERY
    SELECT
        'org:' || membership.organization_id::text,
        'ORGANIZATION'::text,
        exact_actor_user_id,
        exact_session_id,
        membership.organization_id,
        membership.id,
        ARRAY(
            SELECT DISTINCT role_grant.role_code
            FROM iam.membership_role_grants AS role_grant
            WHERE role_grant.membership_id = membership.id
              AND role_grant.organization_id = membership.organization_id
              AND role_grant.user_id = exact_actor_user_id
              AND role_grant.granted_at <= transaction_timestamp()
              AND role_grant.revoked_at IS NULL
            ORDER BY role_grant.role_code
        ),
        active_user_roles,
        active_platform_duties,
        marker
    FROM iam.memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'ACTIVE'
    WHERE membership.user_id = exact_actor_user_id
      AND membership.status = 'ACTIVE'
      AND EXISTS (
          SELECT 1
          FROM iam.membership_role_grants AS role_grant
          WHERE role_grant.membership_id = membership.id
            AND role_grant.organization_id = membership.organization_id
            AND role_grant.user_id = exact_actor_user_id
            AND role_grant.granted_at <= transaction_timestamp()
            AND role_grant.revoked_at IS NULL
      )
    UNION ALL
    SELECT
        'personal:' || exact_actor_user_id::text,
        'PERSONAL'::text,
        exact_actor_user_id,
        exact_session_id,
        NULL::uuid,
        NULL::uuid,
        ARRAY[]::text[],
        active_user_roles,
        active_platform_duties,
        marker
    WHERE 'CREATOR' = ANY (active_user_roles)
    ORDER BY 1;
END
$function$;

CREATE FUNCTION iam_api.verify_editor_principal_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam_api
AS $function$
DECLARE
    computed_marker bytea;
BEGIN
    IF session_user NOT IN ('profile_app', 'demand_self', 'demand_review')
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR COALESCE(
            NULLIF(current_setting('app.actor_user_id', true), ''),
            NULLIF(current_setting('app.actor_id', true), '')
       ) IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NOT iam_api.editor_principal_context_valid_v1() THEN
        RETURN false;
    END IF;
    computed_marker := iam_api.editor_principal_marker_v1(
        exact_actor_user_id,
        exact_session_id
    );
    RETURN computed_marker IS NOT NULL
       AND computed_marker = expected_principal_marker_sha256;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.editor_principal_context_valid_v1()
FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.editor_principal_marker_v1(uuid, uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.resolve_editor_principal_v1(uuid, uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.verify_editor_principal_marker_v1(
    uuid, uuid, bytea
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION iam_api.resolve_editor_principal_v1(uuid, uuid)
TO iam_app;
GRANT EXECUTE ON FUNCTION iam_api.verify_editor_principal_marker_v1(
    uuid, uuid, bytea
) TO profile_schema_owner, demand_schema_owner;

GRANT USAGE ON SCHEMA iam_api TO profile_schema_owner, demand_schema_owner;
