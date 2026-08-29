-- Marker-only IAM authority resolution for Profile and Demand runtimes.

CREATE POLICY rls_authority_marker_profile_user_definer
ON iam.users
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.profile_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE_PROFILE',
        'SAVE_PROFILE_DRAFT',
        'PUBLISH_PROFILE',
        'PAUSE_PROFILE',
        'RESUME_PROFILE',
        'ARCHIVE_PROFILE'
    ])
);

CREATE POLICY rls_authority_marker_profile_session_definer
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND NULLIF(current_setting('app.profile_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE_PROFILE',
        'SAVE_PROFILE_DRAFT',
        'PUBLISH_PROFILE',
        'PAUSE_PROFILE',
        'RESUME_PROFILE',
        'ARCHIVE_PROFILE'
    ])
);

CREATE POLICY rls_authority_marker_profile_family_definer
ON iam.session_families
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND NULLIF(current_setting('app.profile_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE_PROFILE',
        'SAVE_PROFILE_DRAFT',
        'PUBLISH_PROFILE',
        'PAUSE_PROFILE',
        'RESUME_PROFILE',
        'ARCHIVE_PROFILE'
    ])
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.id::text
            = NULLIF(current_setting('app.session_id', true), '')
          AND exact_session.user_id = session_families.user_id
          AND exact_session.family_id = session_families.id
    )
);

CREATE POLICY rls_authority_marker_profile_creator_definer
ON iam.user_role_grants
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND role_code = 'CREATOR'
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.profile_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE_PROFILE',
        'SAVE_PROFILE_DRAFT',
        'PUBLISH_PROFILE',
        'PAUSE_PROFILE',
        'RESUME_PROFILE',
        'ARCHIVE_PROFILE'
    ])
);

CREATE POLICY rls_authority_marker_owner_user_definer
ON iam.users
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    ])
);

CREATE POLICY rls_authority_marker_owner_session_definer
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    ])
);

CREATE POLICY rls_authority_marker_owner_family_definer
ON iam.session_families
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    ])
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.id::text
            = NULLIF(current_setting('app.session_id', true), '')
          AND exact_session.user_id = session_families.user_id
          AND exact_session.family_id = session_families.id
    )
);

CREATE POLICY rls_authority_marker_owner_organization_definer
ON iam.organizations
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    ])
);

CREATE POLICY rls_authority_marker_owner_membership_definer
ON iam.memberships
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    ])
);

CREATE POLICY rls_authority_marker_owner_role_definer
ON iam.membership_role_grants
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND role_code = 'DEMAND_OWNER'
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    ])
);

CREATE POLICY rls_authority_marker_reviewer_user_definer
ON iam.users
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_review'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.assignment_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
    ])
);

CREATE POLICY rls_authority_marker_reviewer_session_definer
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_review'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.assignment_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
    ])
);

CREATE POLICY rls_authority_marker_reviewer_family_definer
ON iam.session_families
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_review'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.assignment_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
    ])
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.id::text
            = NULLIF(current_setting('app.session_id', true), '')
          AND exact_session.user_id = session_families.user_id
          AND exact_session.family_id = session_families.id
    )
);

CREATE POLICY rls_authority_marker_reviewer_organization_definer
ON iam.organizations
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_review'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.assignment_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
    ])
);

CREATE POLICY rls_authority_marker_reviewer_membership_definer
ON iam.memberships
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_review'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.assignment_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
    ])
);

CREATE POLICY rls_authority_marker_reviewer_duty_definer
ON iam.platform_duty_grants
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_review'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND duty_code = 'OPERATIONS_REVIEWER'
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.assignment_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
        'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
    ])
);

CREATE FUNCTION iam_api.resolve_profile_self_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text,
    exact_profile_id uuid
)
RETURNS TABLE (authority_marker_sha256 bytea)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_profile_id IS NULL
       OR exact_profile_id = zero_uuid
       OR exact_operation NOT IN (
            'CREATE_PROFILE',
            'SAVE_PROFILE_DRAFT',
            'PUBLISH_PROFILE',
            'PAUSE_PROFILE',
            'RESUME_PROFILE',
            'ARCHIVE_PROFILE'
       )
       OR session_user IS DISTINCT FROM 'profile_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'PROFILE_SELF'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.profile_id', true), '')
            IS DISTINCT FROM exact_profile_id::text THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT pg_catalog.sha256(
        pg_catalog.convert_to(
            pg_catalog.concat_ws(
                E'\x1f',
                'desire:iam:authority-marker:profile-self:v1',
                exact_actor_user_id::text,
                exact_session_id::text,
                exact_operation,
                exact_profile_id::text,
                actor.aggregate_version::text,
                family.id::text,
                family.aggregate_version::text,
                family.current_generation::text,
                coalesce(family.revoked_at::text, 'none'),
                active_session.aggregate_version::text,
                active_session.generation::text,
                extract(epoch FROM active_session.idle_expires_at)::text,
                extract(epoch FROM active_session.absolute_expires_at)::text,
                creator_grant.id::text,
                creator_grant.aggregate_version::text,
                creator_grant.source_invitation_id::text,
                pg_catalog.encode(creator_grant.policy_selector_digest, 'hex'),
                extract(epoch FROM creator_grant.granted_at)::text,
                coalesce(creator_grant.revoked_at::text, 'none')
            ),
            'UTF8'
        )
    )
    FROM iam.users AS actor
    JOIN iam.sessions AS active_session
      ON active_session.id = exact_session_id
     AND active_session.user_id = actor.id
    JOIN iam.session_families AS family
      ON family.id = active_session.family_id
     AND family.user_id = actor.id
    JOIN iam.user_role_grants AS creator_grant
      ON creator_grant.user_id = actor.id
     AND creator_grant.role_code = 'CREATOR'
    WHERE actor.id = exact_actor_user_id
      AND actor.status = 'ACTIVE'
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
      AND family.status = 'ACTIVE'
      AND family.revoked_at IS NULL
      AND creator_grant.granted_at <= transaction_timestamp()
      AND creator_grant.revoked_at IS NULL;
END
$function$;

ALTER FUNCTION iam_api.resolve_profile_self_authority_marker_v1(
    uuid, uuid, text, uuid
) OWNER TO schema_owner;

CREATE FUNCTION iam_api.resolve_demand_owner_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_operation text,
    exact_demand_id uuid
)
RETURNS TABLE (authority_marker_sha256 bytea)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL
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
       OR session_user IS DISTINCT FROM 'demand_self'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_OWNER'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT pg_catalog.sha256(
        pg_catalog.convert_to(
            pg_catalog.concat_ws(
                E'\x1f',
                'desire:iam:authority-marker:demand-owner:v1',
                exact_actor_user_id::text,
                exact_session_id::text,
                exact_organization_id::text,
                exact_operation,
                exact_demand_id::text,
                actor.aggregate_version::text,
                family.id::text,
                family.aggregate_version::text,
                family.current_generation::text,
                coalesce(family.revoked_at::text, 'none'),
                active_session.aggregate_version::text,
                active_session.generation::text,
                extract(epoch FROM active_session.idle_expires_at)::text,
                extract(epoch FROM active_session.absolute_expires_at)::text,
                organization.aggregate_version::text,
                membership.id::text,
                membership.aggregate_version::text,
                membership.source_invitation_id::text,
                owner_grant.id::text,
                owner_grant.aggregate_version::text,
                owner_grant.source_invitation_id::text,
                pg_catalog.encode(owner_grant.policy_selector_digest, 'hex'),
                extract(epoch FROM owner_grant.granted_at)::text,
                coalesce(owner_grant.revoked_at::text, 'none')
            ),
            'UTF8'
        )
    )
    FROM iam.users AS actor
    JOIN iam.sessions AS active_session
      ON active_session.id = exact_session_id
     AND active_session.user_id = actor.id
    JOIN iam.session_families AS family
      ON family.id = active_session.family_id
     AND family.user_id = actor.id
    JOIN iam.organizations AS organization
      ON organization.id = exact_organization_id
    JOIN iam.memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.user_id = actor.id
    JOIN iam.membership_role_grants AS owner_grant
      ON owner_grant.organization_id = organization.id
     AND owner_grant.membership_id = membership.id
     AND owner_grant.user_id = actor.id
     AND owner_grant.role_code = 'DEMAND_OWNER'
    WHERE actor.id = exact_actor_user_id
      AND actor.status = 'ACTIVE'
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
      AND family.status = 'ACTIVE'
      AND family.revoked_at IS NULL
      AND organization.status = 'ACTIVE'
      AND membership.status = 'ACTIVE'
      AND owner_grant.granted_at <= transaction_timestamp()
      AND owner_grant.revoked_at IS NULL;
END
$function$;

ALTER FUNCTION iam_api.resolve_demand_owner_authority_marker_v1(
    uuid, uuid, uuid, text, uuid
) OWNER TO schema_owner;

CREATE FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_operation text,
    exact_demand_id uuid,
    exact_assignment_id uuid
)
RETURNS TABLE (authority_marker_sha256 bytea)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL
       OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL
       OR exact_demand_id = zero_uuid
       OR exact_assignment_id IS NULL
       OR exact_assignment_id = zero_uuid
       OR exact_operation NOT IN (
            'REQUEST_CHANGES',
            'VERIFY',
            'REQUEST_MATCHING',
            'CANCEL_REVIEW'
       )
       OR session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '')
            IS DISTINCT FROM exact_assignment_id::text THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT pg_catalog.sha256(
        pg_catalog.convert_to(
            pg_catalog.concat_ws(
                E'\x1f',
                'desire:iam:authority-marker:demand-reviewer:v1',
                exact_actor_user_id::text,
                exact_session_id::text,
                exact_organization_id::text,
                exact_operation,
                exact_demand_id::text,
                exact_assignment_id::text,
                actor.aggregate_version::text,
                family.id::text,
                family.aggregate_version::text,
                family.current_generation::text,
                coalesce(family.revoked_at::text, 'none'),
                active_session.aggregate_version::text,
                active_session.generation::text,
                extract(epoch FROM active_session.idle_expires_at)::text,
                extract(epoch FROM active_session.absolute_expires_at)::text,
                organization.aggregate_version::text,
                membership.id::text,
                membership.aggregate_version::text,
                membership.source_invitation_id::text,
                reviewer_duty.id::text,
                reviewer_duty.aggregate_version::text,
                extract(epoch FROM reviewer_duty.granted_at)::text,
                coalesce(
                    extract(epoch FROM reviewer_duty.expires_at)::text,
                    'none'
                ),
                coalesce(reviewer_duty.revoked_at::text, 'none')
            ),
            'UTF8'
        )
    )
    FROM iam.users AS actor
    JOIN iam.sessions AS active_session
      ON active_session.id = exact_session_id
     AND active_session.user_id = actor.id
    JOIN iam.session_families AS family
      ON family.id = active_session.family_id
     AND family.user_id = actor.id
    JOIN iam.organizations AS organization
      ON organization.id = exact_organization_id
    JOIN iam.memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.user_id = actor.id
    JOIN iam.platform_duty_grants AS reviewer_duty
      ON reviewer_duty.user_id = actor.id
     AND reviewer_duty.duty_code = 'OPERATIONS_REVIEWER'
    WHERE actor.id = exact_actor_user_id
      AND actor.status = 'ACTIVE'
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
      AND family.status = 'ACTIVE'
      AND family.revoked_at IS NULL
      AND organization.status = 'ACTIVE'
      AND membership.status = 'ACTIVE'
      AND reviewer_duty.granted_at <= transaction_timestamp()
      AND reviewer_duty.revoked_at IS NULL
      AND (
          reviewer_duty.expires_at IS NULL
          OR transaction_timestamp() < reviewer_duty.expires_at
      );
END
$function$;

ALTER FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid
) OWNER TO schema_owner;

-- A duty-only editor has no Organization or CREATOR workspace to select.  Keep
-- the established result shape and marker program while adding one closed
-- PLATFORM candidate for that otherwise-unrepresented principal.
CREATE OR REPLACE FUNCTION iam_api.resolve_editor_principal_v1(
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
    UNION ALL
    SELECT
        'platform:' || exact_actor_user_id::text,
        'PLATFORM'::text,
        exact_actor_user_id,
        exact_session_id,
        NULL::uuid,
        NULL::uuid,
        ARRAY[]::text[],
        active_user_roles,
        active_platform_duties,
        marker
    WHERE cardinality(active_platform_duties) > 0
    ORDER BY 1;
END
$function$;

ALTER FUNCTION iam_api.resolve_editor_principal_v1(uuid, uuid)
OWNER TO schema_owner;

REVOKE ALL ON FUNCTION iam_api.resolve_profile_self_authority_marker_v1(
    uuid, uuid, text, uuid
) FROM PUBLIC, profile_app, demand_self, demand_review;
REVOKE ALL ON FUNCTION iam_api.resolve_demand_owner_authority_marker_v1(
    uuid, uuid, uuid, text, uuid
) FROM PUBLIC, profile_app, demand_self, demand_review;
REVOKE ALL ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid
) FROM PUBLIC, profile_app, demand_self, demand_review;

GRANT USAGE ON SCHEMA iam_api TO profile_app, demand_self, demand_review;
GRANT EXECUTE ON FUNCTION iam_api.resolve_profile_self_authority_marker_v1(
    uuid, uuid, text, uuid
) TO profile_app;
GRANT EXECUTE ON FUNCTION iam_api.resolve_demand_owner_authority_marker_v1(
    uuid, uuid, uuid, text, uuid
) TO demand_self;
GRANT EXECUTE ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid
) TO demand_review;

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
    WHERE namespace.nspname = 'iam_api'
      AND procedure.proname IN (
        'resolve_profile_self_authority_marker_v1',
        'resolve_demand_owner_authority_marker_v1',
        'resolve_demand_reviewer_authority_marker_v1'
      )
      AND (
        owner_role.rolname <> 'schema_owner'
        OR NOT procedure.prosecdef
        OR procedure.provolatile <> 's'
        OR procedure.proparallel <> 'u'
        OR procedure.proconfig IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, iam']::text[]
        OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'authority marker resolver definition assertion failed';
    END IF;

    IF NOT pg_catalog.has_function_privilege(
        'profile_app',
        'iam_api.resolve_profile_self_authority_marker_v1(uuid,uuid,text,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_self',
        'iam_api.resolve_profile_self_authority_marker_v1(uuid,uuid,text,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_review',
        'iam_api.resolve_profile_self_authority_marker_v1(uuid,uuid,text,uuid)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'demand_self',
        'iam_api.resolve_demand_owner_authority_marker_v1(uuid,uuid,uuid,text,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'profile_app',
        'iam_api.resolve_demand_owner_authority_marker_v1(uuid,uuid,uuid,text,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_review',
        'iam_api.resolve_demand_owner_authority_marker_v1(uuid,uuid,uuid,text,uuid)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'demand_review',
        'iam_api.resolve_demand_reviewer_authority_marker_v1(uuid,uuid,uuid,text,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'profile_app',
        'iam_api.resolve_demand_reviewer_authority_marker_v1(uuid,uuid,uuid,text,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_self',
        'iam_api.resolve_demand_reviewer_authority_marker_v1(uuid,uuid,uuid,text,uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'authority marker resolver grant assertion failed';
    END IF;

    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'iam'
      AND policyname LIKE 'rls_authority_marker_%_definer'
      AND (
        cmd <> 'SELECT'
        OR roles IS DISTINCT FROM ARRAY['schema_owner']::name[]
      );
    IF invalid_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'authority marker resolver RLS assertion failed';
    END IF;
END
$assert$;
