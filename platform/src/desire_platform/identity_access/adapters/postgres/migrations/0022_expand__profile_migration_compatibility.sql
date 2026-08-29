-- IAM 0022: allow the independent Profile migration runner to verify only
-- the reviewed IAM schema compatibility projection before applying Profile SQL.

GRANT USAGE ON SCHEMA infra TO profile_migration_runner;
GRANT SELECT ON TABLE infra.iam_schema_compatibility TO profile_migration_runner;

-- Resolver output is an input to the older canonical lock programs.  Keep the
-- read-only producer byte-for-byte aligned with those programs instead of
-- introducing a second authority-marker protocol.
CREATE OR REPLACE FUNCTION iam_api.resolve_profile_self_authority_marker_v1(
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
            actor.id::text || '|' ||
            exact_session_id::text || '|' ||
            creator_grant.id::text || '|' ||
            pg_catalog.encode(creator_grant.policy_selector_digest, 'hex') || '|' ||
            selector.current_bundle_id::text || '|' ||
            actor.aggregate_version::text || '|' ||
            creator_grant.aggregate_version::text,
            'UTF8'
        )
    )
    FROM iam.session_families AS family
    JOIN iam.sessions AS active_session
      ON active_session.family_id = family.id
     AND active_session.user_id = family.user_id
    JOIN iam.users AS actor
      ON actor.id = active_session.user_id
    JOIN iam.user_role_grants AS creator_grant
      ON creator_grant.user_id = actor.id
     AND creator_grant.role_code = 'CREATOR'
     AND creator_grant.revoked_at IS NULL
    JOIN iam.access_invitations AS source_invitation
      ON source_invitation.id = creator_grant.source_invitation_id
     AND source_invitation.policy_selector_digest
         = creator_grant.policy_selector_digest
     AND source_invitation.status = 'ACCEPTED'
     AND source_invitation.accepted_by_user_id = actor.id
     AND source_invitation.purpose = 'CREATOR_ENROLLMENT'
     AND source_invitation.target_scope = 'USER'
     AND source_invitation.target_role = 'CREATOR'
    JOIN iam.policy_selectors AS selector
      ON selector.selector_digest = creator_grant.policy_selector_digest
     AND selector.access_purpose = 'CREATOR_ENROLLMENT'
     AND selector.scope_type = 'USER_ROLE'
     AND selector.target_role = 'CREATOR'
     AND selector.current_bundle_id IS NOT NULL
    JOIN iam.policy_bundles AS current_bundle
      ON current_bundle.id = selector.current_bundle_id
     AND current_bundle.selector_digest = selector.selector_digest
     AND current_bundle.status = 'ACTIVE'
     AND current_bundle.effective_at <= transaction_timestamp()
     AND (
        current_bundle.effective_until IS NULL
        OR current_bundle.effective_until > transaction_timestamp()
     )
    WHERE family.status = 'ACTIVE'
      AND family.current_generation = active_session.generation
      AND active_session.id = exact_session_id
      AND active_session.user_id = exact_actor_user_id
      AND active_session.status = 'ACTIVE'
      AND active_session.idle_expires_at > transaction_timestamp()
      AND active_session.absolute_expires_at > transaction_timestamp()
      AND actor.id = exact_actor_user_id
      AND actor.status = 'ACTIVE'
      AND NOT EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        JOIN iam.policy_documents AS document
          ON document.id = membership.document_id
        WHERE membership.bundle_id = current_bundle.id
          AND membership.required
          AND (
            document.status <> 'ACTIVE'
            OR document.effective_at IS NULL
            OR document.effective_at > transaction_timestamp()
            OR document.legal_effect NOT IN (
                'NOTICE_ACKNOWLEDGEMENT',
                'CONTRACT_ACCEPTANCE'
            )
            OR NOT EXISTS (
                SELECT 1
                FROM iam.policy_acceptances AS acceptance
                WHERE acceptance.user_id = actor.id
                  AND acceptance.document_id = document.id
                  AND acceptance.content_sha256 = document.content_sha256
            )
          )
      );
END
$function$;

CREATE OR REPLACE FUNCTION iam_api.resolve_demand_owner_authority_marker_v1(
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
            'iam-demand-owner-authority-v1|' ||
            exact_operation || '|' ||
            exact_demand_id::text || '|' ||
            family.id::text || '|' ||
            family.aggregate_version::text || '|' ||
            exact_session_id::text || '|' ||
            active_session.aggregate_version::text || '|' ||
            active_session.generation::text || '|' ||
            exact_actor_user_id::text || '|' ||
            actor.aggregate_version::text || '|' ||
            exact_organization_id::text || '|' ||
            organization.aggregate_version::text || '|' ||
            membership.id::text || '|' ||
            membership.aggregate_version::text || '|' ||
            owner_grant.id::text || '|' ||
            owner_grant.aggregate_version::text || '|' ||
            source_invitation.id::text || '|' ||
            source_invitation.aggregate_version::text || '|' ||
            pg_catalog.encode(owner_grant.policy_selector_digest, 'hex') || '|' ||
            selector.aggregate_version::text || '|' ||
            current_bundle.id::text || '|' ||
            current_bundle.aggregate_version::text,
            'UTF8'
        )
    )
    FROM iam.session_families AS family
    JOIN iam.sessions AS active_session
      ON active_session.family_id = family.id
     AND active_session.user_id = family.user_id
    JOIN iam.users AS actor
      ON actor.id = active_session.user_id
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
     AND owner_grant.revoked_at IS NULL
    JOIN iam.access_invitations AS source_invitation
      ON source_invitation.id = owner_grant.source_invitation_id
     AND source_invitation.organization_id = exact_organization_id
     AND source_invitation.accepted_by_user_id = exact_actor_user_id
     AND source_invitation.policy_selector_digest
         = owner_grant.policy_selector_digest
     AND source_invitation.purpose = 'ORGANIZATION_MEMBERSHIP'
     AND source_invitation.target_scope = 'ORGANIZATION'
     AND source_invitation.target_role = 'DEMAND_OWNER'
     AND source_invitation.status = 'ACCEPTED'
     AND source_invitation.terminal_at IS NOT NULL
     AND source_invitation.terminal_reason_code IS NULL
    JOIN iam.policy_selectors AS selector
      ON selector.selector_digest = owner_grant.policy_selector_digest
     AND selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
     AND selector.scope_type = 'ORGANIZATION_ROLE'
     AND selector.target_role = 'DEMAND_OWNER'
     AND selector.current_bundle_id IS NOT NULL
    JOIN iam.policy_bundles AS current_bundle
      ON current_bundle.id = selector.current_bundle_id
     AND current_bundle.selector_digest = owner_grant.policy_selector_digest
     AND current_bundle.status = 'ACTIVE'
     AND current_bundle.effective_at <= transaction_timestamp()
     AND (
        current_bundle.effective_until IS NULL
        OR current_bundle.effective_until > transaction_timestamp()
     )
    WHERE family.user_id = exact_actor_user_id
      AND family.status = 'ACTIVE'
      AND active_session.id = exact_session_id
      AND active_session.user_id = exact_actor_user_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND active_session.idle_expires_at > transaction_timestamp()
      AND active_session.absolute_expires_at > transaction_timestamp()
      AND actor.id = exact_actor_user_id
      AND actor.status = 'ACTIVE'
      AND organization.status = 'ACTIVE'
      AND membership.status = 'ACTIVE'
      AND NOT EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS bundle_membership
        JOIN iam.policy_documents AS document
          ON document.id = bundle_membership.document_id
        WHERE bundle_membership.bundle_id = current_bundle.id
          AND bundle_membership.required
          AND (
            document.status <> 'ACTIVE'
            OR document.effective_at IS NULL
            OR document.effective_at > transaction_timestamp()
            OR document.legal_effect NOT IN (
                'NOTICE_ACKNOWLEDGEMENT',
                'CONTRACT_ACCEPTANCE'
            )
            OR NOT EXISTS (
                SELECT 1
                FROM iam.policy_acceptances AS acceptance
                WHERE acceptance.user_id = exact_actor_user_id
                  AND acceptance.document_id = document.id
                  AND acceptance.content_sha256 = document.content_sha256
            )
          )
      );
END
$function$;

CREATE OR REPLACE FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
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
            'iam-demand-reviewer-session-v1|' ||
            exact_operation || '|' ||
            exact_organization_id::text || '|' ||
            exact_demand_id::text || '|' ||
            exact_assignment_id::text || '|' ||
            family.id::text || '|' ||
            family.aggregate_version::text || '|' ||
            exact_session_id::text || '|' ||
            active_session.aggregate_version::text || '|' ||
            active_session.generation::text || '|' ||
            exact_actor_user_id::text || '|' ||
            actor.aggregate_version::text,
            'UTF8'
        )
    )
    FROM iam.session_families AS family
    JOIN iam.sessions AS active_session
      ON active_session.family_id = family.id
     AND active_session.user_id = family.user_id
    JOIN iam.users AS actor
      ON actor.id = active_session.user_id
    WHERE family.user_id = exact_actor_user_id
      AND family.status = 'ACTIVE'
      AND active_session.id = exact_session_id
      AND active_session.user_id = exact_actor_user_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND active_session.idle_expires_at > transaction_timestamp()
      AND active_session.absolute_expires_at > transaction_timestamp()
      AND actor.id = exact_actor_user_id
      AND actor.status = 'ACTIVE';
END
$function$;

-- Workspace kind chooses which authority layer may be activated by the
-- application. Organization roles are always scoped to the exact ORG
-- candidate; a role in one organization must never appear on another ORG
-- candidate or on a workspace with no organization identity.
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

ALTER FUNCTION iam_api.resolve_profile_self_authority_marker_v1(
    uuid, uuid, text, uuid
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.resolve_demand_owner_authority_marker_v1(
    uuid, uuid, uuid, text, uuid
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.resolve_editor_principal_v1(uuid, uuid)
OWNER TO schema_owner;

DO $assert$
BEGIN
    IF NOT pg_catalog.has_schema_privilege(
        'profile_migration_runner',
        'infra',
        'USAGE'
    ) OR NOT pg_catalog.has_table_privilege(
        'profile_migration_runner',
        'infra.iam_schema_compatibility',
        'SELECT'
    ) OR pg_catalog.has_table_privilege(
        'profile_migration_runner',
        'infra.iam_schema_contracts',
        'SELECT'
    ) OR pg_catalog.has_table_privilege(
        'profile_migration_runner',
        'infra.schema_migrations',
        'SELECT'
    ) OR pg_catalog.has_table_privilege(
        'profile_migration_runner',
        'iam.users',
        'SELECT'
    ) OR pg_catalog.has_function_privilege(
        'profile_migration_runner',
        'iam_api.resolve_profile_self_authority_marker_v1(uuid,uuid,text,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Profile migration IAM compatibility grant assertion failed';
    END IF;
END
$assert$;
