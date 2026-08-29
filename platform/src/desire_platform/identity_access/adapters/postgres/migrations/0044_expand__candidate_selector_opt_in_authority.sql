-- IAM 0044: authenticated, selection-scoped Candidate Selector opt-in.
--
-- Candidate Selector is not a standing IAM role.  Any exact ACTIVE member of
-- the selected ACTIVE organization may opt in, but only through the dedicated
-- matching_assignment login and an exact, transaction-local request context.
-- The generic editor principal marker remains the authority consumed by later
-- selector requests.  A separate IAM44 evidence digest binds the one-off
-- opt-in purpose, organization, selection, demand, command, and current IAM
-- state so the opt-in cannot be replayed for another tuple.

DO $iam44_role_guard$
DECLARE
    role_facts record;
    role_oid oid;
BEGIN
    SELECT oid, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
           rolreplication, rolbypassrls
    INTO role_facts
    FROM pg_catalog.pg_roles
    WHERE rolname = 'matching_assignment';
    role_oid := role_facts.oid;

    IF NOT FOUND
       OR NOT role_facts.rolcanlogin
       OR role_facts.rolinherit
       OR role_facts.rolsuper
       OR role_facts.rolcreatedb
       OR role_facts.rolcreaterole
       OR role_facts.rolreplication
       OR role_facts.rolbypassrls
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = role_oid
               OR membership.roleid = role_oid
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam44_matching_assignment_role',
            MESSAGE = 'matching assignment role is not provisioned';
    END IF;
END
$iam44_role_guard$;

-- Preserve every existing editor-principal context and add exactly one
-- internal branch.  matching_assignment receives no EXECUTE authority on this
-- helper or on editor_principal_marker_v1; the IAM44 resolver invokes the
-- marker as schema_owner after validating the full opt-in tuple.
CREATE OR REPLACE FUNCTION iam_api.editor_principal_context_valid_v1()
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
    WHEN session_user = 'matching_assignment' THEN
        current_user = 'schema_owner'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'MATCHING_ASSIGNMENT'
        AND NULLIF(current_setting('app.operation', true), '')
            = 'OPT_IN_CANDIDATE_SELECTOR'
        AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.selection_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.demand_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
    ELSE false
END
$function$;

ALTER FUNCTION iam_api.editor_principal_context_valid_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.editor_principal_context_valid_v1()
FROM PUBLIC, matching_assignment, matching_schema_owner;

-- These restrictive guards leave every existing runtime unchanged.  For the
-- new session_user they ensure that the schema owner can see only the exact
-- actor/session and that actor's authority facts.  The generic principal
-- marker intentionally covers all of the actor's active workspace authority;
-- the exact target organization is proven separately by the resolver and the
-- IAM44 evidence digest.
CREATE POLICY rls_candidate_selector_opt_in_user_guard_v1
ON iam.users
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_family_guard_v1
ON iam.session_families
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_session_guard_v1
ON iam.sessions
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND id::text = NULLIF(current_setting('app.session_id', true), '')
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_organization_guard_v1
ON iam.organizations
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND EXISTS (
            SELECT 1
            FROM iam.memberships AS actor_membership
            WHERE actor_membership.organization_id = organizations.id
              AND actor_membership.user_id::text = NULLIF(
                    current_setting('app.actor_user_id', true), ''
              )
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_membership_guard_v1
ON iam.memberships
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_user_role_guard_v1
ON iam.user_role_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_membership_role_guard_v1
ON iam.membership_role_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_candidate_selector_opt_in_duty_guard_v1
ON iam.platform_duty_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_assignment'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE FUNCTION iam_api.resolve_candidate_selector_opt_in_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_selection_id uuid,
    exact_demand_id uuid,
    exact_command_id uuid
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    organization_id uuid,
    selection_id uuid,
    demand_id uuid,
    role_code varchar,
    authority_marker_sha256 bytea,
    evidence_sha256 bytea,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    server_now timestamptz := transaction_timestamp();
    principal_marker bytea;
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_selection_id IS NULL OR exact_selection_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_command_id IS NULL OR exact_command_id = zero_uuid
       OR session_user IS DISTINCT FROM 'matching_assignment'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_ASSIGNMENT'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'OPT_IN_CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NOT iam_api.editor_principal_context_valid_v1() THEN
        RETURN;
    END IF;

    principal_marker := iam_api.editor_principal_marker_v1(
        exact_actor_user_id,
        exact_session_id
    );
    IF principal_marker IS NULL OR octet_length(principal_marker) <> 32 THEN
        RETURN;
    END IF;

    -- Thirty minutes is the closed recent-authentication window for an
    -- explicit selector opt-in.  valid_until never exceeds either Session
    -- expiry, so already-issued evidence stops authorizing immediately when
    -- the bounded authentication window or Session lifetime ends.
    RETURN QUERY
    WITH eligible AS (
        SELECT
            actor.aggregate_version AS user_version,
            family.id AS family_id,
            family.aggregate_version AS family_version,
            family.current_generation AS family_generation,
            active_session.aggregate_version AS session_version,
            active_session.generation AS session_generation,
            active_session.auth_time,
            active_session.last_activity_at,
            active_session.idle_expires_at,
            active_session.absolute_expires_at,
            organization.aggregate_version AS organization_version,
            membership.id AS membership_id,
            membership.aggregate_version AS membership_version,
            membership.updated_at AS membership_updated_at,
            LEAST(
                active_session.idle_expires_at,
                active_session.absolute_expires_at,
                active_session.auth_time + interval '30 minutes'
            ) AS bounded_valid_until
        FROM iam.users AS actor
        JOIN iam.session_families AS family
          ON family.user_id = actor.id
        JOIN iam.sessions AS active_session
          ON active_session.family_id = family.id
         AND active_session.user_id = family.user_id
        JOIN iam.organizations AS organization
          ON organization.id = exact_organization_id
        JOIN iam.memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.user_id = actor.id
        WHERE actor.id = exact_actor_user_id
          AND actor.status = 'ACTIVE'
          AND family.status = 'ACTIVE'
          AND family.revoked_at IS NULL
          AND active_session.id = exact_session_id
          AND active_session.status = 'ACTIVE'
          AND active_session.revoked_at IS NULL
          AND active_session.generation = family.current_generation
          AND active_session.auth_time <= server_now
          AND active_session.auth_time > server_now - interval '30 minutes'
          AND active_session.last_activity_at <= server_now
          AND active_session.last_activity_at < active_session.idle_expires_at
          AND server_now < active_session.idle_expires_at
          AND server_now < active_session.absolute_expires_at
          AND organization.status = 'ACTIVE'
          AND membership.status = 'ACTIVE'
    ), evidence AS (
        SELECT
            eligible.*,
            sha256(convert_to(
                'desire.iam.candidate-selector-opt-in-evidence.v1'
                || '|iam_head=44'
                || '|purpose=OPT_IN_CANDIDATE_SELECTOR'
                || '|role_code=CANDIDATE_SELECTOR'
                || '|actor_user_id=' || exact_actor_user_id::text
                || '|session_id=' || exact_session_id::text
                || '|organization_id=' || exact_organization_id::text
                || '|selection_id=' || exact_selection_id::text
                || '|demand_id=' || exact_demand_id::text
                || '|command_id=' || exact_command_id::text
                || '|user_version=' || eligible.user_version::text
                || '|family_id=' || eligible.family_id::text
                || '|family_version=' || eligible.family_version::text
                || '|family_generation=' || eligible.family_generation::text
                || '|session_version=' || eligible.session_version::text
                || '|session_generation=' || eligible.session_generation::text
                || '|auth_time_epoch='
                || extract(epoch FROM eligible.auth_time)::text
                || '|last_activity_epoch='
                || extract(epoch FROM eligible.last_activity_at)::text
                || '|idle_expires_epoch='
                || extract(epoch FROM eligible.idle_expires_at)::text
                || '|absolute_expires_epoch='
                || extract(epoch FROM eligible.absolute_expires_at)::text
                || '|organization_version='
                || eligible.organization_version::text
                || '|membership_id=' || eligible.membership_id::text
                || '|membership_version=' || eligible.membership_version::text
                || '|membership_updated_epoch='
                || extract(epoch FROM eligible.membership_updated_at)::text
                || '|principal_marker_sha256='
                || encode(principal_marker, 'hex')
                || '|valid_until_epoch='
                || extract(epoch FROM eligible.bounded_valid_until)::text,
                'UTF8'
            )) AS exact_evidence_sha256
        FROM eligible
        WHERE eligible.bounded_valid_until > server_now
    )
    SELECT
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        exact_selection_id,
        exact_demand_id,
        'CANDIDATE_SELECTOR'::varchar,
        principal_marker,
        evidence.exact_evidence_sha256,
        evidence.bounded_valid_until
    FROM evidence;
END
$function$;

ALTER FUNCTION iam_api.resolve_candidate_selector_opt_in_marker_v1(
    uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_candidate_selector_opt_in_marker_v1(
    uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_candidate_selector_opt_in_marker_v1(
    uuid, uuid, uuid, uuid, uuid, uuid
) TO matching_assignment, matching_schema_owner;

GRANT USAGE ON SCHEMA iam_api
TO matching_assignment, matching_schema_owner;
REVOKE CREATE ON SCHEMA iam_api
FROM matching_assignment, matching_schema_owner;

DO $iam44_readiness$
DECLARE
    assignment_oid oid;
    matching_owner_oid oid;
    schema_owner_oid oid;
    resolver_oid oid;
    context_oid oid;
    invalid_function_count integer;
    unexpected_execute_acl_count integer;
    direct_relation_acl_count integer;
    guard_policy_count integer;
    context_definition text;
BEGIN
    SELECT oid INTO STRICT assignment_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'matching_assignment';
    SELECT oid INTO STRICT matching_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'matching_schema_owner';
    SELECT oid INTO STRICT schema_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'schema_owner';
    SELECT 'iam_api.resolve_candidate_selector_opt_in_marker_v1('
           'uuid,uuid,uuid,uuid,uuid,uuid)'::regprocedure::oid
    INTO STRICT resolver_oid;
    SELECT 'iam_api.editor_principal_context_valid_v1()'::regprocedure::oid
    INTO STRICT context_oid;

    SELECT pg_catalog.pg_get_functiondef(context_oid)
    INTO STRICT context_definition;

    SELECT count(*) INTO STRICT invalid_function_count
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid IN (resolver_oid, context_oid)
      AND (
            procedure.proowner <> schema_owner_oid
            OR NOT procedure.prosecdef
            OR procedure.provolatile <> 's'
            OR procedure.proparallel <> 'u'
            OR procedure.proconfig IS NULL
            OR (
                procedure.oid = resolver_oid
                AND (
                    NOT procedure.proretset
                    OR procedure.pronargs <> 6
                    OR procedure.prorettype <> 'record'::regtype
                    OR NOT (
                        'search_path=pg_catalog, iam, iam_api'
                        = ANY(procedure.proconfig)
                    )
                )
            )
            OR (
                procedure.oid = context_oid
                AND (
                    procedure.proretset
                    OR procedure.pronargs <> 0
                    OR procedure.prorettype <> 'boolean'::regtype
                    OR NOT (
                        'search_path=pg_catalog' = ANY(procedure.proconfig)
                    )
                )
            )
      );

    SELECT count(*) INTO STRICT unexpected_execute_acl_count
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            procedure.proacl,
            pg_catalog.acldefault('f', procedure.proowner)
        )
    ) AS privilege
    WHERE procedure.oid = resolver_oid
      AND privilege.privilege_type = 'EXECUTE'
      AND (
            privilege.grantee NOT IN (
                schema_owner_oid, assignment_oid, matching_owner_oid
            )
            OR (
                privilege.grantee IN (assignment_oid, matching_owner_oid)
                AND privilege.is_grantable
            )
      );

    SELECT count(*) INTO STRICT direct_relation_acl_count
    FROM pg_catalog.pg_class AS relation
    LEFT JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS privilege
      ON true
    LEFT JOIN pg_catalog.pg_attribute AS column_acl
      ON column_acl.attrelid = relation.oid
     AND column_acl.attnum > 0
     AND NOT column_acl.attisdropped
    LEFT JOIN LATERAL pg_catalog.aclexplode(column_acl.attacl) AS column_privilege
      ON true
    WHERE relation.relnamespace = 'iam'::regnamespace
      AND (
            privilege.grantee = assignment_oid
            OR column_privilege.grantee = assignment_oid
      );

    SELECT count(*) INTO STRICT guard_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname IN (
        'rls_candidate_selector_opt_in_user_guard_v1',
        'rls_candidate_selector_opt_in_family_guard_v1',
        'rls_candidate_selector_opt_in_session_guard_v1',
        'rls_candidate_selector_opt_in_organization_guard_v1',
        'rls_candidate_selector_opt_in_membership_guard_v1',
        'rls_candidate_selector_opt_in_user_role_guard_v1',
        'rls_candidate_selector_opt_in_membership_role_guard_v1',
        'rls_candidate_selector_opt_in_duty_guard_v1'
    )
      AND NOT policy.polpermissive
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY[schema_owner_oid];

    IF invalid_function_count <> 0
       OR unexpected_execute_acl_count <> 0
       OR direct_relation_acl_count <> 0
       OR guard_policy_count <> 8
       OR context_definition NOT LIKE '%matching_assignment%'
       OR context_definition NOT LIKE '%MATCHING_ASSIGNMENT%'
       OR context_definition NOT LIKE '%OPT_IN_CANDIDATE_SELECTOR%'
       OR NOT pg_catalog.has_schema_privilege(
            'matching_assignment', 'iam_api', 'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_assignment', 'iam_api', 'CREATE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_assignment', 'iam', 'USAGE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_assignment', resolver_oid, 'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_schema_owner', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_selector', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_worker', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_coordinator', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'iam_app', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_assignment', context_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_assignment',
            'iam_api.editor_principal_marker_v1(uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_iam44_candidate_selector_opt_in_readiness',
            MESSAGE = 'IAM44 candidate selector opt-in authority drifted';
    END IF;
END
$iam44_readiness$;
