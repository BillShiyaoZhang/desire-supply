-- IAM 0045: authenticated Matching reviewer claim authority.
--
-- Matching review is a bounded domain role derived from the actor's current
-- OPERATIONS_REVIEWER platform duty.  The exact target organization must be
-- ACTIVE and the actor must not be an ACTIVE member of it.  Browser input can
-- identify only the claim tuple; duty facts, the ordinary editor principal
-- marker, and the conflict evidence are derived inside IAM.

DO $iam45_role_guard$
DECLARE
    role_facts record;
    role_oid oid;
BEGIN
    SELECT oid, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
           rolreplication, rolbypassrls
    INTO role_facts
    FROM pg_catalog.pg_roles
    WHERE rolname = 'matching_review';
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
            CONSTRAINT = 'ck_iam45_matching_review_role',
            MESSAGE = 'matching review role is not provisioned';
    END IF;
END
$iam45_role_guard$;

-- Preserve all five existing contexts byte-for-byte within the replacement
-- body and add one exact internal branch.  matching_review cannot invoke this
-- helper or editor_principal_marker_v1 directly.
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
    WHEN session_user = 'matching_review' THEN
        current_user = 'schema_owner'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'MATCHING_REVIEW'
        AND NULLIF(current_setting('app.operation', true), '')
            = 'CLAIM_MATCHING_REVIEW'
        AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.attempt_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.purpose_code', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
    ELSE false
END
$function$;

ALTER FUNCTION iam_api.editor_principal_context_valid_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.editor_principal_context_valid_v1()
FROM PUBLIC, matching_assignment, matching_review, matching_schema_owner;

-- The original editor-principal organization policy exposes only
-- organizations linked to the actor.  A reviewer must prove the opposite for
-- the exact target, so this additional permissive policy exposes that one
-- organization while the restrictive guard below prevents broader reads.
CREATE POLICY rls_matching_review_target_organization_definer_v1
ON iam.organizations
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_review'
    AND iam_api.editor_principal_context_valid_v1()
    AND id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
);

-- These restrictive guards keep every existing runtime unchanged.  For the
-- new session_user they expose only the actor/session, the actor's complete
-- authority graph needed for the ordinary editor marker, and the exact target
-- organization needed for the conflict proof.
CREATE POLICY rls_matching_review_user_guard_v1
ON iam.users
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_review_family_guard_v1
ON iam.session_families
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_review_session_guard_v1
ON iam.sessions
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND id::text = NULLIF(current_setting('app.session_id', true), '')
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_review_organization_guard_v1
ON iam.organizations
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND (
            id::text = NULLIF(
                current_setting('app.organization_id', true), ''
            )
            OR EXISTS (
                SELECT 1
                FROM iam.memberships AS actor_membership
                WHERE actor_membership.organization_id = organizations.id
                  AND actor_membership.user_id::text = NULLIF(
                        current_setting('app.actor_user_id', true), ''
                  )
            )
        )
    )
);

CREATE POLICY rls_matching_review_membership_guard_v1
ON iam.memberships
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_review_user_role_guard_v1
ON iam.user_role_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_review_membership_role_guard_v1
ON iam.membership_role_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_review_duty_guard_v1
ON iam.platform_duty_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_review'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE FUNCTION iam_api.resolve_matching_reviewer_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_attempt_id uuid,
    exact_match_run_id uuid,
    exact_purpose_code text,
    exact_claim_command_id uuid
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    organization_id uuid,
    attempt_id uuid,
    match_run_id uuid,
    purpose_code varchar,
    role_code varchar,
    duty_code varchar,
    duty_grant_id uuid,
    duty_grant_version bigint,
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
       OR exact_attempt_id IS NULL OR exact_attempt_id = zero_uuid
       OR exact_match_run_id IS NULL OR exact_match_run_id = zero_uuid
       OR exact_claim_command_id IS NULL OR exact_claim_command_id = zero_uuid
       OR exact_purpose_code IS NULL
       OR exact_purpose_code NOT IN (
            'MATCH_RETRY', 'INVITATION_REVIEW', 'ATTEMPT_REVIEW'
       )
       OR session_user IS DISTINCT FROM 'matching_review'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_MATCHING_REVIEW'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.attempt_id', true), '')
            IS DISTINCT FROM exact_attempt_id::text
       OR NULLIF(current_setting('app.match_run_id', true), '')
            IS DISTINCT FROM exact_match_run_id::text
       OR NULLIF(current_setting('app.purpose_code', true), '')
            IS DISTINCT FROM exact_purpose_code
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_claim_command_id::text
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

    -- Recent authentication is closed at thirty minutes.  Claim evidence is
    -- intentionally shorter lived: five minutes, additionally capped by the
    -- authentication window, Session lifetimes, and duty expiry.
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
            target_organization.aggregate_version AS organization_version,
            reviewer_duty.id AS exact_duty_grant_id,
            reviewer_duty.aggregate_version AS exact_duty_grant_version,
            reviewer_duty.granted_at AS duty_granted_at,
            reviewer_duty.expires_at AS duty_expires_at,
            reviewer_duty.updated_at AS duty_updated_at,
            0::bigint AS target_active_membership_count,
            LEAST(
                active_session.idle_expires_at,
                active_session.absolute_expires_at,
                active_session.auth_time + interval '30 minutes',
                COALESCE(reviewer_duty.expires_at, 'infinity'::timestamptz),
                server_now + interval '5 minutes'
            ) AS bounded_valid_until
        FROM iam.users AS actor
        JOIN iam.session_families AS family
          ON family.user_id = actor.id
        JOIN iam.sessions AS active_session
          ON active_session.family_id = family.id
         AND active_session.user_id = family.user_id
        JOIN iam.organizations AS target_organization
          ON target_organization.id = exact_organization_id
        JOIN iam.platform_duty_grants AS reviewer_duty
          ON reviewer_duty.user_id = actor.id
         AND reviewer_duty.duty_code = 'OPERATIONS_REVIEWER'
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
          AND target_organization.status = 'ACTIVE'
          AND reviewer_duty.granted_at <= server_now
          AND reviewer_duty.revoked_at IS NULL
          AND (
                reviewer_duty.expires_at IS NULL
                OR server_now < reviewer_duty.expires_at
          )
          AND NOT EXISTS (
                SELECT 1
                FROM iam.memberships AS conflict_membership
                WHERE conflict_membership.organization_id
                        = exact_organization_id
                  AND conflict_membership.user_id = exact_actor_user_id
                  AND conflict_membership.status = 'ACTIVE'
          )
    ), evidence AS (
        SELECT
            eligible.*,
            sha256(convert_to(
                'desire.iam.matching-reviewer-claim-evidence.v1'
                || '|iam_head=45'
                || '|operation=CLAIM_MATCHING_REVIEW'
                || '|purpose_code=' || exact_purpose_code
                || '|role_code=MATCHING_REVIEWER'
                || '|duty_code=OPERATIONS_REVIEWER'
                || '|duty_status=ACTIVE'
                || '|target_organization_status=ACTIVE'
                || '|actor_user_id=' || exact_actor_user_id::text
                || '|session_id=' || exact_session_id::text
                || '|organization_id=' || exact_organization_id::text
                || '|attempt_id=' || exact_attempt_id::text
                || '|match_run_id=' || exact_match_run_id::text
                || '|claim_command_id=' || exact_claim_command_id::text
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
                || '|duty_grant_id=' || eligible.exact_duty_grant_id::text
                || '|duty_grant_version='
                || eligible.exact_duty_grant_version::text
                || '|duty_granted_epoch='
                || extract(epoch FROM eligible.duty_granted_at)::text
                || '|duty_expires_epoch='
                || COALESCE(
                    extract(epoch FROM eligible.duty_expires_at)::text,
                    'none'
                )
                || '|duty_updated_epoch='
                || extract(epoch FROM eligible.duty_updated_at)::text
                || '|conflict_policy=TARGET_ACTIVE_MEMBERSHIP_ABSENT'
                || '|target_active_membership_count='
                || eligible.target_active_membership_count::text
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
        exact_attempt_id,
        exact_match_run_id,
        exact_purpose_code::varchar,
        'MATCHING_REVIEWER'::varchar,
        'OPERATIONS_REVIEWER'::varchar,
        evidence.exact_duty_grant_id,
        evidence.exact_duty_grant_version,
        principal_marker,
        evidence.exact_evidence_sha256,
        evidence.bounded_valid_until
    FROM evidence;
END
$function$;

ALTER FUNCTION iam_api.resolve_matching_reviewer_authority_marker_v1(
    uuid, uuid, uuid, uuid, uuid, text, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_matching_reviewer_authority_marker_v1(
    uuid, uuid, uuid, uuid, uuid, text, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_matching_reviewer_authority_marker_v1(
    uuid, uuid, uuid, uuid, uuid, text, uuid
) TO matching_review, matching_schema_owner;

GRANT USAGE ON SCHEMA iam_api
TO matching_review, matching_schema_owner;
REVOKE CREATE ON SCHEMA iam_api
FROM matching_review, matching_schema_owner;

DO $iam45_readiness$
DECLARE
    review_oid oid;
    matching_owner_oid oid;
    schema_owner_oid oid;
    resolver_oid oid;
    context_oid oid;
    invalid_function_count integer;
    unexpected_execute_acl_count integer;
    direct_relation_acl_count integer;
    guard_policy_count integer;
    target_policy_count integer;
    context_definition text;
BEGIN
    SELECT oid INTO STRICT review_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'matching_review';
    SELECT oid INTO STRICT matching_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'matching_schema_owner';
    SELECT oid INTO STRICT schema_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'schema_owner';
    SELECT 'iam_api.resolve_matching_reviewer_authority_marker_v1('
           'uuid,uuid,uuid,uuid,uuid,text,uuid)'::regprocedure::oid
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
                    OR procedure.pronargs <> 7
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
                schema_owner_oid, review_oid, matching_owner_oid
            )
            OR (
                privilege.grantee IN (review_oid, matching_owner_oid)
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
            privilege.grantee = review_oid
            OR column_privilege.grantee = review_oid
      );

    SELECT count(*) INTO STRICT guard_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname IN (
        'rls_matching_review_user_guard_v1',
        'rls_matching_review_family_guard_v1',
        'rls_matching_review_session_guard_v1',
        'rls_matching_review_organization_guard_v1',
        'rls_matching_review_membership_guard_v1',
        'rls_matching_review_user_role_guard_v1',
        'rls_matching_review_membership_role_guard_v1',
        'rls_matching_review_duty_guard_v1'
    )
      AND NOT policy.polpermissive
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY[schema_owner_oid];

    SELECT count(*) INTO STRICT target_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname = 'rls_matching_review_target_organization_definer_v1'
      AND policy.polpermissive
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY[schema_owner_oid];

    IF invalid_function_count <> 0
       OR unexpected_execute_acl_count <> 0
       OR direct_relation_acl_count <> 0
       OR guard_policy_count <> 8
       OR target_policy_count <> 1
       OR context_definition NOT LIKE '%matching_review%'
       OR context_definition NOT LIKE '%MATCHING_REVIEW%'
       OR context_definition NOT LIKE '%CLAIM_MATCHING_REVIEW%'
       OR NOT pg_catalog.has_schema_privilege(
            'matching_review', 'iam_api', 'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_review', 'iam_api', 'CREATE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_review', 'iam', 'USAGE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_review', resolver_oid, 'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_schema_owner', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_assignment', resolver_oid, 'EXECUTE'
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
            'demand_review', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'iam_app', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_review', context_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_review',
            'iam_api.editor_principal_marker_v1(uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_iam45_matching_reviewer_readiness',
            MESSAGE = 'IAM45 matching reviewer authority drifted';
    END IF;
END
$iam45_readiness$;
