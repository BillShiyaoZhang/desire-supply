-- IAM 0037: distinct exact-resource authority for manual funding review.
--
-- IAM31's v1 CLAIM/CONFIRM lock and ACL remain unchanged.  The v2 lock is
-- deliberately limited to assignment release and finding submission.  A
-- finding's closed disposition is owned by Demand and is not an IAM operation.

DO $prerequisites$
BEGIN
    IF pg_catalog.to_regprocedure(
        'iam.finance_funding_authority_context_v1()'
    ) IS NULL
       OR pg_catalog.to_regprocedure(
            'iam_api.verify_finance_funding_principal_marker_v1(uuid,uuid,bytea)'
       ) IS NULL
       OR pg_catalog.to_regprocedure(
            'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)'
       ) IS NULL
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_schema_owner',
            'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'finance funding IAM31 authority prerequisite missing';
    END IF;
END
$prerequisites$;

CREATE OR REPLACE FUNCTION iam.finance_funding_authority_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT
    session_user = 'demand_finance'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'LIST_FUNDING_REVIEWS',
        'GET_FUNDING_REVIEW',
        'CLAIM_FUNDING_REVIEW',
        'CONFIRM_FUNDING_REVIEW',
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
$function$;

ALTER FUNCTION iam.finance_funding_authority_context_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.finance_funding_authority_context_v1()
FROM PUBLIC;

CREATE FUNCTION iam_api.lock_finance_funding_authority_v2(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    candidate_organization_id uuid,
    candidate_demand_id uuid,
    candidate_funding_review_id uuid,
    candidate_assignment_id uuid,
    candidate_operation text,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    locked_family_id uuid;
    locked_family_version bigint;
    locked_family_generation bigint;
    locked_session_version bigint;
    locked_session_generation bigint;
    locked_user_version bigint;
    locked_organization_version bigint;
    locked_duty_id uuid;
    locked_duty_version bigint;
    locked_duty_expires_at timestamptz;
    computed_marker bytea;
BEGIN
    IF candidate_actor_user_id IS NULL
       OR candidate_actor_user_id = zero_uuid
       OR candidate_session_id IS NULL
       OR candidate_session_id = zero_uuid
       OR candidate_organization_id IS NULL
       OR candidate_organization_id = zero_uuid
       OR candidate_demand_id IS NULL
       OR candidate_demand_id = zero_uuid
       OR candidate_funding_review_id IS NULL
       OR candidate_funding_review_id = zero_uuid
       OR candidate_assignment_id IS NULL
       OR candidate_assignment_id = zero_uuid
       OR candidate_operation IS NULL
       OR candidate_operation NOT IN (
            'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
            'SUBMIT_FUNDING_REVIEW_FINDING'
       )
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.finance_funding_authority_context_v1()
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM candidate_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM candidate_demand_id::text
       OR NULLIF(current_setting('app.funding_review_id', true), '')
            IS DISTINCT FROM candidate_funding_review_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '')
            IS DISTINCT FROM candidate_assignment_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM candidate_operation
       OR NOT iam_api.verify_finance_funding_principal_marker_v1(
            candidate_actor_user_id,
            candidate_session_id,
            expected_principal_marker_sha256
       ) THEN
        RETURN;
    END IF;

    SELECT family.id, family.aggregate_version, family.current_generation
    INTO locked_family_id, locked_family_version, locked_family_generation
    FROM iam.session_families AS family
    WHERE family.user_id = candidate_actor_user_id
      AND family.status = 'ACTIVE'
      AND family.revoked_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM iam.sessions AS candidate_session
          WHERE candidate_session.id = candidate_session_id
            AND candidate_session.family_id = family.id
            AND candidate_session.user_id = candidate_actor_user_id
      )
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT active_session.aggregate_version, active_session.generation
    INTO locked_session_version, locked_session_generation
    FROM iam.sessions AS active_session
    WHERE active_session.id = candidate_session_id
      AND active_session.family_id = locked_family_id
      AND active_session.user_id = candidate_actor_user_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = locked_family_generation
      AND active_session.last_activity_at <= transaction_timestamp()
      AND active_session.last_activity_at < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT actor.aggregate_version
    INTO locked_user_version
    FROM iam.users AS actor
    WHERE actor.id = candidate_actor_user_id
      AND actor.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT organization.aggregate_version
    INTO locked_organization_version
    FROM iam.organizations AS organization
    WHERE organization.id = candidate_organization_id
      AND organization.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM 1
    FROM iam.memberships AS membership
    WHERE membership.organization_id = candidate_organization_id
      AND membership.user_id = candidate_actor_user_id
      AND membership.status = 'ACTIVE'
    FOR UPDATE;
    IF FOUND THEN RETURN; END IF;

    SELECT duty.id, duty.aggregate_version, duty.expires_at
    INTO locked_duty_id, locked_duty_version, locked_duty_expires_at
    FROM iam.platform_duty_grants AS duty
    WHERE duty.user_id = candidate_actor_user_id
      AND duty.duty_code = 'FINANCE_OPERATOR'
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (
          duty.expires_at IS NULL
          OR transaction_timestamp() < duty.expires_at
      )
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    IF NOT iam_api.verify_finance_funding_principal_marker_v1(
        candidate_actor_user_id,
        candidate_session_id,
        expected_principal_marker_sha256
    ) THEN
        RETURN;
    END IF;

    computed_marker := sha256(convert_to(
        'iam-finance-funding-authority-v2|' || candidate_operation || '|' ||
        candidate_actor_user_id::text || '|' || candidate_session_id::text ||
        '|' || candidate_organization_id::text || '|' ||
        candidate_demand_id::text || '|' ||
        candidate_funding_review_id::text || '|' ||
        candidate_assignment_id::text || '|' || locked_family_id::text || '|' ||
        locked_family_version::text || '|' ||
        locked_family_generation::text || '|' ||
        locked_session_version::text || '|' ||
        locked_session_generation::text || '|' || locked_user_version::text ||
        '|' || locked_organization_version::text || '|' ||
        locked_duty_id::text || '|' || locked_duty_version::text || '|' ||
        COALESCE(extract(epoch FROM locked_duty_expires_at)::text, 'none') ||
        '|' || encode(expected_principal_marker_sha256, 'hex'),
        'UTF8'
    ));

    RETURN QUERY SELECT
        locked_duty_id,
        locked_duty_version,
        locked_duty_expires_at,
        computed_marker;
END
$function$;

ALTER FUNCTION iam_api.lock_finance_funding_authority_v2(
    uuid, uuid, uuid, uuid, uuid, uuid, text, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.lock_finance_funding_authority_v2(
    uuid, uuid, uuid, uuid, uuid, uuid, text, bytea
) FROM PUBLIC, demand_finance;
GRANT EXECUTE ON FUNCTION iam_api.lock_finance_funding_authority_v2(
    uuid, uuid, uuid, uuid, uuid, uuid, text, bytea
) TO demand_schema_owner;

DO $assertions$
DECLARE
    valid_context_count integer;
    valid_lock_count integer;
BEGIN
    SELECT count(*)
    INTO valid_context_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'iam'
      AND procedure.proname = 'finance_funding_authority_context_v1'
      AND procedure.pronargs = 0
      AND procedure.prorettype = 'boolean'::pg_catalog.regtype
      AND owner_role.rolname = 'schema_owner'
      AND NOT procedure.prosecdef
      AND procedure.provolatile = 's'
      AND procedure.proparallel = 'u'
      AND procedure.proconfig IS NOT DISTINCT FROM
            ARRAY['search_path=pg_catalog']::text[];

    SELECT count(*)
    INTO valid_lock_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'iam_api'
      AND procedure.proname = 'lock_finance_funding_authority_v2'
      AND pg_catalog.pg_get_function_identity_arguments(procedure.oid)
            = 'candidate_actor_user_id uuid, candidate_session_id uuid, '
              'candidate_organization_id uuid, candidate_demand_id uuid, '
              'candidate_funding_review_id uuid, candidate_assignment_id uuid, '
              'candidate_operation text, expected_principal_marker_sha256 bytea'
      AND owner_role.rolname = 'schema_owner'
      AND procedure.prosecdef
      AND procedure.provolatile = 'v'
      AND procedure.proparallel = 'u'
      AND pg_catalog.upper(procedure.prosrc) NOT LIKE '%EXECUTE%';

    IF valid_context_count <> 1
       OR valid_lock_count <> 1
       OR NOT pg_catalog.has_function_privilege(
            'schema_owner',
            'iam.finance_funding_authority_context_v1()',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_schema_owner',
            'iam.finance_funding_authority_context_v1()',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'iam.finance_funding_authority_context_v1()',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_schema_owner',
            'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'iam_api.lock_finance_funding_authority_v2(uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_schema_owner',
            'iam_api.lock_finance_funding_authority_v2(uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'finance funding review IAM37 authority assertion failed';
    END IF;
END
$assertions$;
