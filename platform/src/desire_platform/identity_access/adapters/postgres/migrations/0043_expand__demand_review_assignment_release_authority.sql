-- Add an exact reviewer authority action for returning an active Demand
-- review assignment to the shared queue.  The v2 ABI remains stable; only
-- its closed operation set grows, and every authority marker remains bound
-- to the exact operation text.

CREATE OR REPLACE FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
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
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_assignment_id IS NULL OR exact_assignment_id = zero_uuid
       OR exact_operation IS NULL
       OR exact_operation NOT IN (
            'REQUEST_CHANGES', 'VERIFY', 'RELEASE_REVIEW_ASSIGNMENT',
            'REQUEST_MATCHING', 'CANCEL_REVIEW'
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
    SELECT sha256(convert_to(
        'iam-demand-reviewer-duty-v2|' || exact_operation || '|' ||
        exact_organization_id::text || '|' || exact_demand_id::text || '|' ||
        exact_assignment_id::text || '|' || family.id::text || '|' ||
        family.aggregate_version::text || '|' ||
        family.current_generation::text || '|' || exact_session_id::text || '|' ||
        active_session.aggregate_version::text || '|' ||
        active_session.generation::text || '|' || exact_actor_user_id::text || '|' ||
        actor.aggregate_version::text || '|' || organization.aggregate_version::text || '|' ||
        reviewer_duty.id::text || '|' || reviewer_duty.aggregate_version::text || '|' ||
        COALESCE(extract(epoch FROM reviewer_duty.expires_at)::text, 'none'),
        'UTF8'
    ))
    FROM iam.session_families AS family
    JOIN iam.sessions AS active_session
      ON active_session.family_id = family.id
     AND active_session.user_id = family.user_id
    JOIN iam.users AS actor ON actor.id = active_session.user_id
    JOIN iam.organizations AS organization
      ON organization.id = exact_organization_id
    JOIN iam.platform_duty_grants AS reviewer_duty
      ON reviewer_duty.user_id = actor.id
     AND reviewer_duty.duty_code = 'OPERATIONS_REVIEWER'
    WHERE family.user_id = exact_actor_user_id
      AND family.status = 'ACTIVE' AND family.revoked_at IS NULL
      AND active_session.id = exact_session_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
      AND actor.status = 'ACTIVE'
      AND organization.status = 'ACTIVE'
      AND reviewer_duty.granted_at <= transaction_timestamp()
      AND reviewer_duty.revoked_at IS NULL
      AND (
          reviewer_duty.expires_at IS NULL
          OR transaction_timestamp() < reviewer_duty.expires_at
      )
      AND NOT EXISTS (
          SELECT 1 FROM iam.memberships AS membership
          WHERE membership.organization_id = exact_organization_id
            AND membership.user_id = exact_actor_user_id
            AND membership.status = 'ACTIVE'
      );
END
$function$;

CREATE OR REPLACE FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    candidate_organization_id uuid,
    candidate_demand_id uuid,
    candidate_assignment_id uuid,
    candidate_operation text,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    session_family_id uuid,
    session_family_version bigint,
    session_version bigint,
    session_generation bigint,
    user_version bigint,
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
    IF candidate_actor_user_id IS NULL OR candidate_actor_user_id = zero_uuid
       OR candidate_session_id IS NULL OR candidate_session_id = zero_uuid
       OR candidate_organization_id IS NULL OR candidate_organization_id = zero_uuid
       OR candidate_demand_id IS NULL OR candidate_demand_id = zero_uuid
       OR candidate_assignment_id IS NULL OR candidate_assignment_id = zero_uuid
       OR candidate_operation IS NULL
       OR candidate_operation NOT IN (
            'REQUEST_CHANGES', 'VERIFY', 'RELEASE_REVIEW_ASSIGNMENT',
            'REQUEST_MATCHING', 'CANCEL_REVIEW'
       )
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM candidate_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM candidate_operation
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM candidate_demand_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '')
            IS DISTINCT FROM candidate_assignment_id::text THEN
        RETURN;
    END IF;

    SELECT family.id, family.aggregate_version, family.current_generation
    INTO locked_family_id, locked_family_version, locked_family_generation
    FROM iam.session_families AS family
    WHERE family.user_id = candidate_actor_user_id
      AND family.status = 'ACTIVE' AND family.revoked_at IS NULL
      AND EXISTS (
          SELECT 1 FROM iam.sessions AS candidate_session
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
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT actor.aggregate_version INTO locked_user_version
    FROM iam.users AS actor
    WHERE actor.id = candidate_actor_user_id AND actor.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT organization.aggregate_version INTO locked_organization_version
    FROM iam.organizations AS organization
    WHERE organization.id = candidate_organization_id
      AND organization.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND OR EXISTS (
        SELECT 1 FROM iam.memberships AS membership
        WHERE membership.organization_id = candidate_organization_id
          AND membership.user_id = candidate_actor_user_id
          AND membership.status = 'ACTIVE'
        FOR UPDATE
    ) THEN RETURN; END IF;

    SELECT duty.id, duty.aggregate_version, duty.expires_at
    INTO locked_duty_id, locked_duty_version, locked_duty_expires_at
    FROM iam.platform_duty_grants AS duty
    WHERE duty.user_id = candidate_actor_user_id
      AND duty.duty_code = 'OPERATIONS_REVIEWER'
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (duty.expires_at IS NULL OR transaction_timestamp() < duty.expires_at)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    computed_marker := sha256(convert_to(
        'iam-demand-reviewer-duty-v2|' || candidate_operation || '|' ||
        candidate_organization_id::text || '|' || candidate_demand_id::text || '|' ||
        candidate_assignment_id::text || '|' || locked_family_id::text || '|' ||
        locked_family_version::text || '|' || locked_family_generation::text || '|' ||
        candidate_session_id::text || '|' || locked_session_version::text || '|' ||
        locked_session_generation::text || '|' || candidate_actor_user_id::text || '|' ||
        locked_user_version::text || '|' || locked_organization_version::text || '|' ||
        locked_duty_id::text || '|' || locked_duty_version::text || '|' ||
        COALESCE(extract(epoch FROM locked_duty_expires_at)::text, 'none'),
        'UTF8'
    ));
    IF computed_marker IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    RETURN QUERY SELECT
        candidate_actor_user_id,
        candidate_session_id,
        locked_family_id,
        locked_family_version,
        locked_session_version,
        locked_session_generation,
        locked_user_version,
        locked_duty_id,
        locked_duty_version,
        locked_duty_expires_at,
        computed_marker;
END
$function$;

ALTER FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
    uuid, uuid, uuid, text, uuid, uuid
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    uuid, uuid, uuid, uuid, uuid, text, bytea
) OWNER TO schema_owner;

REVOKE ALL ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
    uuid, uuid, uuid, text, uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    uuid, uuid, uuid, uuid, uuid, text, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
    uuid, uuid, uuid, text, uuid, uuid
) TO demand_review;
GRANT EXECUTE ON FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    uuid, uuid, uuid, uuid, uuid, text, bytea
) TO demand_review;

DO $assert$
DECLARE
    resolver_definition text;
    lock_definition text;
    invalid_metadata_count integer;
    unexpected_acl_count integer;
    schema_owner_oid oid;
    demand_review_oid oid;
BEGIN
    SELECT role.oid INTO STRICT schema_owner_oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'schema_owner';
    SELECT role.oid INTO STRICT demand_review_oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'demand_review';

    SELECT pg_get_functiondef(
        'iam_api.resolve_demand_reviewer_authority_marker_v2('
        'uuid,uuid,uuid,text,uuid,uuid)'::regprocedure
    ) INTO STRICT resolver_definition;
    SELECT pg_get_functiondef(
        'iam_api.lock_demand_reviewer_authority_v2('
        'uuid,uuid,uuid,uuid,uuid,text,bytea)'::regprocedure
    ) INTO STRICT lock_definition;

    SELECT count(*) INTO STRICT invalid_metadata_count
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid IN (
            'iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)'::regprocedure,
            'iam_api.lock_demand_reviewer_authority_v2(uuid,uuid,uuid,uuid,uuid,text,bytea)'::regprocedure
       )
      AND (
            procedure.proowner <> schema_owner_oid
            OR NOT procedure.prosecdef
            OR procedure.proparallel <> 'u'
            OR (
                procedure.oid =
                    'iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)'::regprocedure
                AND (
                    procedure.provolatile <> 's'
                    OR procedure.proconfig IS NULL
                    OR NOT (
                        'search_path=pg_catalog, iam'
                        = ANY(procedure.proconfig)
                    )
                )
            )
            OR (
                procedure.oid =
                    'iam_api.lock_demand_reviewer_authority_v2(uuid,uuid,uuid,uuid,uuid,text,bytea)'::regprocedure
                AND (
                    procedure.provolatile <> 'v'
                    OR procedure.proconfig IS NULL
                    OR NOT (
                        'search_path=pg_catalog, iam, iam_api'
                        = ANY(procedure.proconfig)
                    )
                )
            )
       );

    SELECT count(*) INTO STRICT unexpected_acl_count
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            procedure.proacl,
            pg_catalog.acldefault('f', procedure.proowner)
        )
    ) AS privilege
    WHERE procedure.oid IN (
            'iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)'::regprocedure,
            'iam_api.lock_demand_reviewer_authority_v2(uuid,uuid,uuid,uuid,uuid,text,bytea)'::regprocedure
       )
      AND privilege.privilege_type = 'EXECUTE'
      AND (
            privilege.grantee NOT IN (schema_owner_oid, demand_review_oid)
            OR (
                privilege.grantee = demand_review_oid
                AND privilege.is_grantable
            )
       );

    IF resolver_definition NOT LIKE '%RELEASE_REVIEW_ASSIGNMENT%'
       OR lock_definition NOT LIKE '%RELEASE_REVIEW_ASSIGNMENT%'
       OR resolver_definition NOT LIKE '%iam-demand-reviewer-duty-v2%'
       OR lock_definition NOT LIKE '%iam-demand-reviewer-duty-v2%'
       OR invalid_metadata_count <> 0
       OR unexpected_acl_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.lock_demand_reviewer_authority_v2(uuid,uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'IAM43_DEMAND_RELEASE_AUTHORITY_DRIFTED';
    END IF;
END
$assert$;
