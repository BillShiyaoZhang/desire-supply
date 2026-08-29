-- Demand review duty authority v2 and pre-assignment queue/claim capability.
-- Existing v1 bytes stay immutable; its online EXECUTE is revoked below.

CREATE POLICY rls_demand_review_v2_organization_definer
ON iam.organizations
FOR ALL TO schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
);

CREATE POLICY rls_demand_review_v2_membership_definer
ON iam.memberships
FOR ALL TO schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_review_v2_duty_definer
ON iam.platform_duty_grants
FOR ALL TO schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND duty_code = 'OPERATIONS_REVIEWER'
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND duty_code = 'OPERATIONS_REVIEWER'
);

CREATE FUNCTION iam_api.authorize_demand_review_queue_v1(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF candidate_actor_user_id IS NULL
       OR candidate_actor_user_id = zero_uuid
       OR candidate_session_id IS NULL
       OR candidate_session_id = zero_uuid
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '') NOT IN (
            'LIST_REVIEW_QUEUE',
            'RESOLVE_REVIEW_QUEUE_TARGET'
       )
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NOT iam_api.verify_editor_principal_marker_v1(
            candidate_actor_user_id,
            candidate_session_id,
            expected_principal_marker_sha256
       ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT duty.id, duty.aggregate_version, duty.expires_at
    FROM iam.platform_duty_grants AS duty
    WHERE duty.user_id = candidate_actor_user_id
      AND duty.duty_code = 'OPERATIONS_REVIEWER'
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (
          duty.expires_at IS NULL
          OR transaction_timestamp() < duty.expires_at
      );
END
$function$;

CREATE FUNCTION iam_api.lock_demand_review_claim_authority_v1(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    candidate_organization_id uuid,
    candidate_demand_id uuid,
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
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM candidate_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM candidate_demand_id::text
       OR NOT iam_api.verify_editor_principal_marker_v1(
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
    IF NOT FOUND THEN
        RETURN;
    END IF;

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
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT actor.aggregate_version
    INTO locked_user_version
    FROM iam.users AS actor
    WHERE actor.id = candidate_actor_user_id
      AND actor.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT organization.aggregate_version
    INTO locked_organization_version
    FROM iam.organizations AS organization
    WHERE organization.id = candidate_organization_id
      AND organization.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND OR EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.organization_id = candidate_organization_id
          AND membership.user_id = candidate_actor_user_id
          AND membership.status = 'ACTIVE'
        FOR UPDATE
    ) THEN
        RETURN;
    END IF;

    SELECT duty.id, duty.aggregate_version, duty.expires_at
    INTO locked_duty_id, locked_duty_version, locked_duty_expires_at
    FROM iam.platform_duty_grants AS duty
    WHERE duty.user_id = candidate_actor_user_id
      AND duty.duty_code = 'OPERATIONS_REVIEWER'
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (
          duty.expires_at IS NULL
          OR transaction_timestamp() < duty.expires_at
      )
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    computed_marker := sha256(convert_to(
        'iam-demand-review-claim-v1|' ||
        candidate_actor_user_id::text || '|' ||
        candidate_session_id::text || '|' ||
        candidate_organization_id::text || '|' ||
        candidate_demand_id::text || '|' ||
        locked_family_id::text || '|' ||
        locked_family_version::text || '|' ||
        locked_family_generation::text || '|' ||
        locked_session_version::text || '|' ||
        locked_session_generation::text || '|' ||
        locked_user_version::text || '|' ||
        locked_organization_version::text || '|' ||
        locked_duty_id::text || '|' ||
        locked_duty_version::text || '|' ||
        COALESCE(extract(epoch FROM locked_duty_expires_at)::text, 'none') || '|' ||
        encode(expected_principal_marker_sha256, 'hex'),
        'UTF8'
    ));

    RETURN QUERY SELECT
        locked_duty_id,
        locked_duty_version,
        locked_duty_expires_at,
        computed_marker;
END
$function$;

CREATE FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
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
       OR exact_operation NOT IN (
            'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
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

CREATE FUNCTION iam_api.lock_demand_reviewer_authority_v2(
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
       OR candidate_operation NOT IN (
            'REQUEST_CHANGES', 'VERIFY', 'REQUEST_MATCHING', 'CANCEL_REVIEW'
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
    IF computed_marker <> expected_authority_marker_sha256 THEN RETURN; END IF;

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

ALTER FUNCTION iam_api.authorize_demand_review_queue_v1(uuid, uuid, bytea)
OWNER TO schema_owner;
ALTER FUNCTION iam_api.lock_demand_review_claim_authority_v1(
    uuid, uuid, uuid, uuid, bytea
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
    uuid, uuid, uuid, text, uuid, uuid
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    uuid, uuid, uuid, uuid, uuid, text, bytea
) OWNER TO schema_owner;

REVOKE ALL ON FUNCTION iam_api.lock_demand_reviewer_session_v1(
    uuid, uuid, uuid, uuid, uuid, text, bytea
) FROM demand_review;
REVOKE ALL ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid
) FROM demand_review;
REVOKE ALL ON FUNCTION iam_api.authorize_demand_review_queue_v1(
    uuid, uuid, bytea
) FROM PUBLIC, demand_review;
REVOKE ALL ON FUNCTION iam_api.lock_demand_review_claim_authority_v1(
    uuid, uuid, uuid, uuid, bytea
) FROM PUBLIC, demand_review;
REVOKE ALL ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
    uuid, uuid, uuid, text, uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    uuid, uuid, uuid, uuid, uuid, text, bytea
) FROM PUBLIC;

GRANT USAGE ON SCHEMA iam_api TO demand_review, demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.authorize_demand_review_queue_v1(
    uuid, uuid, bytea
) TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.lock_demand_review_claim_authority_v1(
    uuid, uuid, uuid, uuid, bytea
) TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_demand_reviewer_authority_marker_v2(
    uuid, uuid, uuid, text, uuid, uuid
) TO demand_review;
GRANT EXECUTE ON FUNCTION iam_api.lock_demand_reviewer_authority_v2(
    uuid, uuid, uuid, uuid, uuid, text, bytea
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
          'authorize_demand_review_queue_v1',
          'lock_demand_review_claim_authority_v1',
          'resolve_demand_reviewer_authority_marker_v2',
          'lock_demand_reviewer_authority_v2'
      )
      AND (
          owner_role.rolname <> 'schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.proparallel <> 'u'
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.lock_demand_reviewer_session_v1(uuid,uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.resolve_demand_reviewer_authority_marker_v1(uuid,uuid,uuid,text,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.lock_demand_reviewer_authority_v2(uuid,uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_schema_owner',
            'iam_api.authorize_demand_review_queue_v1(uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_review',
            'iam_api.authorize_demand_review_queue_v1(uuid,uuid,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand review duty authority v2 assertion failed';
    END IF;
END
$assert$;
