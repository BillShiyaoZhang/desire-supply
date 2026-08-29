-- Narrow IAM authority capabilities consumed by Demand PostgreSQL.

CREATE POLICY rls_demand_owner_family_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_reviewer_family_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_owner_session_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_reviewer_session_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_owner_user_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_reviewer_user_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_owner_organization_definer
ON iam.organizations
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
);

CREATE POLICY rls_demand_owner_membership_definer
ON iam.memberships
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_demand_owner_role_grant_definer
ON iam.membership_role_grants
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND role_code = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_owner_invitation_definer
ON iam.access_invitations
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND accepted_by_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND purpose = 'ORGANIZATION_MEMBERSHIP'
    AND target_scope = 'ORGANIZATION'
    AND target_role = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_owner_selector_definer
ON iam.policy_selectors
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND access_purpose = 'ORGANIZATION_MEMBERSHIP'
    AND scope_type = 'ORGANIZATION_ROLE'
    AND target_role = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_owner_bundle_definer
ON iam.policy_bundles
FOR ALL TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_owner_bundle_document_definer
ON iam.policy_bundle_documents
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_owner_document_definer
ON iam.policy_documents
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
);

CREATE POLICY rls_demand_owner_acceptance_definer
ON iam.policy_acceptances
FOR SELECT TO schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE FUNCTION iam_api.lock_demand_owner_authority_v1(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    candidate_organization_id uuid,
    candidate_operation text,
    candidate_demand_id uuid,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    session_family_id uuid,
    organization_id uuid,
    membership_id uuid,
    membership_role_grant_id uuid,
    membership_role_grant_version bigint,
    policy_selector_digest bytea,
    current_bundle_id uuid,
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
    locked_session_version bigint;
    locked_session_generation bigint;
    locked_user_version bigint;
    locked_organization_version bigint;
    locked_membership_id uuid;
    locked_membership_version bigint;
    locked_role_grant_id uuid;
    locked_role_grant_version bigint;
    locked_invitation_id uuid;
    locked_invitation_version bigint;
    locked_selector_digest bytea;
    locked_selector_version bigint;
    locked_bundle_id uuid;
    locked_bundle_version bigint;
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
       OR candidate_operation NOT IN (
            'CREATE',
            'CREATE_VERSION',
            'SUBMIT',
            'CANCEL_OWNER'
       )
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_OWNER'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM candidate_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM candidate_operation
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM candidate_demand_id::text THEN
        RETURN;
    END IF;

    SELECT family.id, family.aggregate_version
    INTO locked_family_id, locked_family_version
    FROM iam.session_families AS family
    JOIN iam.sessions AS candidate_session
      ON candidate_session.family_id = family.id
     AND candidate_session.user_id = family.user_id
    WHERE candidate_session.id = candidate_session_id
      AND candidate_session.user_id = candidate_actor_user_id
      AND family.user_id = candidate_actor_user_id
      AND family.status = 'ACTIVE'
    FOR UPDATE OF family;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT active_session.aggregate_version, active_session.generation
    INTO locked_session_version, locked_session_generation
    FROM iam.sessions AS active_session
    WHERE active_session.id = candidate_session_id
      AND active_session.user_id = candidate_actor_user_id
      AND active_session.family_id = locked_family_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = (
        SELECT family.current_generation
        FROM iam.session_families AS family
        WHERE family.id = locked_family_id
      )
      AND active_session.idle_expires_at > transaction_timestamp()
      AND active_session.absolute_expires_at > transaction_timestamp()
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
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT membership.id, membership.aggregate_version
    INTO locked_membership_id, locked_membership_version
    FROM iam.memberships AS membership
    WHERE membership.organization_id = candidate_organization_id
      AND membership.user_id = candidate_actor_user_id
      AND membership.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        role_grant.id,
        role_grant.aggregate_version,
        role_grant.source_invitation_id,
        role_grant.policy_selector_digest
    INTO
        locked_role_grant_id,
        locked_role_grant_version,
        locked_invitation_id,
        locked_selector_digest
    FROM iam.membership_role_grants AS role_grant
    WHERE role_grant.organization_id = candidate_organization_id
      AND role_grant.membership_id = locked_membership_id
      AND role_grant.user_id = candidate_actor_user_id
      AND role_grant.role_code = 'DEMAND_OWNER'
      AND role_grant.revoked_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT source_invitation.aggregate_version
    INTO locked_invitation_version
    FROM iam.access_invitations AS source_invitation
    WHERE source_invitation.id = locked_invitation_id
      AND source_invitation.organization_id = candidate_organization_id
      AND source_invitation.accepted_by_user_id = candidate_actor_user_id
      AND source_invitation.policy_selector_digest = locked_selector_digest
      AND source_invitation.purpose = 'ORGANIZATION_MEMBERSHIP'
      AND source_invitation.target_scope = 'ORGANIZATION'
      AND source_invitation.target_role = 'DEMAND_OWNER'
      AND source_invitation.status = 'ACCEPTED'
      AND source_invitation.terminal_at IS NOT NULL
      AND source_invitation.terminal_reason_code IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT selector.aggregate_version, selector.current_bundle_id
    INTO locked_selector_version, locked_bundle_id
    FROM iam.policy_selectors AS selector
    WHERE selector.selector_digest = locked_selector_digest
      AND selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
      AND selector.scope_type = 'ORGANIZATION_ROLE'
      AND selector.target_role = 'DEMAND_OWNER'
      AND selector.current_bundle_id IS NOT NULL
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT current_bundle.aggregate_version
    INTO locked_bundle_version
    FROM iam.policy_bundles AS current_bundle
    WHERE current_bundle.id = locked_bundle_id
      AND current_bundle.selector_digest = locked_selector_digest
      AND current_bundle.status = 'ACTIVE'
      AND current_bundle.effective_at <= transaction_timestamp()
      AND (
        current_bundle.effective_until IS NULL
        OR current_bundle.effective_until > transaction_timestamp()
      )
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM membership.document_id
    FROM iam.policy_bundle_documents AS membership
    JOIN iam.policy_documents AS document
      ON document.id = membership.document_id
    WHERE membership.bundle_id = locked_bundle_id
      AND membership.required
    ORDER BY membership.position, membership.document_id
    FOR KEY SHARE OF membership, document;

    PERFORM acceptance.id
    FROM iam.policy_bundle_documents AS membership
    JOIN iam.policy_documents AS document
      ON document.id = membership.document_id
    JOIN iam.policy_acceptances AS acceptance
      ON acceptance.user_id = candidate_actor_user_id
     AND acceptance.document_id = document.id
     AND acceptance.content_sha256 = document.content_sha256
    WHERE membership.bundle_id = locked_bundle_id
      AND membership.required
    ORDER BY membership.position, acceptance.id
    FOR KEY SHARE OF acceptance;

    IF EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        JOIN iam.policy_documents AS document
          ON document.id = membership.document_id
        WHERE membership.bundle_id = locked_bundle_id
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
                WHERE acceptance.user_id = candidate_actor_user_id
                  AND acceptance.document_id = document.id
                  AND acceptance.content_sha256 = document.content_sha256
            )
          )
    ) THEN
        RETURN;
    END IF;

    computed_marker := pg_catalog.sha256(
        pg_catalog.convert_to(
            'iam-demand-owner-authority-v1|' ||
            candidate_operation || '|' ||
            candidate_demand_id::text || '|' ||
            locked_family_id::text || '|' ||
            locked_family_version::text || '|' ||
            candidate_session_id::text || '|' ||
            locked_session_version::text || '|' ||
            locked_session_generation::text || '|' ||
            candidate_actor_user_id::text || '|' ||
            locked_user_version::text || '|' ||
            candidate_organization_id::text || '|' ||
            locked_organization_version::text || '|' ||
            locked_membership_id::text || '|' ||
            locked_membership_version::text || '|' ||
            locked_role_grant_id::text || '|' ||
            locked_role_grant_version::text || '|' ||
            locked_invitation_id::text || '|' ||
            locked_invitation_version::text || '|' ||
            pg_catalog.encode(locked_selector_digest, 'hex') || '|' ||
            locked_selector_version::text || '|' ||
            locked_bundle_id::text || '|' ||
            locked_bundle_version::text,
            'UTF8'
        )
    );

    IF computed_marker <> expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    RETURN QUERY SELECT
        candidate_actor_user_id,
        candidate_session_id,
        locked_family_id,
        candidate_organization_id,
        locked_membership_id,
        locked_role_grant_id,
        locked_role_grant_version,
        locked_selector_digest,
        locked_bundle_id,
        computed_marker;
END
$function$;

CREATE FUNCTION iam_api.lock_demand_reviewer_session_v1(
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
    locked_session_version bigint;
    locked_session_generation bigint;
    locked_user_version bigint;
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
       OR candidate_assignment_id IS NULL
       OR candidate_assignment_id = zero_uuid
       OR candidate_operation NOT IN (
            'REQUEST_CHANGES',
            'VERIFY',
            'REQUEST_MATCHING',
            'CANCEL_REVIEW'
       )
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
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

    SELECT family.id, family.aggregate_version
    INTO locked_family_id, locked_family_version
    FROM iam.session_families AS family
    JOIN iam.sessions AS candidate_session
      ON candidate_session.family_id = family.id
     AND candidate_session.user_id = family.user_id
    WHERE candidate_session.id = candidate_session_id
      AND candidate_session.user_id = candidate_actor_user_id
      AND family.user_id = candidate_actor_user_id
      AND family.status = 'ACTIVE'
    FOR UPDATE OF family;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT active_session.aggregate_version, active_session.generation
    INTO locked_session_version, locked_session_generation
    FROM iam.sessions AS active_session
    WHERE active_session.id = candidate_session_id
      AND active_session.user_id = candidate_actor_user_id
      AND active_session.family_id = locked_family_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = (
        SELECT family.current_generation
        FROM iam.session_families AS family
        WHERE family.id = locked_family_id
      )
      AND active_session.idle_expires_at > transaction_timestamp()
      AND active_session.absolute_expires_at > transaction_timestamp()
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

    computed_marker := pg_catalog.sha256(
        pg_catalog.convert_to(
            'iam-demand-reviewer-session-v1|' ||
            candidate_operation || '|' ||
            candidate_organization_id::text || '|' ||
            candidate_demand_id::text || '|' ||
            candidate_assignment_id::text || '|' ||
            locked_family_id::text || '|' ||
            locked_family_version::text || '|' ||
            candidate_session_id::text || '|' ||
            locked_session_version::text || '|' ||
            locked_session_generation::text || '|' ||
            candidate_actor_user_id::text || '|' ||
            locked_user_version::text,
            'UTF8'
        )
    );

    IF computed_marker <> expected_authority_marker_sha256 THEN
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
        computed_marker;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.lock_demand_owner_authority_v1(
    uuid,
    uuid,
    uuid,
    text,
    uuid,
    bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.lock_demand_reviewer_session_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    bytea
) FROM PUBLIC;
GRANT USAGE ON SCHEMA iam_api TO
    demand_self,
    demand_review,
    demand_migration_runner;
GRANT USAGE ON SCHEMA infra TO demand_migration_runner;
GRANT SELECT ON TABLE infra.iam_schema_compatibility TO demand_migration_runner;
GRANT EXECUTE ON FUNCTION iam_api.lock_demand_owner_authority_v1(
    uuid,
    uuid,
    uuid,
    text,
    uuid,
    bytea
) TO demand_self;
GRANT EXECUTE ON FUNCTION iam_api.lock_demand_reviewer_session_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    bytea
) TO demand_review;

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'iam_api'
      AND procedure.proname IN (
        'lock_demand_owner_authority_v1',
        'lock_demand_reviewer_session_v1'
      )
      AND (
        NOT procedure.prosecdef
        OR procedure.provolatile <> 'v'
        OR procedure.proparallel <> 'u'
        OR procedure.proconfig
            IS DISTINCT FROM ARRAY['search_path=pg_catalog, iam, iam_api']::text[]
        OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand IAM capability definition assertion failed';
    END IF;

    IF NOT pg_catalog.has_function_privilege(
        'demand_self',
        'iam_api.lock_demand_owner_authority_v1(uuid,uuid,uuid,text,uuid,bytea)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_review',
        'iam_api.lock_demand_owner_authority_v1(uuid,uuid,uuid,text,uuid,bytea)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'demand_review',
        'iam_api.lock_demand_reviewer_session_v1(uuid,uuid,uuid,uuid,uuid,text,bytea)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_self',
        'iam_api.lock_demand_reviewer_session_v1(uuid,uuid,uuid,uuid,uuid,text,bytea)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand IAM capability grant assertion failed';
    END IF;

    IF NOT pg_catalog.has_schema_privilege(
        'demand_migration_runner',
        'infra',
        'USAGE'
    ) OR NOT pg_catalog.has_schema_privilege(
        'demand_migration_runner',
        'iam_api',
        'USAGE'
    ) OR NOT pg_catalog.has_table_privilege(
        'demand_migration_runner',
        'infra.iam_schema_compatibility',
        'SELECT'
    ) OR pg_catalog.has_function_privilege(
        'demand_migration_runner',
        'iam_api.lock_demand_owner_authority_v1(uuid,uuid,uuid,text,uuid,bytea)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_migration_runner',
        'iam_api.lock_demand_reviewer_session_v1(uuid,uuid,uuid,uuid,uuid,text,bytea)',
        'EXECUTE'
    ) OR pg_catalog.has_table_privilege(
        'demand_migration_runner',
        'iam.users',
        'SELECT'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand migration compatibility grant assertion failed';
    END IF;
END
$assert$;
