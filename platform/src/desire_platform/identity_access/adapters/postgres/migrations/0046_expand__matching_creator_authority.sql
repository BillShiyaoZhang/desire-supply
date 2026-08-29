-- IAM 0046: authenticated Matching creator invitation authority.
--
-- The Matching creator runtime may ask IAM only whether the exact current
-- actor/session still has an invitation-backed, policy-eligible CREATOR
-- principal.  The returned authority marker is the same generic
-- EditorPrincipal marker used by the authenticated HTTP boundary.  A separate
-- short-lived IAM46 evidence digest binds the closed Matching operation tuple
-- and every IAM fact used for the decision.  No Matching target is authorized
-- here: invitation ownership remains a Matching-domain invariant.

DO $iam46_role_guard$
DECLARE
    role_facts record;
    role_oid oid;
BEGIN
    SELECT oid, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
           rolreplication, rolbypassrls
    INTO role_facts
    FROM pg_catalog.pg_roles
    WHERE rolname = 'matching_creator';
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
            CONSTRAINT = 'ck_iam46_matching_creator_role',
            MESSAGE = 'matching creator role is not provisioned';
    END IF;
END
$iam46_role_guard$;

-- Preserve all six existing contexts and add one closed creator branch.  The
-- helper and marker remain inaccessible to matching_creator; only the exact
-- IAM46 resolver may invoke them as schema_owner.
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
    WHEN session_user = 'matching_creator' THEN
        current_user = 'schema_owner'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'MATCHING_CREATOR'
        AND NULLIF(current_setting('app.operation', true), '') = ANY (ARRAY[
            'LIST_MATCHING_INVITATIONS',
            'READ_MATCHING_INVITATION',
            'ACCEPT_MATCHING_INVITATION',
            'DECLINE_MATCHING_INVITATION',
            'WITHDRAW_MATCHING_INVITATION'
        ])
        AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
        AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
        AND CASE NULLIF(current_setting('app.operation', true), '')
            WHEN 'LIST_MATCHING_INVITATIONS' THEN
                NULLIF(current_setting('app.invitation_id', true), '') IS NULL
                AND NULLIF(
                    current_setting('app.command_id', true), ''
                ) IS NULL
            WHEN 'READ_MATCHING_INVITATION' THEN
                NULLIF(
                    current_setting('app.invitation_id', true), ''
                ) IS NOT NULL
                AND NULLIF(
                    current_setting('app.command_id', true), ''
                ) IS NULL
            ELSE
                NULLIF(
                    current_setting('app.invitation_id', true), ''
                ) IS NOT NULL
                AND NULLIF(
                    current_setting('app.command_id', true), ''
                ) IS NOT NULL
        END
    ELSE false
END
$function$;

ALTER FUNCTION iam_api.editor_principal_context_valid_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.editor_principal_context_valid_v1()
FROM PUBLIC, matching_assignment, matching_review, matching_creator,
     matching_schema_owner;

-- The ordinary EditorPrincipal policies are permissive.  These restrictive
-- guards ensure that, for matching_creator only, schema_owner can see exactly
-- the actor/session and that actor's complete marker authority graph.
CREATE POLICY rls_matching_creator_user_guard_v1
ON iam.users
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_creator_family_guard_v1
ON iam.session_families
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_creator_session_guard_v1
ON iam.sessions
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND id::text = NULLIF(current_setting('app.session_id', true), '')
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_creator_organization_guard_v1
ON iam.organizations
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
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

CREATE POLICY rls_matching_creator_membership_guard_v1
ON iam.memberships
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_creator_user_role_guard_v1
ON iam.user_role_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_creator_membership_role_guard_v1
ON iam.membership_role_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

CREATE POLICY rls_matching_creator_duty_guard_v1
ON iam.platform_duty_grants
AS RESTRICTIVE
FOR SELECT TO schema_owner
USING (
    session_user <> 'matching_creator'
    OR (
        iam_api.editor_principal_context_valid_v1()
        AND user_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
    )
);

-- These six policies expose only the enrollment graph needed to prove that
-- the current CREATOR grant remains policy-eligible.  They do not expose IAM
-- relations to the login role itself.
CREATE POLICY rls_matching_creator_source_invitation_definer_v1
ON iam.access_invitations
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_creator'
    AND iam_api.editor_principal_context_valid_v1()
    AND accepted_by_user_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND purpose = 'CREATOR_ENROLLMENT'
    AND target_scope = 'USER'
    AND target_role = 'CREATOR'
    AND status = 'ACCEPTED'
);

CREATE POLICY rls_matching_creator_selector_definer_v1
ON iam.policy_selectors
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_creator'
    AND iam_api.editor_principal_context_valid_v1()
    AND access_purpose = 'CREATOR_ENROLLMENT'
    AND scope_type = 'USER_ROLE'
    AND target_role = 'CREATOR'
    AND EXISTS (
        SELECT 1
        FROM iam.user_role_grants AS creator_grant
        WHERE creator_grant.user_id::text = NULLIF(
                current_setting('app.actor_user_id', true), ''
              )
          AND creator_grant.role_code = 'CREATOR'
          AND creator_grant.revoked_at IS NULL
          AND creator_grant.policy_selector_digest
                = policy_selectors.selector_digest
    )
);

CREATE POLICY rls_matching_creator_bundle_definer_v1
ON iam.policy_bundles
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_creator'
    AND iam_api.editor_principal_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = policy_bundles.selector_digest
          AND selector.current_bundle_id = policy_bundles.id
          AND selector.access_purpose = 'CREATOR_ENROLLMENT'
          AND selector.scope_type = 'USER_ROLE'
          AND selector.target_role = 'CREATOR'
    )
);

CREATE POLICY rls_matching_creator_bundle_document_definer_v1
ON iam.policy_bundle_documents
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_creator'
    AND iam_api.editor_principal_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS current_bundle
        WHERE current_bundle.id = policy_bundle_documents.bundle_id
    )
);

CREATE POLICY rls_matching_creator_document_definer_v1
ON iam.policy_documents
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_creator'
    AND iam_api.editor_principal_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS bundle_document
        WHERE bundle_document.document_id = policy_documents.id
    )
);

CREATE POLICY rls_matching_creator_acceptance_definer_v1
ON iam.policy_acceptances
FOR SELECT TO schema_owner
USING (
    session_user = 'matching_creator'
    AND iam_api.editor_principal_context_valid_v1()
    AND user_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
);

CREATE FUNCTION iam_api.resolve_matching_creator_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation_code text,
    exact_invitation_id uuid,
    exact_command_id uuid
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    operation_code varchar,
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
       OR exact_operation_code IS NULL
       OR exact_operation_code NOT IN (
            'LIST_MATCHING_INVITATIONS',
            'READ_MATCHING_INVITATION',
            'ACCEPT_MATCHING_INVITATION',
            'DECLINE_MATCHING_INVITATION',
            'WITHDRAW_MATCHING_INVITATION'
       )
       OR NOT (
            (
                exact_operation_code = 'LIST_MATCHING_INVITATIONS'
                AND exact_invitation_id IS NULL
                AND exact_command_id IS NULL
            )
            OR (
                exact_operation_code = 'READ_MATCHING_INVITATION'
                AND exact_invitation_id IS NOT NULL
                AND exact_invitation_id <> zero_uuid
                AND exact_command_id IS NULL
            )
            OR (
                exact_operation_code IN (
                    'ACCEPT_MATCHING_INVITATION',
                    'DECLINE_MATCHING_INVITATION',
                    'WITHDRAW_MATCHING_INVITATION'
                )
                AND exact_invitation_id IS NOT NULL
                AND exact_invitation_id <> zero_uuid
                AND exact_command_id IS NOT NULL
                AND exact_command_id <> zero_uuid
            )
       )
       OR session_user IS DISTINCT FROM 'matching_creator'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_CREATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation_code
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR (
            exact_invitation_id IS NULL
            AND NULLIF(
                current_setting('app.invitation_id', true), ''
            ) IS NOT NULL
       )
       OR (
            exact_invitation_id IS NOT NULL
            AND NULLIF(
                current_setting('app.invitation_id', true), ''
            ) IS DISTINCT FROM exact_invitation_id::text
       )
       OR (
            exact_command_id IS NULL
            AND NULLIF(
                current_setting('app.command_id', true), ''
            ) IS NOT NULL
       )
       OR (
            exact_command_id IS NOT NULL
            AND NULLIF(
                current_setting('app.command_id', true), ''
            ) IS DISTINCT FROM exact_command_id::text
       )
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

    RETURN QUERY
    WITH eligible AS (
        SELECT
            actor.aggregate_version AS user_version,
            actor.updated_at AS user_updated_at,
            family.id AS family_id,
            family.aggregate_version AS family_version,
            family.current_generation AS family_generation,
            family.updated_at AS family_updated_at,
            active_session.aggregate_version AS session_version,
            active_session.generation AS session_generation,
            active_session.auth_time,
            active_session.last_activity_at,
            active_session.idle_expires_at,
            active_session.absolute_expires_at,
            active_session.updated_at AS session_updated_at,
            creator_grant.id AS creator_grant_id,
            creator_grant.aggregate_version AS creator_grant_version,
            creator_grant.granted_at AS creator_granted_at,
            creator_grant.source_invitation_id,
            creator_grant.policy_selector_digest,
            source_invitation.aggregate_version AS invitation_version,
            source_invitation.terminal_at AS invitation_terminal_at,
            source_invitation.updated_at AS invitation_updated_at,
            selector.aggregate_version AS selector_version,
            selector.current_bundle_id,
            selector.updated_at AS selector_updated_at,
            current_bundle.aggregate_version AS bundle_version,
            current_bundle.effective_at AS bundle_effective_at,
            current_bundle.effective_until AS bundle_effective_until,
            current_bundle.updated_at AS bundle_updated_at,
            LEAST(
                active_session.idle_expires_at,
                active_session.absolute_expires_at,
                COALESCE(
                    current_bundle.effective_until,
                    'infinity'::timestamptz
                ),
                server_now + interval '5 minutes'
            ) AS bounded_valid_until
        FROM iam.users AS actor
        JOIN iam.session_families AS family
          ON family.user_id = actor.id
        JOIN iam.sessions AS active_session
          ON active_session.family_id = family.id
         AND active_session.user_id = family.user_id
        JOIN iam.user_role_grants AS creator_grant
          ON creator_grant.user_id = actor.id
         AND creator_grant.role_code = 'CREATOR'
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
         AND current_bundle.effective_at <= server_now
         AND (
                current_bundle.effective_until IS NULL
                OR server_now < current_bundle.effective_until
         )
        WHERE actor.id = exact_actor_user_id
          AND actor.status = 'ACTIVE'
          AND family.status = 'ACTIVE'
          AND family.revoked_at IS NULL
          AND active_session.id = exact_session_id
          AND active_session.status = 'ACTIVE'
          AND active_session.revoked_at IS NULL
          AND active_session.generation = family.current_generation
          AND active_session.auth_time <= server_now
          AND active_session.last_activity_at <= server_now
          AND active_session.last_activity_at < active_session.idle_expires_at
          AND server_now < active_session.idle_expires_at
          AND server_now < active_session.absolute_expires_at
          AND creator_grant.granted_at <= server_now
          AND creator_grant.revoked_at IS NULL
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
                        OR document.effective_at > server_now
                        OR document.legal_effect NOT IN (
                            'NOTICE_ACKNOWLEDGEMENT',
                            'CONTRACT_ACCEPTANCE'
                        )
                        OR NOT EXISTS (
                            SELECT 1
                            FROM iam.policy_acceptances AS acceptance
                            WHERE acceptance.user_id = actor.id
                              AND acceptance.bundle_id = current_bundle.id
                              AND acceptance.document_id = document.id
                              AND acceptance.content_sha256
                                    = document.content_sha256
                        )
                  )
          )
    ), bound AS (
        SELECT
            eligible.*,
            COALESCE(
                (
                    SELECT string_agg(
                        bundle_document.document_id::text || ':'
                        || bundle_document.position::text || ':'
                        || bundle_document.required::text || ':'
                        || document.status || ':'
                        || COALESCE(
                            extract(epoch FROM document.effective_at)::text,
                            'none'
                        ) || ':'
                        || document.legal_effect || ':'
                        || encode(document.content_sha256, 'hex') || ':'
                        || extract(epoch FROM document.updated_at)::text || ':'
                        || COALESCE(acceptance.id::text, 'none') || ':'
                        || COALESCE(
                            extract(epoch FROM acceptance.accepted_at)::text,
                            'none'
                        ) || ':'
                        || COALESCE(
                            acceptance.aggregate_version::text,
                            'none'
                        ),
                        ',' ORDER BY bundle_document.position,
                                     bundle_document.document_id
                    )
                    FROM iam.policy_bundle_documents AS bundle_document
                    JOIN iam.policy_documents AS document
                      ON document.id = bundle_document.document_id
                    LEFT JOIN iam.policy_acceptances AS acceptance
                      ON acceptance.user_id = exact_actor_user_id
                     AND acceptance.bundle_id = eligible.current_bundle_id
                     AND acceptance.document_id = document.id
                     AND acceptance.content_sha256 = document.content_sha256
                    WHERE bundle_document.bundle_id
                            = eligible.current_bundle_id
                ),
                ''
            ) AS policy_document_facts
        FROM eligible
    ), evidence AS (
        SELECT
            bound.*,
            sha256(convert_to(
                'desire.iam.matching-creator-authority-evidence.v1'
                || '|iam_head=46'
                || '|scope_kind=MATCHING_CREATOR'
                || '|operation_code=' || exact_operation_code
                || '|role_code=CREATOR'
                || '|actor_user_id=' || exact_actor_user_id::text
                || '|session_id=' || exact_session_id::text
                || '|invitation_id=' || COALESCE(
                    exact_invitation_id::text,
                    'none'
                )
                || '|command_id=' || COALESCE(
                    exact_command_id::text,
                    'none'
                )
                || '|user_version=' || bound.user_version::text
                || '|user_updated_epoch='
                || extract(epoch FROM bound.user_updated_at)::text
                || '|family_id=' || bound.family_id::text
                || '|family_version=' || bound.family_version::text
                || '|family_generation=' || bound.family_generation::text
                || '|family_updated_epoch='
                || extract(epoch FROM bound.family_updated_at)::text
                || '|session_version=' || bound.session_version::text
                || '|session_generation=' || bound.session_generation::text
                || '|auth_time_epoch='
                || extract(epoch FROM bound.auth_time)::text
                || '|last_activity_epoch='
                || extract(epoch FROM bound.last_activity_at)::text
                || '|idle_expires_epoch='
                || extract(epoch FROM bound.idle_expires_at)::text
                || '|absolute_expires_epoch='
                || extract(epoch FROM bound.absolute_expires_at)::text
                || '|session_updated_epoch='
                || extract(epoch FROM bound.session_updated_at)::text
                || '|creator_grant_id=' || bound.creator_grant_id::text
                || '|creator_grant_version='
                || bound.creator_grant_version::text
                || '|creator_granted_epoch='
                || extract(epoch FROM bound.creator_granted_at)::text
                || '|source_invitation_id='
                || bound.source_invitation_id::text
                || '|policy_selector_digest='
                || encode(bound.policy_selector_digest, 'hex')
                || '|enrollment_invitation_version='
                || bound.invitation_version::text
                || '|enrollment_invitation_terminal_epoch='
                || extract(epoch FROM bound.invitation_terminal_at)::text
                || '|enrollment_invitation_updated_epoch='
                || extract(epoch FROM bound.invitation_updated_at)::text
                || '|selector_version=' || bound.selector_version::text
                || '|selector_updated_epoch='
                || extract(epoch FROM bound.selector_updated_at)::text
                || '|current_bundle_id=' || bound.current_bundle_id::text
                || '|bundle_version=' || bound.bundle_version::text
                || '|bundle_effective_epoch='
                || extract(epoch FROM bound.bundle_effective_at)::text
                || '|bundle_effective_until_epoch=' || COALESCE(
                    extract(epoch FROM bound.bundle_effective_until)::text,
                    'none'
                )
                || '|bundle_updated_epoch='
                || extract(epoch FROM bound.bundle_updated_at)::text
                || '|policy_document_facts_sha256='
                || encode(
                    sha256(convert_to(bound.policy_document_facts, 'UTF8')),
                    'hex'
                )
                || '|principal_marker_sha256='
                || encode(principal_marker, 'hex')
                || '|valid_until_epoch='
                || extract(epoch FROM bound.bounded_valid_until)::text,
                'UTF8'
            )) AS exact_evidence_sha256
        FROM bound
        WHERE bound.bounded_valid_until > server_now
    )
    SELECT
        exact_actor_user_id,
        exact_session_id,
        exact_operation_code::varchar,
        'CREATOR'::varchar,
        principal_marker,
        evidence.exact_evidence_sha256,
        evidence.bounded_valid_until
    FROM evidence;
END
$function$;

ALTER FUNCTION iam_api.resolve_matching_creator_authority_marker_v1(
    uuid, uuid, text, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_matching_creator_authority_marker_v1(
    uuid, uuid, text, uuid, uuid
) FROM PUBLIC, matching_creator, matching_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_matching_creator_authority_marker_v1(
    uuid, uuid, text, uuid, uuid
) TO matching_creator, matching_schema_owner;

GRANT USAGE ON SCHEMA iam_api TO matching_creator, matching_schema_owner;
REVOKE CREATE ON SCHEMA iam_api FROM matching_creator, matching_schema_owner;

DO $iam46_readiness$
DECLARE
    creator_oid oid;
    matching_owner_oid oid;
    schema_owner_oid oid;
    resolver_oid oid;
    context_oid oid;
    invalid_function_count integer;
    unexpected_execute_acl_count integer;
    direct_relation_acl_count integer;
    marker_guard_policy_count integer;
    eligibility_policy_count integer;
    context_definition text;
BEGIN
    SELECT oid INTO STRICT creator_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'matching_creator';
    SELECT oid INTO STRICT matching_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'matching_schema_owner';
    SELECT oid INTO STRICT schema_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'schema_owner';
    SELECT 'iam_api.resolve_matching_creator_authority_marker_v1('
           'uuid,uuid,text,uuid,uuid)'::regprocedure::oid
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
                    OR procedure.pronargs <> 5
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
                schema_owner_oid, creator_oid, matching_owner_oid
            )
            OR (
                privilege.grantee IN (creator_oid, matching_owner_oid)
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
            privilege.grantee IN (creator_oid, matching_owner_oid)
            OR column_privilege.grantee IN (creator_oid, matching_owner_oid)
      );

    SELECT count(*) INTO STRICT marker_guard_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname IN (
        'rls_matching_creator_user_guard_v1',
        'rls_matching_creator_family_guard_v1',
        'rls_matching_creator_session_guard_v1',
        'rls_matching_creator_organization_guard_v1',
        'rls_matching_creator_membership_guard_v1',
        'rls_matching_creator_user_role_guard_v1',
        'rls_matching_creator_membership_role_guard_v1',
        'rls_matching_creator_duty_guard_v1'
    )
      AND NOT policy.polpermissive
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY[schema_owner_oid];

    SELECT count(*) INTO STRICT eligibility_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname IN (
        'rls_matching_creator_source_invitation_definer_v1',
        'rls_matching_creator_selector_definer_v1',
        'rls_matching_creator_bundle_definer_v1',
        'rls_matching_creator_bundle_document_definer_v1',
        'rls_matching_creator_document_definer_v1',
        'rls_matching_creator_acceptance_definer_v1'
    )
      AND policy.polpermissive
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY[schema_owner_oid];

    IF invalid_function_count <> 0
       OR unexpected_execute_acl_count <> 0
       OR direct_relation_acl_count <> 0
       OR marker_guard_policy_count <> 8
       OR eligibility_policy_count <> 6
       OR context_definition NOT LIKE '%matching_creator%'
       OR context_definition NOT LIKE '%MATCHING_CREATOR%'
       OR context_definition NOT LIKE '%LIST_MATCHING_INVITATIONS%'
       OR context_definition NOT LIKE '%WITHDRAW_MATCHING_INVITATION%'
       OR NOT pg_catalog.has_schema_privilege(
            'matching_creator', 'iam_api', 'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_creator', 'iam_api', 'CREATE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_creator', 'iam', 'USAGE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_creator', resolver_oid, 'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_schema_owner', resolver_oid, 'EXECUTE'
       )
       OR NOT pg_catalog.has_schema_privilege(
            'matching_schema_owner', 'iam_api', 'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_schema_owner', 'iam_api', 'CREATE'
       )
       OR pg_catalog.has_schema_privilege(
            'matching_schema_owner', 'iam', 'USAGE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_assignment', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_selector', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_review', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_worker', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_coordinator', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_app', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'iam_app', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_creator', context_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_creator',
            'iam_api.editor_principal_marker_v1(uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_iam46_matching_creator_readiness',
            MESSAGE = 'IAM46 matching creator authority drifted';
    END IF;
END
$iam46_readiness$;

-- Profile's derived matching-input capture runs as profile_schema_owner inside
-- a profile_matcher session.  This internal predicate closes the outer batch
-- context before any IAM row can become visible to the IAM definer.
CREATE FUNCTION iam_api.profile_match_derivation_context_valid_v1()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT
    session_user = 'profile_matcher'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.authorization_digest', true), '')
        ~ '^[0-9a-f]{64}$'
    AND NULLIF(
        current_setting('app.demand_match_context_sha256', true), ''
    ) ~ '^[0-9a-f]{64}$'
$function$;

ALTER FUNCTION iam_api.profile_match_derivation_context_valid_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.profile_match_derivation_context_valid_v1()
FROM PUBLIC, profile_matcher, profile_schema_owner;

-- Exact-candidate RLS for the Profile5 nested IAM call.  The candidate GUC is
-- installed only after the resolver has authenticated and bound the complete
-- outer derivation context.  No relation privilege is granted to either
-- Profile role.
CREATE POLICY rls_profile_match_derivation_user_definer_v1
ON iam.users
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
);

CREATE POLICY rls_profile_match_derivation_grant_definer_v1
ON iam.user_role_grants
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND user_id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
    AND role_code = 'CREATOR'
);

CREATE POLICY rls_profile_match_derivation_invitation_definer_v1
ON iam.access_invitations
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND accepted_by_user_id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
    AND purpose = 'CREATOR_ENROLLMENT'
    AND target_scope = 'USER'
    AND target_role = 'CREATOR'
);

CREATE POLICY rls_profile_match_derivation_selector_definer_v1
ON iam.policy_selectors
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND access_purpose = 'CREATOR_ENROLLMENT'
    AND scope_type = 'USER_ROLE'
    AND target_role = 'CREATOR'
    AND EXISTS (
        SELECT 1
        FROM iam.user_role_grants AS creator_grant
        WHERE creator_grant.user_id::text = NULLIF(
                current_setting(
                    'app.iam_profile_candidate_user_id', true
                ), ''
              )
          AND creator_grant.role_code = 'CREATOR'
          AND creator_grant.revoked_at IS NULL
          AND creator_grant.policy_selector_digest
                = policy_selectors.selector_digest
    )
);

CREATE POLICY rls_profile_match_derivation_bundle_definer_v1
ON iam.policy_bundles
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = policy_bundles.selector_digest
          AND selector.current_bundle_id = policy_bundles.id
          AND selector.access_purpose = 'CREATOR_ENROLLMENT'
          AND selector.scope_type = 'USER_ROLE'
          AND selector.target_role = 'CREATOR'
    )
);

CREATE POLICY rls_profile_match_derivation_bundle_document_definer_v1
ON iam.policy_bundle_documents
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS current_bundle
        WHERE current_bundle.id = policy_bundle_documents.bundle_id
    )
);

CREATE POLICY rls_profile_match_derivation_document_definer_v1
ON iam.policy_documents
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS bundle_document
        WHERE bundle_document.document_id = policy_documents.id
    )
);

CREATE POLICY rls_profile_match_derivation_acceptance_definer_v1
ON iam.policy_acceptances
FOR SELECT TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND user_id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
);

-- PostgreSQL applies UPDATE row-security policies while acquiring row marks,
-- including SELECT ... FOR KEY SHARE.  These policies expose exactly the same
-- closed candidate graph for locking only; the fixed resolver contains no
-- write statement and neither Profile role receives any IAM relation grant.
CREATE POLICY rls_profile_match_derivation_user_lock_v1
ON iam.users
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
);

CREATE POLICY rls_profile_match_derivation_grant_lock_v1
ON iam.user_role_grants
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND user_id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
    AND role_code = 'CREATOR'
);

CREATE POLICY rls_profile_match_derivation_invitation_lock_v1
ON iam.access_invitations
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND accepted_by_user_id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
    AND purpose = 'CREATOR_ENROLLMENT'
    AND target_scope = 'USER'
    AND target_role = 'CREATOR'
);

CREATE POLICY rls_profile_match_derivation_selector_lock_v1
ON iam.policy_selectors
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND access_purpose = 'CREATOR_ENROLLMENT'
    AND scope_type = 'USER_ROLE'
    AND target_role = 'CREATOR'
    AND EXISTS (
        SELECT 1
        FROM iam.user_role_grants AS creator_grant
        WHERE creator_grant.user_id::text = NULLIF(
                current_setting(
                    'app.iam_profile_candidate_user_id', true
                ), ''
              )
          AND creator_grant.role_code = 'CREATOR'
          AND creator_grant.revoked_at IS NULL
          AND creator_grant.policy_selector_digest
                = policy_selectors.selector_digest
    )
);

CREATE POLICY rls_profile_match_derivation_bundle_lock_v1
ON iam.policy_bundles
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = policy_bundles.selector_digest
          AND selector.current_bundle_id = policy_bundles.id
          AND selector.access_purpose = 'CREATOR_ENROLLMENT'
          AND selector.scope_type = 'USER_ROLE'
          AND selector.target_role = 'CREATOR'
    )
);

CREATE POLICY rls_profile_match_derivation_bundle_document_lock_v1
ON iam.policy_bundle_documents
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS current_bundle
        WHERE current_bundle.id = policy_bundle_documents.bundle_id
    )
);

CREATE POLICY rls_profile_match_derivation_document_lock_v1
ON iam.policy_documents
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS bundle_document
        WHERE bundle_document.document_id = policy_documents.id
    )
);

CREATE POLICY rls_profile_match_derivation_acceptance_lock_v1
ON iam.policy_acceptances
FOR UPDATE TO schema_owner
USING (
    session_user = 'profile_matcher'
    AND iam_api.profile_match_derivation_context_valid_v1()
    AND user_id::text = NULLIF(
        current_setting('app.iam_profile_candidate_user_id', true), ''
    )
);

CREATE FUNCTION iam_api.resolve_profile_match_creator_eligibility_v1(
    exact_candidate_user_id uuid,
    exact_match_run_id uuid,
    exact_workload_id uuid,
    exact_authorization_digest bytea,
    exact_demand_match_context_sha256 bytea
)
RETURNS TABLE (
    candidate_user_id uuid,
    eligible boolean,
    creator_user_version bigint,
    creator_grant_id uuid,
    creator_grant_version bigint,
    source_invitation_id uuid,
    source_invitation_version bigint,
    policy_selector_digest bytea,
    policy_selector_version bigint,
    policy_bundle_id uuid,
    policy_bundle_version bigint,
    required_policy_acceptance_set_sha256 bytea,
    eligibility_evidence_sha256 bytea,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api, infra
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    server_now timestamptz := transaction_timestamp();
    authority record;
    contract record;
    invalid_required_count bigint;
    expected_required_count bigint;
    locked_bundle_document_count bigint;
    locked_document_count bigint;
    expected_acceptance_count bigint;
    locked_acceptance_count bigint;
    authority_rows_locked boolean := true;
    required_acceptance_facts text;
    acceptance_set_digest bytea;
    evidence_digest bytea;
    bounded_valid_until timestamptz;
BEGIN
    IF exact_candidate_user_id IS NULL
       OR exact_candidate_user_id = zero_uuid
       OR exact_match_run_id IS NULL
       OR exact_match_run_id = zero_uuid
       OR exact_workload_id IS NULL
       OR exact_workload_id = zero_uuid
       OR exact_authorization_digest IS NULL
       OR octet_length(exact_authorization_digest) <> 32
       OR exact_demand_match_context_sha256 IS NULL
       OR octet_length(exact_demand_match_context_sha256) <> 32
       OR session_user IS DISTINCT FROM 'profile_matcher'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam_api.profile_match_derivation_context_valid_v1()
       OR NULLIF(current_setting('app.match_run_id', true), '')
            IS DISTINCT FROM exact_match_run_id::text
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM exact_workload_id::text
       OR NULLIF(current_setting('app.authorization_digest', true), '')
            IS DISTINCT FROM encode(exact_authorization_digest, 'hex')
       OR NULLIF(current_setting(
            'app.demand_match_context_sha256', true
       ), '') IS DISTINCT FROM encode(
            exact_demand_match_context_sha256,
            'hex'
       ) THEN
        RETURN;
    END IF;

    PERFORM set_config(
        'app.iam_profile_candidate_user_id',
        exact_candidate_user_id::text,
        true
    );

    -- Resolve the exact enrollment graph from one REPEATABLE READ snapshot,
    -- then lock its rows one relation at a time in canonical parent-to-child
    -- order.  PostgreSQL row-security rechecks a row-marked multi-relation
    -- join after each lock; separate exact-key locks avoid making a valid
    -- graph disappear during that recheck while still preventing authority
    -- mutation until the outer Profile transaction commits.
    SELECT
        actor.aggregate_version AS user_version,
        actor.status AS user_status,
        actor.updated_at AS user_updated_at,
        creator_grant.id AS grant_id,
        creator_grant.aggregate_version AS grant_version,
        creator_grant.granted_at,
        creator_grant.revoked_at,
        creator_grant.source_invitation_id,
        creator_grant.policy_selector_digest,
        source_invitation.aggregate_version AS invitation_version,
        source_invitation.status AS invitation_status,
        source_invitation.accepted_by_user_id,
        source_invitation.issued_policy_bundle_id,
        source_invitation.terminal_at AS invitation_terminal_at,
        source_invitation.updated_at AS invitation_updated_at,
        selector.aggregate_version AS selector_version,
        selector.current_bundle_id,
        selector.updated_at AS selector_updated_at,
        current_bundle.aggregate_version AS bundle_version,
        current_bundle.status AS bundle_status,
        current_bundle.effective_at AS bundle_effective_at,
        current_bundle.effective_until AS bundle_effective_until,
        current_bundle.release_manifest_sha256,
        current_bundle.updated_at AS bundle_updated_at
    INTO authority
    FROM iam.users AS actor
    JOIN iam.user_role_grants AS creator_grant
      ON creator_grant.user_id = actor.id
     AND creator_grant.role_code = 'CREATOR'
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
    WHERE actor.id = exact_candidate_user_id
      AND actor.status = 'ACTIVE'
      AND creator_grant.granted_at <= server_now
      AND creator_grant.revoked_at IS NULL
      AND current_bundle.status = 'ACTIVE'
      AND current_bundle.effective_at <= server_now
      AND (
            current_bundle.effective_until IS NULL
            OR server_now < current_bundle.effective_until
      )
    ;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            exact_candidate_user_id,
            false,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bytea,
            NULL::timestamptz;
        RETURN;
    END IF;

    PERFORM 1
    FROM iam.users AS actor
    WHERE actor.id = exact_candidate_user_id
    FOR KEY SHARE OF actor;
    IF NOT FOUND THEN
        authority_rows_locked := false;
    END IF;

    PERFORM 1
    FROM iam.user_role_grants AS creator_grant
    WHERE creator_grant.id = authority.grant_id
      AND creator_grant.user_id = exact_candidate_user_id
      AND creator_grant.role_code = 'CREATOR'
    FOR KEY SHARE OF creator_grant;
    IF NOT FOUND THEN
        authority_rows_locked := false;
    END IF;

    PERFORM 1
    FROM iam.access_invitations AS source_invitation
    WHERE source_invitation.id = authority.source_invitation_id
      AND source_invitation.accepted_by_user_id = exact_candidate_user_id
    FOR KEY SHARE OF source_invitation;
    IF NOT FOUND THEN
        authority_rows_locked := false;
    END IF;

    PERFORM 1
    FROM iam.policy_selectors AS selector
    WHERE selector.selector_digest = authority.policy_selector_digest
      AND selector.current_bundle_id = authority.current_bundle_id
    FOR KEY SHARE OF selector;
    IF NOT FOUND THEN
        authority_rows_locked := false;
    END IF;

    PERFORM 1
    FROM iam.policy_bundles AS current_bundle
    WHERE current_bundle.id = authority.current_bundle_id
      AND current_bundle.selector_digest = authority.policy_selector_digest
    FOR KEY SHARE OF current_bundle;
    IF NOT FOUND THEN
        authority_rows_locked := false;
    END IF;

    IF NOT authority_rows_locked THEN
        RETURN QUERY SELECT
            exact_candidate_user_id,
            false,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bytea,
            NULL::timestamptz;
        RETURN;
    END IF;

    -- Lock every required document and the candidate's matching acceptances in
    -- deterministic order before deriving the set digest.
    SELECT count(*)
    INTO STRICT expected_required_count
    FROM iam.policy_bundle_documents AS bundle_document
    WHERE bundle_document.bundle_id = authority.current_bundle_id
      AND bundle_document.required;

    PERFORM 1
    FROM iam.policy_bundle_documents AS bundle_document
    WHERE bundle_document.bundle_id = authority.current_bundle_id
      AND bundle_document.required
    ORDER BY bundle_document.position, bundle_document.document_id
    FOR KEY SHARE OF bundle_document;
    GET DIAGNOSTICS locked_bundle_document_count = ROW_COUNT;

    PERFORM 1
    FROM iam.policy_documents AS document
    WHERE document.id IN (
        SELECT bundle_document.document_id
        FROM iam.policy_bundle_documents AS bundle_document
        WHERE bundle_document.bundle_id = authority.current_bundle_id
          AND bundle_document.required
    )
    ORDER BY document.id
    FOR KEY SHARE OF document;
    GET DIAGNOSTICS locked_document_count = ROW_COUNT;

    SELECT count(*)
    INTO STRICT expected_acceptance_count
    FROM iam.policy_acceptances AS acceptance
    WHERE acceptance.user_id = exact_candidate_user_id
      AND acceptance.bundle_id = authority.current_bundle_id
      AND EXISTS (
            SELECT 1
            FROM iam.policy_bundle_documents AS bundle_document
            WHERE bundle_document.bundle_id = authority.current_bundle_id
              AND bundle_document.document_id = acceptance.document_id
              AND bundle_document.required
      );

    PERFORM 1
    FROM iam.policy_acceptances AS acceptance
    WHERE acceptance.user_id = exact_candidate_user_id
      AND acceptance.bundle_id = authority.current_bundle_id
      AND EXISTS (
            SELECT 1
            FROM iam.policy_bundle_documents AS bundle_document
            WHERE bundle_document.bundle_id = authority.current_bundle_id
              AND bundle_document.document_id = acceptance.document_id
              AND bundle_document.required
      )
    ORDER BY acceptance.document_id, acceptance.id
    FOR KEY SHARE OF acceptance;
    GET DIAGNOSTICS locked_acceptance_count = ROW_COUNT;

    IF locked_bundle_document_count <> expected_required_count
       OR locked_document_count <> expected_required_count
       OR locked_acceptance_count <> expected_acceptance_count THEN
        RETURN QUERY SELECT
            exact_candidate_user_id,
            false,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bytea,
            NULL::timestamptz;
        RETURN;
    END IF;

    SELECT
        count(*) FILTER (
            WHERE document.status <> 'ACTIVE'
               OR document.effective_at IS NULL
               OR document.effective_at > server_now
               OR document.legal_effect NOT IN (
                    'NOTICE_ACKNOWLEDGEMENT',
                    'CONTRACT_ACCEPTANCE'
               )
               OR acceptance.id IS NULL
        ),
        COALESCE(
            string_agg(
                bundle_document.document_id::text || ':'
                || bundle_document.position::text || ':'
                || bundle_document.required::text || ':'
                || document.status || ':'
                || COALESCE(
                    extract(epoch FROM document.effective_at)::text,
                    'none'
                ) || ':'
                || document.legal_effect || ':'
                || encode(document.content_sha256, 'hex') || ':'
                || extract(epoch FROM document.created_at)::text || ':'
                || extract(epoch FROM document.updated_at)::text || ':'
                || COALESCE(acceptance.id::text, 'none') || ':'
                || COALESCE(acceptance.session_id::text, 'none') || ':'
                || COALESCE(
                    acceptance.auth_transaction_id::text,
                    'none'
                ) || ':'
                || COALESCE(
                    acceptance.aggregate_version::text,
                    'none'
                ) || ':'
                || COALESCE(
                    extract(epoch FROM acceptance.accepted_at)::text,
                    'none'
                ) || ':'
                || COALESCE(
                    extract(epoch FROM acceptance.auth_time)::text,
                    'none'
                ) || ':'
                || COALESCE(
                    extract(epoch FROM acceptance.created_at)::text,
                    'none'
                ),
                ',' ORDER BY bundle_document.position,
                             bundle_document.document_id
            ),
            ''
        )
    INTO invalid_required_count, required_acceptance_facts
    FROM iam.policy_bundle_documents AS bundle_document
    JOIN iam.policy_documents AS document
      ON document.id = bundle_document.document_id
    LEFT JOIN iam.policy_acceptances AS acceptance
      ON acceptance.user_id = exact_candidate_user_id
     AND acceptance.bundle_id = authority.current_bundle_id
     AND acceptance.document_id = document.id
     AND acceptance.content_sha256 = document.content_sha256
    WHERE bundle_document.bundle_id = authority.current_bundle_id
      AND bundle_document.required;

    IF invalid_required_count <> 0 THEN
        RETURN QUERY SELECT
            exact_candidate_user_id,
            false,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bytea,
            NULL::timestamptz;
        RETURN;
    END IF;

    SELECT
        schema_head_version,
        migration_manifest_sha256,
        combined_contract_sha256
    INTO contract
    FROM infra.iam_schema_contracts
    WHERE component = 'iam'
      AND schema_head_version = 46
      AND min_app_compatible_version = 46
      AND max_app_compatible_version = 46;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            exact_candidate_user_id,
            false,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bytea,
            NULL::timestamptz;
        RETURN;
    END IF;

    bounded_valid_until := LEAST(
        COALESCE(
            authority.bundle_effective_until,
            'infinity'::timestamptz
        ),
        server_now + interval '15 minutes'
    );
    IF bounded_valid_until <= server_now THEN
        RETURN QUERY SELECT
            exact_candidate_user_id,
            false,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bigint,
            NULL::uuid,
            NULL::bigint,
            NULL::bytea,
            NULL::bytea,
            NULL::timestamptz;
        RETURN;
    END IF;

    acceptance_set_digest := sha256(convert_to(
        'desire.iam.profile-match-required-policy-acceptance-set.v1'
        || '|iam_head=46'
        || '|iam_contract_sha256='
        || encode(contract.combined_contract_sha256, 'hex')
        || '|candidate_user_id=' || exact_candidate_user_id::text
        || '|match_run_id=' || exact_match_run_id::text
        || '|workload_id=' || exact_workload_id::text
        || '|authorization_digest='
        || encode(exact_authorization_digest, 'hex')
        || '|demand_match_context_sha256='
        || encode(exact_demand_match_context_sha256, 'hex')
        || '|policy_bundle_id=' || authority.current_bundle_id::text
        || '|required_acceptance_facts=' || required_acceptance_facts,
        'UTF8'
    ));

    evidence_digest := sha256(convert_to(
        'desire.iam.profile-match-creator-eligibility-evidence.v1'
        || '|iam_head=46'
        || '|iam_schema_head=' || contract.schema_head_version::text
        || '|iam_manifest_sha256='
        || encode(contract.migration_manifest_sha256, 'hex')
        || '|iam_contract_sha256='
        || encode(contract.combined_contract_sha256, 'hex')
        || '|scope_kind=PROFILE_MATCH_DERIVATION'
        || '|operation=CAPTURE_DERIVED_MATCH_INPUTS'
        || '|decision=ELIGIBLE'
        || '|candidate_user_id=' || exact_candidate_user_id::text
        || '|match_run_id=' || exact_match_run_id::text
        || '|workload_id=' || exact_workload_id::text
        || '|authorization_digest='
        || encode(exact_authorization_digest, 'hex')
        || '|demand_match_context_sha256='
        || encode(exact_demand_match_context_sha256, 'hex')
        || '|creator_user_version=' || authority.user_version::text
        || '|creator_user_status=' || authority.user_status
        || '|creator_user_updated_epoch='
        || extract(epoch FROM authority.user_updated_at)::text
        || '|creator_grant_id=' || authority.grant_id::text
        || '|creator_grant_version=' || authority.grant_version::text
        || '|creator_granted_epoch='
        || extract(epoch FROM authority.granted_at)::text
        || '|creator_grant_revoked_epoch=' || COALESCE(
            extract(epoch FROM authority.revoked_at)::text,
            'none'
        )
        || '|source_invitation_id='
        || authority.source_invitation_id::text
        || '|source_invitation_version='
        || authority.invitation_version::text
        || '|source_invitation_status=' || authority.invitation_status
        || '|source_invitation_accepted_by='
        || authority.accepted_by_user_id::text
        || '|source_invitation_issued_bundle_id='
        || authority.issued_policy_bundle_id::text
        || '|source_invitation_terminal_epoch='
        || extract(epoch FROM authority.invitation_terminal_at)::text
        || '|source_invitation_updated_epoch='
        || extract(epoch FROM authority.invitation_updated_at)::text
        || '|policy_selector_digest='
        || encode(authority.policy_selector_digest, 'hex')
        || '|policy_selector_version=' || authority.selector_version::text
        || '|policy_selector_updated_epoch='
        || extract(epoch FROM authority.selector_updated_at)::text
        || '|policy_bundle_id=' || authority.current_bundle_id::text
        || '|policy_bundle_version=' || authority.bundle_version::text
        || '|policy_bundle_status=' || authority.bundle_status
        || '|policy_bundle_effective_epoch='
        || extract(epoch FROM authority.bundle_effective_at)::text
        || '|policy_bundle_effective_until_epoch=' || COALESCE(
            extract(epoch FROM authority.bundle_effective_until)::text,
            'none'
        )
        || '|policy_bundle_release_manifest_sha256='
        || encode(authority.release_manifest_sha256, 'hex')
        || '|policy_bundle_updated_epoch='
        || extract(epoch FROM authority.bundle_updated_at)::text
        || '|required_policy_acceptance_set_sha256='
        || encode(acceptance_set_digest, 'hex')
        || '|valid_until_epoch='
        || extract(epoch FROM bounded_valid_until)::text,
        'UTF8'
    ));

    RETURN QUERY SELECT
        exact_candidate_user_id,
        true,
        authority.user_version,
        authority.grant_id,
        authority.grant_version,
        authority.source_invitation_id,
        authority.invitation_version,
        authority.policy_selector_digest,
        authority.selector_version,
        authority.current_bundle_id,
        authority.bundle_version,
        acceptance_set_digest,
        evidence_digest,
        bounded_valid_until;
END
$function$;

ALTER FUNCTION iam_api.resolve_profile_match_creator_eligibility_v1(
    uuid, uuid, uuid, bytea, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_profile_match_creator_eligibility_v1(
    uuid, uuid, uuid, bytea, bytea
) FROM PUBLIC, profile_matcher, profile_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_profile_match_creator_eligibility_v1(
    uuid, uuid, uuid, bytea, bytea
) TO profile_schema_owner;

DO $iam46_profile_match_readiness$
DECLARE
    matcher_oid oid;
    profile_owner_oid oid;
    schema_owner_oid oid;
    resolver_oid oid;
    context_oid oid;
    invalid_function_count integer;
    unexpected_execute_acl_count integer;
    direct_relation_acl_count integer;
    derivation_policy_count integer;
    derivation_lock_policy_count integer;
BEGIN
    SELECT oid INTO STRICT matcher_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'profile_matcher';
    SELECT oid INTO STRICT profile_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'profile_schema_owner';
    SELECT oid INTO STRICT schema_owner_oid
    FROM pg_catalog.pg_roles WHERE rolname = 'schema_owner';
    SELECT 'iam_api.resolve_profile_match_creator_eligibility_v1('
           'uuid,uuid,uuid,bytea,bytea)'::regprocedure::oid
    INTO STRICT resolver_oid;
    SELECT 'iam_api.profile_match_derivation_context_valid_v1()'::regprocedure::oid
    INTO STRICT context_oid;

    SELECT count(*) INTO STRICT invalid_function_count
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid IN (resolver_oid, context_oid)
      AND (
            procedure.proowner <> schema_owner_oid
            OR NOT procedure.prosecdef
            OR procedure.proparallel <> 'u'
            OR procedure.proconfig IS NULL
            OR (
                procedure.oid = resolver_oid
                AND (
                    procedure.provolatile <> 'v'
                    OR NOT procedure.proretset
                    OR procedure.pronargs <> 5
                    OR procedure.prorettype <> 'record'::regtype
                    OR NOT (
                        'search_path=pg_catalog, iam, iam_api, infra'
                        = ANY(procedure.proconfig)
                    )
                )
            )
            OR (
                procedure.oid = context_oid
                AND (
                    procedure.provolatile <> 's'
                    OR procedure.proretset
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
                schema_owner_oid, profile_owner_oid
            )
            OR (
                privilege.grantee = profile_owner_oid
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
            privilege.grantee IN (matcher_oid, profile_owner_oid)
            OR column_privilege.grantee IN (matcher_oid, profile_owner_oid)
      );

    SELECT count(*) INTO STRICT derivation_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname IN (
        'rls_profile_match_derivation_user_definer_v1',
        'rls_profile_match_derivation_grant_definer_v1',
        'rls_profile_match_derivation_invitation_definer_v1',
        'rls_profile_match_derivation_selector_definer_v1',
        'rls_profile_match_derivation_bundle_definer_v1',
        'rls_profile_match_derivation_bundle_document_definer_v1',
        'rls_profile_match_derivation_document_definer_v1',
        'rls_profile_match_derivation_acceptance_definer_v1'
    )
      AND policy.polpermissive
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY[schema_owner_oid];

    SELECT count(*) INTO STRICT derivation_lock_policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polname IN (
        'rls_profile_match_derivation_user_lock_v1',
        'rls_profile_match_derivation_grant_lock_v1',
        'rls_profile_match_derivation_invitation_lock_v1',
        'rls_profile_match_derivation_selector_lock_v1',
        'rls_profile_match_derivation_bundle_lock_v1',
        'rls_profile_match_derivation_bundle_document_lock_v1',
        'rls_profile_match_derivation_document_lock_v1',
        'rls_profile_match_derivation_acceptance_lock_v1'
    )
      AND policy.polpermissive
      AND policy.polcmd = 'w'
      AND policy.polroles = ARRAY[schema_owner_oid];

    IF invalid_function_count <> 0
       OR unexpected_execute_acl_count <> 0
       OR direct_relation_acl_count <> 0
       OR derivation_policy_count <> 8
       OR derivation_lock_policy_count <> 8
       OR NOT pg_catalog.has_schema_privilege(
            'profile_schema_owner', 'iam_api', 'USAGE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'profile_schema_owner', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_matcher', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_app', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_creator', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_schema_owner', resolver_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_matcher', context_oid, 'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_schema_owner', context_oid, 'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_iam46_profile_match_creator_readiness',
            MESSAGE = 'IAM46 Profile match creator eligibility drifted';
    END IF;
END
$iam46_profile_match_readiness$;
