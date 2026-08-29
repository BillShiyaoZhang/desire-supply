-- Narrow IAM authority capabilities consumed by Creator Profile PostgreSQL.

CREATE POLICY rls_profile_authority_family_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    session_user = 'profile_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_profile_authority_session_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    session_user = 'profile_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_profile_authority_user_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    (
        session_user = 'profile_app'
        AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
        AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    )
    OR
    (
        session_user = 'profile_matcher'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'PROFILE_MATCH_CAPTURE'
        AND id = NULLIF(
            current_setting('app.iam_profile_candidate_user_id', true),
            ''
        )::uuid
    )
);

CREATE POLICY rls_profile_authority_grant_definer
ON iam.user_role_grants
FOR ALL TO schema_owner
USING (
    role_code = 'CREATOR'
    AND (
        (
            session_user = 'profile_app'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'PROFILE_SELF'
            AND user_id = NULLIF(
                current_setting('app.actor_user_id', true),
                ''
            )::uuid
        )
        OR
        (
            session_user = 'profile_matcher'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'PROFILE_MATCH_CAPTURE'
            AND user_id = NULLIF(
                current_setting('app.iam_profile_candidate_user_id', true),
                ''
            )::uuid
        )
    )
);

CREATE POLICY rls_profile_authority_invitation_definer
ON iam.access_invitations
FOR ALL TO schema_owner
USING (
    purpose = 'CREATOR_ENROLLMENT'
    AND target_scope = 'USER'
    AND target_role = 'CREATOR'
    AND (
        (
            session_user = 'profile_app'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'PROFILE_SELF'
            AND accepted_by_user_id = NULLIF(
                current_setting('app.actor_user_id', true),
                ''
            )::uuid
        )
        OR
        (
            session_user = 'profile_matcher'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'PROFILE_MATCH_CAPTURE'
            AND accepted_by_user_id = NULLIF(
                current_setting('app.iam_profile_candidate_user_id', true),
                ''
            )::uuid
        )
    )
);

CREATE POLICY rls_profile_authority_selector_definer
ON iam.policy_selectors
FOR ALL TO schema_owner
USING (
    access_purpose = 'CREATOR_ENROLLMENT'
    AND scope_type = 'USER_ROLE'
    AND target_role = 'CREATOR'
    AND (
        (
            session_user = 'profile_app'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'PROFILE_SELF'
        )
        OR
        (
            session_user = 'profile_matcher'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'PROFILE_MATCH_CAPTURE'
        )
    )
);

CREATE POLICY rls_profile_authority_bundle_definer
ON iam.policy_bundles
FOR ALL TO schema_owner
USING (
    (
        session_user = 'profile_app'
        AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    )
    OR
    (
        session_user = 'profile_matcher'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'PROFILE_MATCH_CAPTURE'
    )
);

CREATE POLICY rls_profile_authority_bundle_document_definer
ON iam.policy_bundle_documents
FOR SELECT TO schema_owner
USING (
    (
        session_user = 'profile_app'
        AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    )
    OR
    (
        session_user = 'profile_matcher'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'PROFILE_MATCH_CAPTURE'
    )
);

CREATE POLICY rls_profile_authority_document_definer
ON iam.policy_documents
FOR SELECT TO schema_owner
USING (
    (
        session_user = 'profile_app'
        AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    )
    OR
    (
        session_user = 'profile_matcher'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'PROFILE_MATCH_CAPTURE'
    )
);

CREATE POLICY rls_profile_authority_acceptance_definer
ON iam.policy_acceptances
FOR SELECT TO schema_owner
USING (
    (
        session_user = 'profile_app'
        AND NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
        AND user_id = NULLIF(
            current_setting('app.actor_user_id', true),
            ''
        )::uuid
    )
    OR
    (
        session_user = 'profile_matcher'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'PROFILE_MATCH_CAPTURE'
        AND user_id = NULLIF(
            current_setting('app.iam_profile_candidate_user_id', true),
            ''
        )::uuid
    )
);

CREATE FUNCTION iam_api.lock_creator_profile_self_v1(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    candidate_operation text,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    user_id uuid,
    creator_grant_id uuid,
    current_bundle_id uuid,
    authority_marker_sha256 bytea,
    marker_matches boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    locked_user_id uuid;
    locked_grant_id uuid;
    locked_selector_digest bytea;
    locked_bundle_id uuid;
    locked_user_version bigint;
    locked_grant_version bigint;
    computed_marker bytea;
BEGIN
    IF candidate_operation NOT IN (
        'CREATE_PROFILE',
        'SAVE_PROFILE_DRAFT',
        'PUBLISH_PROFILE',
        'PAUSE_PROFILE',
        'RESUME_PROFILE',
        'ARCHIVE_PROFILE'
    ) OR octet_length(expected_authority_marker_sha256) <> 32 THEN
        RETURN;
    END IF;

    SELECT
        actor.id,
        creator_grant.id,
        creator_grant.policy_selector_digest,
        selector.current_bundle_id,
        actor.aggregate_version,
        creator_grant.aggregate_version
    INTO
        locked_user_id,
        locked_grant_id,
        locked_selector_digest,
        locked_bundle_id,
        locked_user_version,
        locked_grant_version
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
    WHERE family.id = active_session.family_id
      AND family.status = 'ACTIVE'
      AND family.current_generation = active_session.generation
      AND active_session.id = candidate_session_id
      AND active_session.user_id = candidate_actor_user_id
      AND active_session.status = 'ACTIVE'
      AND active_session.idle_expires_at > transaction_timestamp()
      AND active_session.absolute_expires_at > transaction_timestamp()
      AND actor.id = candidate_actor_user_id
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
      )
    FOR UPDATE OF family, active_session, actor, creator_grant,
        source_invitation, selector, current_bundle;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    computed_marker := pg_catalog.sha256(
        pg_catalog.convert_to(
            locked_user_id::text || '|' ||
            candidate_session_id::text || '|' ||
            locked_grant_id::text || '|' ||
            pg_catalog.encode(locked_selector_digest, 'hex') || '|' ||
            locked_bundle_id::text || '|' ||
            locked_user_version::text || '|' ||
            locked_grant_version::text,
            'UTF8'
        )
    );

    IF computed_marker = expected_authority_marker_sha256 THEN
        RETURN QUERY SELECT
            locked_user_id,
            locked_grant_id,
            locked_bundle_id,
            computed_marker,
            true;
    ELSE
        RETURN QUERY SELECT
            locked_user_id,
            locked_grant_id,
            locked_bundle_id,
            NULL::bytea,
            false;
    END IF;
END
$function$;

CREATE FUNCTION iam_api.is_creator_match_eligible_v1(
    candidate_user_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    eligible boolean;
BEGIN
    PERFORM pg_catalog.set_config(
        'app.iam_profile_candidate_user_id',
        candidate_user_id::text,
        true
    );

    SELECT EXISTS (
        SELECT 1
        FROM iam.users AS creator
        JOIN iam.user_role_grants AS creator_grant
          ON creator_grant.user_id = creator.id
         AND creator_grant.role_code = 'CREATOR'
         AND creator_grant.revoked_at IS NULL
        JOIN iam.access_invitations AS source_invitation
          ON source_invitation.id = creator_grant.source_invitation_id
         AND source_invitation.policy_selector_digest
             = creator_grant.policy_selector_digest
         AND source_invitation.status = 'ACCEPTED'
         AND source_invitation.accepted_by_user_id = creator.id
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
        WHERE creator.id = candidate_user_id
          AND creator.status = 'ACTIVE'
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
                    WHERE acceptance.user_id = creator.id
                      AND acceptance.document_id = document.id
                      AND acceptance.content_sha256 = document.content_sha256
                )
              )
          )
    ) INTO eligible;
    RETURN eligible;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.lock_creator_profile_self_v1(
    uuid,
    uuid,
    text,
    bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.is_creator_match_eligible_v1(uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA iam_api TO profile_app, profile_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.lock_creator_profile_self_v1(
    uuid,
    uuid,
    text,
    bytea
) TO profile_app;
GRANT EXECUTE ON FUNCTION iam_api.is_creator_match_eligible_v1(uuid)
TO profile_schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO profile_app;
GRANT INSERT ON audit.audit_events TO profile_app;
GRANT INSERT ON infra.outbox_events TO profile_app;

CREATE POLICY rls_profile_audit_insert_user
ON audit.audit_events
FOR INSERT TO profile_app
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND actor_kind = 'USER'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND causation_id = NULLIF(current_setting('app.causation_id', true), '')::uuid
    AND target_kind = 'CreatorProfile'
    AND target_id = NULLIF(current_setting('app.profile_id', true), '')::uuid
    AND organization_id IS NULL
    AND action_code IN (
        'PROFILE_CREATED',
        'PROFILE_DRAFT_SAVED',
        'PROFILE_PUBLISHED',
        'PROFILE_PAUSED',
        'PROFILE_RESUMED',
        'PROFILE_ARCHIVED'
    )
);

CREATE POLICY rls_profile_outbox_insert_user
ON infra.outbox_events
FOR INSERT TO profile_app
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND actor_kind = 'USER'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND causation_id = NULLIF(current_setting('app.causation_id', true), '')::uuid
    AND aggregate_type = 'CreatorProfile'
    AND aggregate_id = NULLIF(current_setting('app.profile_id', true), '')::uuid
    AND organization_id IS NULL
    AND event_type IN (
        'CreatorProfileCreated',
        'CreatorProfilePublished',
        'CreatorProfilePaused',
        'CreatorProfileResumed',
        'CreatorProfileArchived'
    )
);

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
        'lock_creator_profile_self_v1',
        'is_creator_match_eligible_v1'
      )
      AND (
        NOT procedure.prosecdef
        OR procedure.provolatile <> 'v'
        OR procedure.proparallel <> 'u'
        OR procedure.proconfig IS NULL
      );
    IF invalid_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Creator Profile IAM capability assertion failed';
    END IF;
    IF pg_catalog.has_function_privilege(
        'profile_matcher',
        'iam_api.is_creator_match_eligible_v1(uuid)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'profile_schema_owner',
        'iam_api.is_creator_match_eligible_v1(uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Creator Profile matcher IAM capability grant failed';
    END IF;
END
$assert$;
