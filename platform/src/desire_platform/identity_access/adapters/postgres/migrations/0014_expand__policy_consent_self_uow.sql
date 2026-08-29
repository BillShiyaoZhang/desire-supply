-- Exact SELF PostgreSQL write boundary for AcceptCurrentPolicies/GrantConsent.

ALTER TABLE infra.command_receipts
    ADD COLUMN response_http_status integer NULL,
    ADD COLUMN response_schema_name varchar(96) NULL,
    ADD COLUMN response_entity_tag varchar(64) NULL,
    ADD COLUMN current_user_entity_tag varchar(64) NULL;

ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_policy_consent_response CHECK (
    command_name NOT IN ('AcceptCurrentPolicies', 'GrantConsent')
    OR (
        command_version = 1
        AND principal_kind = 'USER'
        AND target_kind = 'User'
        AND target_id = principal_id
        AND http_method = 'POST'
        AND if_match_version >= 1
        AND reconstruction_metadata IS NULL
        AND (
            (
                status = 'IN_PROGRESS'
                AND response_http_status IS NULL
                AND response_schema_name IS NULL
                AND response_entity_tag IS NULL
                AND current_user_entity_tag IS NULL
            )
            OR (
                status = 'COMPLETED'
                AND response_schema_version = 1
                AND response_http_status IS NOT NULL
                AND response_schema_name IS NOT NULL
                AND response_entity_tag ~ '^"v[1-9][0-9]*"$'
                AND current_user_entity_tag ~ '^"v[1-9][0-9]*"$'
                AND (
                    (
                        command_name = 'AcceptCurrentPolicies'
                        AND canonical_path = '/v1/me/policy-acceptances'
                        AND response_http_status = 200
                        AND response_schema_name = 'PolicyRequirementStatusDto'
                        AND response_entity_tag = current_user_entity_tag
                    )
                    OR (
                        command_name = 'GrantConsent'
                        AND canonical_path = '/v1/me/consents'
                        AND response_http_status = 201
                        AND response_schema_name = 'ConsentGrantDto'
                        AND jsonb_typeof(
                            safe_response_body -> 'aggregate_version'
                        ) = 'number'
                        AND safe_response_body ->> 'aggregate_version'
                            ~ '^[1-9][0-9]*$'
                        AND response_entity_tag = (
                            '"v'
                            || (safe_response_body ->> 'aggregate_version')
                            || '"'
                        )
                    )
                )
            )
        )
    )
);

CREATE POLICY rls_policy_consent_lock_user_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_lock_family_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_lock_session_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND family_id = NULLIF(
        current_setting('app.session_family_id', true),
        ''
    )::uuid
);

CREATE POLICY rls_policy_consent_lock_auth_definer
ON iam.auth_transactions
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND id = NULLIF(current_setting('app.auth_transaction_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_lock_organization_definer
ON iam.organizations
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_lock_membership_definer
ON iam.memberships
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true),
        ''
    )::uuid
);

CREATE POLICY rls_policy_consent_lock_user_role_definer
ON iam.user_role_grants
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND policy_selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_consent_lock_membership_role_definer
ON iam.membership_role_grants
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true),
        ''
    )::uuid
    AND policy_selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_consent_lock_invitation_definer
ON iam.access_invitations
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND accepted_by_user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
    AND policy_selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_consent_lock_selector_definer
ON iam.policy_selectors
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_consent_lock_bundle_definer
ON iam.policy_bundles
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_consent_lock_bundle_document_definer
ON iam.policy_bundle_documents
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS bundle
        WHERE bundle.id = policy_bundle_documents.bundle_id
          AND bundle.selector_digest = decode(
              NULLIF(
                  current_setting('app.policy_selector_digest', true),
                  ''
              ),
              'hex'
          )
    )
);

CREATE POLICY rls_policy_consent_lock_document_definer
ON iam.policy_documents
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        JOIN iam.policy_bundles AS bundle ON bundle.id = membership.bundle_id
        WHERE membership.document_id = policy_documents.id
          AND bundle.selector_digest = decode(
              NULLIF(
                  current_setting('app.policy_selector_digest', true),
                  ''
              ),
              'hex'
          )
    )
);

CREATE POLICY rls_policy_consent_lock_offer_definer
ON iam.consent_offers
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS bundle
        WHERE bundle.id = consent_offers.bundle_id
          AND bundle.selector_digest = decode(
              NULLIF(
                  current_setting('app.policy_selector_digest', true),
                  ''
              ),
              'hex'
          )
    )
);

CREATE POLICY rls_policy_consent_lock_offer_category_definer
ON iam.consent_offer_data_categories
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.consent_offers AS offer
        JOIN iam.policy_bundles AS bundle ON bundle.id = offer.bundle_id
        WHERE offer.id = consent_offer_data_categories.offer_id
          AND bundle.selector_digest = decode(
              NULLIF(
                  current_setting('app.policy_selector_digest', true),
                  ''
              ),
              'hex'
          )
    )
);

CREATE POLICY rls_policy_consent_lock_acceptance_definer
ON iam.policy_acceptances
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_lock_grant_definer
ON iam.consent_grants
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_lock_grant_category_definer
ON iam.consent_grant_data_categories
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.consent_grants AS grant_row
        WHERE grant_row.id = consent_grant_data_categories.grant_id
          AND grant_row.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
    )
);

CREATE FUNCTION iam.lock_policy_consent_principal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_session_family_id uuid,
    exact_auth_transaction_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    locked_family iam.session_families%ROWTYPE;
    locked_session iam.sessions%ROWTYPE;
    locked_user iam.users%ROWTYPE;
    locked_auth iam.auth_transactions%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'SELF'
       OR NULLIF(current_setting('app.operation', true), '') NOT IN (
            'ACCEPT_CURRENT_POLICIES',
            'GRANT_CONSENT'
       )
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.session_family_id', true), '')
            IS DISTINCT FROM exact_session_family_id::text
       OR NULLIF(current_setting('app.auth_transaction_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_policy_consent_principal_scope',
            MESSAGE = 'policy consent principal scope is invalid';
    END IF;

    SELECT family.*
    INTO locked_family
    FROM iam.session_families AS family
    WHERE family.id = exact_session_family_id
      AND family.user_id = exact_actor_user_id
    FOR UPDATE;

    SELECT session.*
    INTO locked_session
    FROM iam.sessions AS session
    WHERE session.id = exact_session_id
      AND session.user_id = exact_actor_user_id
      AND session.family_id = exact_session_family_id
    FOR UPDATE;

    SELECT actor.*
    INTO locked_user
    FROM iam.users AS actor
    WHERE actor.id = exact_actor_user_id
    FOR UPDATE;

    SELECT auth.*
    INTO locked_auth
    FROM iam.auth_transactions AS auth
    WHERE auth.id = exact_auth_transaction_id
    FOR UPDATE;

    IF locked_family.id IS NULL
       OR locked_session.id IS NULL
       OR locked_user.id IS NULL
       OR locked_auth.id IS NULL
       OR locked_family.status <> 'ACTIVE'
       OR locked_session.status <> 'ACTIVE'
       OR locked_user.status <> 'ACTIVE'
       OR locked_family.current_generation <> locked_session.generation
       OR locked_session.auth_transaction_id <> exact_auth_transaction_id
       OR locked_session.auth_time IS NULL
       OR locked_session.auth_time > transaction_timestamp()
       OR locked_session.idle_expires_at <= transaction_timestamp()
       OR locked_session.absolute_expires_at <= transaction_timestamp()
       OR locked_auth.status <> 'SUCCEEDED'
       OR locked_auth.purpose NOT IN ('LOGIN', 'STEP_UP')
       OR locked_auth.expected_user_id NOT IN (exact_actor_user_id)
          AND locked_auth.expected_user_id IS NOT NULL
       OR locked_auth.succeeded_at IS DISTINCT FROM locked_session.auth_time
       OR locked_auth.deadline <= transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_policy_consent_principal_active',
            MESSAGE = 'policy consent principal is unavailable';
    END IF;

    RETURN jsonb_build_object(
        'user_id', locked_user.id::text,
        'user_status', locked_user.status,
        'user_version', locked_user.aggregate_version,
        'session_id', locked_session.id::text,
        'session_family_id', locked_family.id::text,
        'auth_transaction_id', locked_session.auth_transaction_id::text,
        'auth_time', locked_session.auth_time,
        'acr_code', locked_session.acr_code,
        'amr_codes', to_jsonb(iam.canonical_text_array(locked_session.amr_codes))
    );
END
$function$;

CREATE FUNCTION iam.lock_policy_consent_self_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_selector_digest bytea,
    exact_scope_type text,
    exact_scope_id uuid,
    presented_bundle_id uuid,
    exact_operation text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    principal jsonb;
    locked_organization iam.organizations%ROWTYPE;
    locked_membership iam.memberships%ROWTYPE;
    locked_user_role iam.user_role_grants%ROWTYPE;
    locked_membership_role iam.membership_role_grants%ROWTYPE;
    locked_invitation iam.access_invitations%ROWTYPE;
    locked_selector iam.policy_selectors%ROWTYPE;
    locked_bundle iam.policy_bundles%ROWTYPE;
    authority_count bigint;
    locked_documents jsonb;
    locked_offers jsonb;
    locked_acceptances jsonb;
    locked_grants jsonb;
    authority_role text;
    authority_organization_id uuid;
BEGIN
    IF exact_selector_digest IS NULL
       OR octet_length(exact_selector_digest) <> 32
       OR presented_bundle_id IS NULL
       OR exact_operation NOT IN ('ACCEPT_CURRENT_POLICIES', 'GRANT_CONSENT')
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.policy_selector_digest', true), '')
            IS DISTINCT FROM encode(exact_selector_digest, 'hex')
       OR NULLIF(current_setting('app.policy_bundle_id', true), '')
            IS DISTINCT FROM presented_bundle_id::text
       OR NULLIF(current_setting('app.authority_scope_type', true), '')
            IS DISTINCT FROM exact_scope_type
       OR COALESCE(
            NULLIF(current_setting('app.authority_scope_id', true), ''),
            ''
       ) IS DISTINCT FROM COALESCE(exact_scope_id::text, '') THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_policy_consent_graph_scope',
            MESSAGE = 'policy consent graph scope is invalid';
    END IF;

    principal := iam.lock_policy_consent_principal_v1(
        exact_actor_user_id,
        exact_session_id,
        NULLIF(current_setting('app.session_family_id', true), '')::uuid,
        NULLIF(current_setting('app.auth_transaction_id', true), '')::uuid
    );

    IF exact_scope_type = 'USER_ROLE' AND exact_scope_id IS NULL THEN
        PERFORM grant_row.id
        FROM iam.user_role_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_user_id
          AND grant_row.policy_selector_digest = exact_selector_digest
          AND grant_row.revoked_at IS NULL
        ORDER BY grant_row.id
        FOR UPDATE;

        SELECT count(*)
        INTO authority_count
        FROM iam.user_role_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_user_id
          AND grant_row.policy_selector_digest = exact_selector_digest
          AND grant_row.revoked_at IS NULL;
        IF authority_count <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_policy_consent_authority',
                MESSAGE = 'policy consent authority is unavailable';
        END IF;
        SELECT grant_row.*
        INTO locked_user_role
        FROM iam.user_role_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_user_id
          AND grant_row.policy_selector_digest = exact_selector_digest
          AND grant_row.revoked_at IS NULL;
        authority_role := locked_user_role.role_code;
        SELECT invitation.*
        INTO locked_invitation
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = locked_user_role.source_invitation_id
        FOR UPDATE;
    ELSIF exact_scope_type = 'ORGANIZATION_ROLE' AND exact_scope_id IS NOT NULL THEN
        SELECT organization.*
        INTO locked_organization
        FROM iam.organizations AS organization
        WHERE organization.id = exact_scope_id
        FOR UPDATE;
        SELECT membership.*
        INTO locked_membership
        FROM iam.memberships AS membership
        WHERE membership.organization_id = exact_scope_id
          AND membership.user_id = exact_actor_user_id
        FOR UPDATE;
        PERFORM grant_row.id
        FROM iam.membership_role_grants AS grant_row
        WHERE grant_row.organization_id = exact_scope_id
          AND grant_row.membership_id = locked_membership.id
          AND grant_row.user_id = exact_actor_user_id
          AND grant_row.policy_selector_digest = exact_selector_digest
          AND grant_row.revoked_at IS NULL
        ORDER BY grant_row.id
        FOR UPDATE;
        SELECT count(*)
        INTO authority_count
        FROM iam.membership_role_grants AS grant_row
        WHERE grant_row.organization_id = exact_scope_id
          AND grant_row.membership_id = locked_membership.id
          AND grant_row.user_id = exact_actor_user_id
          AND grant_row.policy_selector_digest = exact_selector_digest
          AND grant_row.revoked_at IS NULL;
        IF locked_organization.id IS NULL
           OR locked_membership.id IS NULL
           OR locked_organization.status <> 'ACTIVE'
           OR locked_membership.status <> 'ACTIVE'
           OR authority_count <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_policy_consent_authority',
                MESSAGE = 'policy consent authority is unavailable';
        END IF;
        SELECT grant_row.*
        INTO locked_membership_role
        FROM iam.membership_role_grants AS grant_row
        WHERE grant_row.organization_id = exact_scope_id
          AND grant_row.membership_id = locked_membership.id
          AND grant_row.user_id = exact_actor_user_id
          AND grant_row.policy_selector_digest = exact_selector_digest
          AND grant_row.revoked_at IS NULL;
        authority_role := locked_membership_role.role_code;
        authority_organization_id := exact_scope_id;
        SELECT invitation.*
        INTO locked_invitation
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = locked_membership_role.source_invitation_id
        FOR UPDATE;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_policy_consent_authority',
            MESSAGE = 'policy consent authority is unavailable';
    END IF;

    SELECT selector.*
    INTO locked_selector
    FROM iam.policy_selectors AS selector
    WHERE selector.selector_digest = exact_selector_digest
    FOR UPDATE;

    IF locked_selector.selector_digest IS NULL
       OR locked_selector.current_bundle_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_policy_consent_selector',
            MESSAGE = 'policy consent selector is unavailable';
    END IF;

    IF locked_selector.scope_type <> exact_scope_type
       OR locked_selector.target_role <> authority_role
       OR locked_invitation.id IS NULL
       OR locked_invitation.status <> 'ACCEPTED'
       OR locked_invitation.accepted_by_user_id <> exact_actor_user_id
       OR locked_invitation.policy_selector_digest <> exact_selector_digest
       OR locked_invitation.target_role <> authority_role
       OR locked_invitation.purpose <> locked_selector.access_purpose THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_policy_consent_authority',
            MESSAGE = 'policy consent authority is unavailable';
    END IF;

    SELECT bundle.*
    INTO locked_bundle
    FROM iam.policy_bundles AS bundle
    WHERE bundle.id = locked_selector.current_bundle_id
      AND bundle.selector_digest = exact_selector_digest
    FOR UPDATE;

    IF locked_bundle.id IS NULL
       OR locked_bundle.status <> 'ACTIVE'
       OR locked_bundle.effective_at IS NULL
       OR locked_bundle.effective_at > transaction_timestamp()
       OR (
           locked_bundle.effective_until IS NOT NULL
           AND transaction_timestamp() >= locked_bundle.effective_until
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_policy_consent_bundle',
            MESSAGE = 'policy consent current bundle is unavailable';
    END IF;

    PERFORM membership.document_id
    FROM iam.policy_bundle_documents AS membership
    WHERE membership.bundle_id = locked_bundle.id
    ORDER BY membership.position, membership.document_id
    FOR UPDATE;
    PERFORM document.id
    FROM iam.policy_documents AS document
    JOIN iam.policy_bundle_documents AS membership
      ON membership.document_id = document.id
     AND membership.bundle_id = locked_bundle.id
    ORDER BY membership.position, document.id
    FOR UPDATE OF document;
    PERFORM offer.id
    FROM iam.consent_offers AS offer
    WHERE offer.bundle_id = locked_bundle.id
    ORDER BY offer.purpose, offer.scope_type, offer.id
    FOR UPDATE;
    PERFORM category.offer_id, category.position
    FROM iam.consent_offer_data_categories AS category
    JOIN iam.consent_offers AS offer
      ON offer.id = category.offer_id
     AND offer.bundle_id = locked_bundle.id
    ORDER BY category.offer_id, category.position
    FOR UPDATE OF category;

    PERFORM acceptance.id
    FROM iam.policy_acceptances AS acceptance
    JOIN iam.policy_bundle_documents AS membership
      ON membership.document_id = acceptance.document_id
     AND membership.bundle_id = locked_bundle.id
     AND membership.required
    WHERE acceptance.user_id = exact_actor_user_id
      AND acceptance.content_sha256 = (
          SELECT document.content_sha256
          FROM iam.policy_documents AS document
          WHERE document.id = membership.document_id
      )
    ORDER BY membership.position, acceptance.id
    FOR UPDATE OF acceptance;

    IF exact_operation = 'GRANT_CONSENT' THEN
        PERFORM grant_row.id
        FROM iam.consent_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_user_id
          AND grant_row.purpose = 'PILOT_RESEARCH'
          AND grant_row.scope_type = 'PLATFORM_PARTICIPATION'
          AND grant_row.scope_id IS NULL
          AND grant_row.status = 'ACTIVE'
        ORDER BY grant_row.id
        FOR UPDATE;
        PERFORM category.grant_id, category.position
        FROM iam.consent_grant_data_categories AS category
        JOIN iam.consent_grants AS grant_row ON grant_row.id = category.grant_id
        WHERE grant_row.user_id = exact_actor_user_id
          AND grant_row.purpose = 'PILOT_RESEARCH'
          AND grant_row.scope_type = 'PLATFORM_PARTICIPATION'
          AND grant_row.scope_id IS NULL
          AND grant_row.status = 'ACTIVE'
        ORDER BY category.grant_id, category.position
        FOR UPDATE OF category;
    END IF;

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'document_id', document.id::text,
                'content_sha256', encode(document.content_sha256, 'hex'),
                'status', document.status,
                'kind', document.kind,
                'legal_effect', document.legal_effect,
                'required', membership.required,
                'position', membership.position
            ) ORDER BY membership.position, document.id
        ),
        '[]'::jsonb
    )
    INTO locked_documents
    FROM iam.policy_bundle_documents AS membership
    JOIN iam.policy_documents AS document ON document.id = membership.document_id
    WHERE membership.bundle_id = locked_bundle.id;

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'consent_offer_id', offer.id::text,
                'offer_version', offer.offer_version,
                'purpose', offer.purpose,
                'scope_type', offer.scope_type,
                'scope_derivation', offer.scope_derivation,
                'recipient_ref', offer.recipient_ref,
                'recipient_label', offer.recipient_label,
                'document_id', offer.document_id::text,
                'document_content_sha256', encode(
                    offer.document_content_sha256,
                    'hex'
                ),
                'expiry_rule', offer.expiry_rule,
                'expiry_days', offer.expiry_days,
                'not_after', offer.not_after,
                'optional', offer.optional,
                'canonical_offer_sha256', encode(
                    offer.canonical_offer_sha256,
                    'hex'
                ),
                'categories', COALESCE(
                    (
                        SELECT jsonb_agg(category.category ORDER BY category.position)
                        FROM iam.consent_offer_data_categories AS category
                        WHERE category.offer_id = offer.id
                    ),
                    '[]'::jsonb
                )
            ) ORDER BY offer.purpose, offer.scope_type, offer.id
        ),
        '[]'::jsonb
    )
    INTO locked_offers
    FROM iam.consent_offers AS offer
    WHERE offer.bundle_id = locked_bundle.id;

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'acceptance_id', acceptance.id::text,
                'document_id', acceptance.document_id::text,
                'content_sha256', encode(acceptance.content_sha256, 'hex'),
                'bundle_id', acceptance.bundle_id::text,
                'accepted_at', acceptance.accepted_at,
                'session_id', acceptance.session_id::text,
                'auth_transaction_id', acceptance.auth_transaction_id::text,
                'auth_time', acceptance.auth_time,
                'acr_code', acceptance.acr_code,
                'amr_codes', to_jsonb(iam.canonical_text_array(acceptance.amr_codes)),
                'source_action', acceptance.source_action,
                'command_id', acceptance.command_id::text,
                'aggregate_version', acceptance.aggregate_version,
                'source_valid', EXISTS (
                    SELECT 1
                    FROM iam.policy_bundles AS source_bundle
                    JOIN iam.policy_bundle_documents AS source_membership
                      ON source_membership.bundle_id = source_bundle.id
                     AND source_membership.document_id = acceptance.document_id
                    JOIN iam.policy_documents AS source_document
                      ON source_document.id = source_membership.document_id
                    WHERE source_bundle.id = acceptance.bundle_id
                      AND source_bundle.selector_digest = exact_selector_digest
                      AND source_document.content_sha256 = acceptance.content_sha256
                      AND source_document.status = 'ACTIVE'
                      AND source_document.legal_effect = 'CONTRACT_ACCEPTANCE'
                )
            ) ORDER BY membership.position, acceptance.id
        ),
        '[]'::jsonb
    )
    INTO locked_acceptances
    FROM iam.policy_bundle_documents AS membership
    JOIN iam.policy_documents AS document ON document.id = membership.document_id
    JOIN iam.policy_acceptances AS acceptance
      ON acceptance.user_id = exact_actor_user_id
     AND acceptance.document_id = document.id
     AND acceptance.content_sha256 = document.content_sha256
    WHERE membership.bundle_id = locked_bundle.id
      AND membership.required;

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'consent_grant_id', grant_row.id::text,
                'consent_offer_id', grant_row.consent_offer_id::text,
                'consent_offer_version', grant_row.consent_offer_version,
                'policy_bundle_id', grant_row.policy_bundle_id::text,
                'purpose', grant_row.purpose,
                'scope_type', grant_row.scope_type,
                'scope_id', grant_row.scope_id,
                'recipient_ref', grant_row.recipient_ref,
                'recipient_label', grant_row.recipient_label,
                'document_id', grant_row.document_id::text,
                'document_content_sha256', encode(
                    grant_row.document_content_sha256,
                    'hex'
                ),
                'granted_at', grant_row.granted_at,
                'expires_at', grant_row.expires_at,
                'session_id', grant_row.session_id::text,
                'auth_transaction_id', grant_row.auth_transaction_id::text,
                'auth_time', grant_row.auth_time,
                'acr_code', grant_row.acr_code,
                'amr_codes', to_jsonb(iam.canonical_text_array(grant_row.amr_codes)),
                'status', grant_row.status,
                'aggregate_version', grant_row.aggregate_version,
                'categories', COALESCE(
                    (
                        SELECT jsonb_agg(category.category ORDER BY category.position)
                        FROM iam.consent_grant_data_categories AS category
                        WHERE category.grant_id = grant_row.id
                    ),
                    '[]'::jsonb
                )
            ) ORDER BY grant_row.id
        ),
        '[]'::jsonb
    )
    INTO locked_grants
    FROM iam.consent_grants AS grant_row
    WHERE exact_operation = 'GRANT_CONSENT'
      AND grant_row.user_id = exact_actor_user_id
      AND grant_row.purpose = 'PILOT_RESEARCH'
      AND grant_row.scope_type = 'PLATFORM_PARTICIPATION'
      AND grant_row.scope_id IS NULL
      AND grant_row.status = 'ACTIVE';

    RETURN jsonb_build_object(
        'principal', principal,
        'authority', jsonb_build_object(
            'purpose', locked_selector.access_purpose,
            'role', authority_role,
            'scope_type', exact_scope_type,
            'scope_id', exact_scope_id,
            'organization_id', authority_organization_id
        ),
        'bundle', jsonb_build_object(
            'policy_bundle_id', locked_bundle.id::text,
            'selector_digest', encode(locked_selector.selector_digest, 'hex'),
            'status', locked_bundle.status,
            'effective_at', locked_bundle.effective_at,
            'effective_until', locked_bundle.effective_until
        ),
        'documents', locked_documents,
        'offers', locked_offers,
        'acceptances', locked_acceptances,
        'active_grants', locked_grants
    );
END
$function$;

REVOKE ALL ON FUNCTION iam.lock_policy_consent_principal_v1(
    uuid,
    uuid,
    uuid,
    uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.lock_policy_consent_self_v1(
    uuid,
    uuid,
    bytea,
    text,
    uuid,
    uuid,
    text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.lock_policy_consent_principal_v1(
    uuid,
    uuid,
    uuid,
    uuid
) TO iam_app;
GRANT EXECUTE ON FUNCTION iam.lock_policy_consent_self_v1(
    uuid,
    uuid,
    bytea,
    text,
    uuid,
    uuid,
    text
) TO iam_app;

GRANT SELECT (auth_transaction_id, auth_time, acr_code, amr_codes)
ON iam.sessions TO iam_app;
GRANT UPDATE (aggregate_version, updated_at) ON iam.users TO iam_app;
GRANT INSERT ON iam.policy_acceptances TO iam_app;
GRANT INSERT ON iam.consent_grants TO iam_app;
GRANT SELECT (command_id, recipient_ref) ON iam.consent_grants TO iam_app;
GRANT UPDATE (status, withdrawn_at, aggregate_version, updated_at)
ON iam.consent_grants TO iam_app;
GRANT INSERT ON iam.consent_grant_data_categories TO iam_app;
GRANT SELECT (recipient_ref, expiry_days) ON iam.consent_offers TO iam_app;

CREATE POLICY rls_policy_consent_user_update
ON iam.users
FOR UPDATE TO iam_app
USING (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'ACCEPT_CURRENT_POLICIES',
        'GRANT_CONSENT'
    )
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
)
WITH CHECK (
    id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
);

CREATE POLICY rls_policy_consent_acceptance_insert
ON iam.policy_acceptances
FOR INSERT TO iam_app
WITH CHECK (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'ACCEPT_CURRENT_POLICIES'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND session_id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND auth_transaction_id = NULLIF(
        current_setting('app.auth_transaction_id', true),
        ''
    )::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
);

CREATE POLICY rls_policy_consent_grant_insert
ON iam.consent_grants
FOR INSERT TO iam_app
WITH CHECK (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'GRANT_CONSENT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND session_id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND auth_transaction_id = NULLIF(
        current_setting('app.auth_transaction_id', true),
        ''
    )::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND policy_bundle_id = NULLIF(
        current_setting('app.policy_bundle_id', true),
        ''
    )::uuid
    AND purpose = 'PILOT_RESEARCH'
    AND scope_type = 'PLATFORM_PARTICIPATION'
    AND scope_id IS NULL
    AND status = 'ACTIVE'
);

CREATE POLICY rls_policy_consent_grant_expire
ON iam.consent_grants
FOR UPDATE TO iam_app
USING (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'GRANT_CONSENT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND purpose = 'PILOT_RESEARCH'
    AND scope_type = 'PLATFORM_PARTICIPATION'
    AND scope_id IS NULL
    AND status = 'ACTIVE'
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND purpose = 'PILOT_RESEARCH'
    AND scope_type = 'PLATFORM_PARTICIPATION'
    AND scope_id IS NULL
    AND status = 'EXPIRED'
    AND withdrawn_at IS NULL
    AND expires_at <= transaction_timestamp()
);

CREATE POLICY rls_policy_consent_grant_category_insert
ON iam.consent_grant_data_categories
FOR INSERT TO iam_app
WITH CHECK (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'GRANT_CONSENT'
    AND EXISTS (
        SELECT 1
        FROM iam.consent_grants AS grant_row
        WHERE grant_row.id = consent_grant_data_categories.grant_id
          AND grant_row.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
          AND grant_row.command_id = NULLIF(
              current_setting('app.command_id', true),
              ''
          )::uuid
    )
);

CREATE POLICY rls_policy_consent_offer_validate_grant
ON iam.consent_offers
FOR SELECT TO iam_app
USING (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'GRANT_CONSENT'
    AND EXISTS (
        SELECT 1
        FROM iam.consent_grants AS grant_row
        WHERE grant_row.consent_offer_id = consent_offers.id
          AND grant_row.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
    )
);

CREATE OR REPLACE FUNCTION iam.assert_consent_grant_matches_offer(
    checked_grant_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    grant_row record;
    offer_row record;
    expected_expiry timestamptz;
BEGIN
    SELECT
        grant_fact.id,
        grant_fact.consent_offer_id,
        grant_fact.consent_offer_version,
        grant_fact.policy_bundle_id,
        grant_fact.purpose,
        grant_fact.scope_type,
        grant_fact.scope_id,
        grant_fact.recipient_ref,
        grant_fact.recipient_label,
        grant_fact.document_id,
        grant_fact.document_content_sha256,
        grant_fact.granted_at,
        grant_fact.expires_at
    INTO grant_row
    FROM iam.consent_grants AS grant_fact
    WHERE grant_fact.id = checked_grant_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        offer.id,
        offer.bundle_id,
        offer.offer_version,
        offer.purpose,
        offer.scope_type,
        offer.recipient_ref,
        offer.recipient_label,
        offer.document_id,
        offer.document_content_sha256,
        offer.expiry_rule,
        offer.expiry_days,
        offer.not_after
    INTO offer_row
    FROM iam.consent_offers AS offer
    WHERE offer.id = grant_row.consent_offer_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_grant_matches_offer',
            MESSAGE = 'consent offer is unavailable';
    END IF;

    expected_expiry := CASE offer_row.expiry_rule
        WHEN 'FIXED_NOT_AFTER' THEN offer_row.not_after
        ELSE least(
            grant_row.granted_at + (offer_row.expiry_days * interval '1 day'),
            offer_row.not_after
        )
    END;

    IF grant_row.consent_offer_version <> offer_row.offer_version
       OR grant_row.policy_bundle_id <> offer_row.bundle_id
       OR grant_row.purpose <> offer_row.purpose
       OR grant_row.scope_type <> offer_row.scope_type
       OR grant_row.scope_id IS NOT NULL
       OR grant_row.recipient_ref <> offer_row.recipient_ref
       OR grant_row.recipient_label <> offer_row.recipient_label
       OR grant_row.document_id <> offer_row.document_id
       OR grant_row.document_content_sha256 <> offer_row.document_content_sha256
       OR grant_row.expires_at <> expected_expiry
       OR EXISTS (
            SELECT category, position
            FROM iam.consent_offer_data_categories
            WHERE offer_id = offer_row.id
            EXCEPT
            SELECT category, position
            FROM iam.consent_grant_data_categories
            WHERE grant_id = grant_row.id
       )
       OR EXISTS (
            SELECT category, position
            FROM iam.consent_grant_data_categories
            WHERE grant_id = grant_row.id
            EXCEPT
            SELECT category, position
            FROM iam.consent_offer_data_categories
            WHERE offer_id = offer_row.id
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_grant_matches_offer',
            MESSAGE = 'consent grant does not match immutable offer';
    END IF;
END
$function$;

GRANT EXECUTE ON FUNCTION iam.assert_consent_grant_matches_offer(uuid)
TO iam_app;
