-- IAM 0029: align PostgreSQL policy-consent evidence with the closed domain.
-- Required documents may be NOTICE_ACKNOWLEDGEMENT or CONTRACT_ACCEPTANCE.
-- IAM 0014 remains byte-frozen; CONSENT_TEXT remains outside this path.

CREATE OR REPLACE FUNCTION iam.lock_policy_consent_self_v1(
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
                      AND source_document.legal_effect IN (
                          'NOTICE_ACKNOWLEDGEMENT',
                          'CONTRACT_ACCEPTANCE'
                      )
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


ALTER FUNCTION iam.lock_policy_consent_self_v1(
    uuid, uuid, bytea, text, uuid, uuid, text
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.lock_policy_consent_self_v1(
    uuid, uuid, bytea, text, uuid, uuid, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.lock_policy_consent_self_v1(
    uuid, uuid, bytea, text, uuid, uuid, text
) TO iam_app;

DO $assertions$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam.lock_policy_consent_self_v1(uuid,uuid,bytea,text,uuid,uuid,text)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_onboarding',
        'iam.lock_policy_consent_self_v1(uuid,uuid,bytea,text,uuid,uuid,text)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam.lock_policy_consent_self_v1(uuid,uuid,bytea,text,uuid,uuid,text)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy consent self EXECUTE assertion failed';
    END IF;
END
$assertions$;
