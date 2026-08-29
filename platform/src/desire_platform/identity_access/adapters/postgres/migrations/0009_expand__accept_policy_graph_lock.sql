CREATE POLICY rls_accept_lock_invitation_definer
ON iam.access_invitations
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND id = NULLIF(
        current_setting('app.target_invitation_id', true),
        ''
    )::uuid
);

CREATE POLICY rls_accept_lock_selector_definer
ON iam.policy_selectors
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_accept_lock_bundle_definer
ON iam.policy_bundles
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
    AND id = (
        SELECT selector.current_bundle_id
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = decode(
            NULLIF(
                current_setting('app.policy_selector_digest', true),
                ''
            ),
            'hex'
        )
    )
);

CREATE POLICY rls_accept_lock_bundle_document_definer
ON iam.policy_bundle_documents
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND bundle_id = (
        SELECT selector.current_bundle_id
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = decode(
            NULLIF(
                current_setting('app.policy_selector_digest', true),
                ''
            ),
            'hex'
        )
    )
);

CREATE POLICY rls_accept_lock_document_definer
ON iam.policy_documents
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        WHERE membership.document_id = policy_documents.id
          AND membership.bundle_id = (
              SELECT selector.current_bundle_id
              FROM iam.policy_selectors AS selector
              WHERE selector.selector_digest = decode(
                  NULLIF(
                      current_setting('app.policy_selector_digest', true),
                      ''
                  ),
                  'hex'
              )
          )
    )
);

CREATE POLICY rls_accept_lock_offer_definer
ON iam.consent_offers
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND bundle_id = (
        SELECT selector.current_bundle_id
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = decode(
            NULLIF(
                current_setting('app.policy_selector_digest', true),
                ''
            ),
            'hex'
        )
    )
);

CREATE POLICY rls_accept_lock_offer_category_definer
ON iam.consent_offer_data_categories
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
          AND offer.bundle_id = (
              SELECT selector.current_bundle_id
              FROM iam.policy_selectors AS selector
              WHERE selector.selector_digest = decode(
                  NULLIF(
                      current_setting('app.policy_selector_digest', true),
                      ''
                  ),
                  'hex'
              )
          )
    )
);

CREATE FUNCTION iam.lock_accept_policy_graph_v1(
    exact_invitation_id uuid,
    exact_selector_digest bytea,
    candidate_bundle_id uuid
)
RETURNS TABLE (
    access_purpose text,
    scope_type text,
    target_role text,
    current_bundle_id uuid,
    bundle_status text,
    bundle_effective_at timestamptz,
    bundle_effective_until timestamptz,
    bundle_documents jsonb,
    consent_offers jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    locked_invitation iam.access_invitations%ROWTYPE;
    locked_selector iam.policy_selectors%ROWTYPE;
    locked_bundle iam.policy_bundles%ROWTYPE;
    locked_bundle_documents jsonb;
    locked_consent_offers jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'ACCEPT'
       OR NULLIF(current_setting('app.target_invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.policy_selector_digest', true), '')
            IS DISTINCT FROM encode(exact_selector_digest, 'hex')
       OR NULLIF(current_setting('app.policy_bundle_id', true), '')
            IS DISTINCT FROM candidate_bundle_id::text
       OR exact_invitation_id IS NULL
       OR exact_selector_digest IS NULL
       OR octet_length(exact_selector_digest) <> 32
       OR candidate_bundle_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_accept_policy_lock_scope',
            MESSAGE = 'Accept policy lock scope is invalid';
    END IF;

    SELECT invitation.*
    INTO locked_invitation
    FROM iam.access_invitations AS invitation
    WHERE invitation.id = exact_invitation_id
    FOR UPDATE;

    IF NOT FOUND
       OR locked_invitation.status <> 'ISSUED'
       OR locked_invitation.policy_selector_digest <> exact_selector_digest THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_accept_policy_lock_invitation',
            MESSAGE = 'Accept policy lock invitation is unavailable';
    END IF;

    SELECT selector.*
    INTO locked_selector
    FROM iam.policy_selectors AS selector
    WHERE selector.selector_digest = exact_selector_digest
    FOR UPDATE;

    IF NOT FOUND OR locked_selector.current_bundle_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_accept_policy_lock_selector',
            MESSAGE = 'Accept policy selector is unavailable';
    END IF;

    SELECT bundle.*
    INTO locked_bundle
    FROM iam.policy_bundles AS bundle
    WHERE bundle.id = locked_selector.current_bundle_id
      AND bundle.selector_digest = exact_selector_digest
    FOR UPDATE;

    IF NOT FOUND
       OR locked_bundle.status <> 'ACTIVE'
       OR locked_bundle.effective_at IS NULL
       OR locked_bundle.effective_at > transaction_timestamp()
       OR (
           locked_bundle.effective_until IS NOT NULL
           AND transaction_timestamp() >= locked_bundle.effective_until
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_accept_policy_lock_bundle',
            MESSAGE = 'Accept current policy bundle is unavailable';
    END IF;

    PERFORM membership.document_id
    FROM iam.policy_bundle_documents AS membership
    WHERE membership.bundle_id = locked_bundle.id
    ORDER BY membership.document_id
    FOR UPDATE;

    PERFORM document.id
    FROM iam.policy_documents AS document
    JOIN iam.policy_bundle_documents AS membership
      ON membership.document_id = document.id
     AND membership.bundle_id = locked_bundle.id
    ORDER BY document.id
    FOR UPDATE OF document;

    PERFORM offer.id
    FROM iam.consent_offers AS offer
    WHERE offer.bundle_id = locked_bundle.id
    ORDER BY offer.id
    FOR UPDATE;

    PERFORM category.offer_id, category.position
    FROM iam.consent_offer_data_categories AS category
    JOIN iam.consent_offers AS offer
      ON offer.id = category.offer_id
     AND offer.bundle_id = locked_bundle.id
    ORDER BY category.offer_id, category.position
    FOR UPDATE OF category;

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
            )
            ORDER BY membership.position, document.id
        ),
        '[]'::jsonb
    )
    INTO locked_bundle_documents
    FROM iam.policy_bundle_documents AS membership
    JOIN iam.policy_documents AS document
      ON document.id = membership.document_id
    WHERE membership.bundle_id = locked_bundle.id
    ;

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
                'supporting_document_status', document.status,
                'supporting_document_kind', document.kind,
                'supporting_document_legal_effect', document.legal_effect,
                'categories', COALESCE(
                    (
                        SELECT jsonb_agg(category.category ORDER BY category.position)
                        FROM iam.consent_offer_data_categories AS category
                        WHERE category.offer_id = offer.id
                    ),
                    '[]'::jsonb
                )
            )
            ORDER BY offer.id
        ),
        '[]'::jsonb
    )
    INTO locked_consent_offers
    FROM iam.consent_offers AS offer
    JOIN iam.policy_documents AS document
      ON document.id = offer.document_id
    WHERE offer.bundle_id = locked_bundle.id;

    access_purpose := locked_selector.access_purpose;
    scope_type := locked_selector.scope_type;
    target_role := locked_selector.target_role;
    current_bundle_id := locked_bundle.id;
    bundle_status := locked_bundle.status;
    bundle_effective_at := locked_bundle.effective_at;
    bundle_effective_until := locked_bundle.effective_until;
    bundle_documents := locked_bundle_documents;
    consent_offers := locked_consent_offers;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION iam.lock_accept_policy_graph_v1(uuid, bytea, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.lock_accept_policy_graph_v1(uuid, bytea, uuid)
    TO iam_onboarding;
