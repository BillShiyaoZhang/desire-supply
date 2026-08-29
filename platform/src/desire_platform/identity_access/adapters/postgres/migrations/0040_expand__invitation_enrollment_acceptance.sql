-- IAM 0040: accept an Organization Invitation from its exact OIDC ENROLLMENT.
--
-- IAM0039 deliberately creates a PENDING_ENROLLMENT User with an ACTIVE
-- ENROLLMENT Session, but the pre-existing browser Accept resolvers admitted
-- only ACTIVE Users and STEP_UP authentication.  Extend those programs only
-- for the same Invitation frozen into the successful ENROLLMENT transaction.

-- Receipt replay authenticates before touching command_receipts.  A pending
-- principal may expose only the AuthTransaction referenced by the exact
-- Session and exact target Invitation installed in the ACCEPT context.
CREATE POLICY rls_accept_receipt_principal_auth_definer_v2
ON iam.auth_transactions
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND NULLIF(current_setting('app.command_name', true), '')
        = 'AcceptAccessInvitation'
    AND NULLIF(current_setting('app.command_version', true), '') = '1'
    AND id::text = NULLIF(
        current_setting('app.auth_transaction_id', true), ''
    )
    AND invitation_id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

-- The formal scope resolver previously needed no User row and its existing
-- AuthTransaction policy intentionally exposes only expected_user_id=actor.
-- Add exact policies for the pending-user check and the one ENROLLMENT row.
CREATE POLICY rls_accept_scope_user_definer_v2
ON iam.users
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_scope_auth_exact_definer_v2
ON iam.auth_transactions
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND id::text = NULLIF(
        current_setting('app.auth_transaction_id', true), ''
    )
    AND invitation_id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

CREATE OR REPLACE FUNCTION iam_api.resolve_accept_receipt_principal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    session_row iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    user_row iam.users%ROWTYPE;
    auth_row iam.auth_transactions%ROWTYPE;
    exact_invitation_id text;
BEGIN
    exact_invitation_id := NULLIF(
        current_setting('app.target_invitation_id', true), ''
    );
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_invitation_id IS NULL
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'ACCEPT'
       OR NULLIF(current_setting('app.command_name', true), '')
            IS DISTINCT FROM 'AcceptAccessInvitation'
       OR NULLIF(current_setting('app.command_version', true), '')
            IS DISTINCT FROM '1'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    SELECT candidate.* INTO session_row
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_session_id
      AND candidate.user_id = exact_actor_user_id;
    IF NOT FOUND
       OR session_row.status <> 'ACTIVE'
       OR transaction_timestamp() >= session_row.idle_expires_at
       OR transaction_timestamp() >= session_row.absolute_expires_at THEN
        RETURN jsonb_build_object('decision_code','AUTHENTICATION_REQUIRED');
    END IF;

    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = session_row.family_id
      AND candidate.user_id = exact_actor_user_id;
    IF NOT FOUND
       OR family_row.status <> 'ACTIVE'
       OR family_row.current_generation <> session_row.generation THEN
        RETURN jsonb_build_object('decision_code','AUTHENTICATION_REQUIRED');
    END IF;

    SELECT candidate.* INTO user_row
    FROM iam.users AS candidate
    WHERE candidate.id = exact_actor_user_id;
    IF NOT FOUND OR user_row.status NOT IN ('ACTIVE','PENDING_ENROLLMENT') THEN
        RETURN jsonb_build_object('decision_code','AUTHENTICATION_REQUIRED');
    END IF;

    -- ACTIVE preserves the existing safe receipt-replay behavior, including
    -- an ordinary current LOGIN and invitation STEP_UP/rotation successors.
    IF user_row.status = 'PENDING_ENROLLMENT' THEN
        IF session_row.rotation_reason <> 'ENROLLMENT'
           OR session_row.verified_for_invitation_id::text
                IS DISTINCT FROM exact_invitation_id
           OR session_row.verified_contact_point_id IS NULL
           OR session_row.verified_at IS NULL
           OR session_row.auth_transaction_id IS NULL THEN
            RETURN jsonb_build_object(
                'decision_code','AUTHENTICATION_REQUIRED'
            );
        END IF;

        PERFORM pg_catalog.set_config(
            'app.auth_transaction_id',
            session_row.auth_transaction_id::text,
            true
        );
        SELECT candidate.* INTO auth_row
        FROM iam.auth_transactions AS candidate
        WHERE candidate.id = session_row.auth_transaction_id
          AND candidate.status = 'SUCCEEDED'
          AND candidate.purpose = 'ENROLLMENT'
          AND candidate.initiating_session_id IS NULL
          AND candidate.initiating_user_id IS NULL
          AND candidate.expected_user_id IS NULL
          AND candidate.invitation_id::text = exact_invitation_id
          AND candidate.expected_contact_point_id
                = session_row.verified_contact_point_id
          AND candidate.succeeded_at IS NOT NULL
          AND transaction_timestamp() < candidate.deadline;
        IF NOT FOUND THEN
            RETURN jsonb_build_object(
                'decision_code','AUTHENTICATION_REQUIRED'
            );
        END IF;
    END IF;

    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED',
        'actor_user_id',exact_actor_user_id::text,
        'session_id',exact_session_id::text,
        'session_family_id',family_row.id::text
    );
END
$function$;

-- Keep the formal v2 entry point and its durable cross-bundle acceptance
-- correction.  Its v1 graph resolver is replaced here with the two exact
-- authentication shapes: existing-User STEP_UP and invitation ENROLLMENT.
CREATE OR REPLACE FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_invitation_id uuid,
    exact_policy_bundle_id uuid,
    exact_selection jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    current_session iam.sessions%ROWTYPE;
    predecessor iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    user_row iam.users%ROWTYPE;
    auth_row iam.auth_transactions%ROWTYPE;
    invitation_row iam.access_invitations%ROWTYPE;
    selector_row iam.policy_selectors%ROWTYPE;
    required_count integer;
    selected_count integer;
    missing_documents jsonb;
    missing_offers jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_invitation_id IS NULL
       OR exact_policy_bundle_id IS NULL
       OR jsonb_typeof(exact_selection) <> 'object'
       OR exact_selection IS NULL
       OR (SELECT array_agg(key ORDER BY key)
           FROM jsonb_object_keys(exact_selection) AS item(key))
            IS DISTINCT FROM ARRAY['consent_choices','policy_acceptances']::text[]
       OR jsonb_typeof(exact_selection->'policy_acceptances') <> 'array'
       OR jsonb_typeof(exact_selection->'consent_choices') <> 'array' THEN
        RETURN jsonb_build_object('decision_code', 'SERVICE_UNAVAILABLE');
    END IF;

    PERFORM pg_catalog.set_config(
        'app.scope_kind', 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE', true
    );
    PERFORM pg_catalog.set_config(
        'app.actor_user_id', exact_actor_user_id::text, true
    );
    PERFORM pg_catalog.set_config(
        'app.target_invitation_id', exact_invitation_id::text, true
    );
    PERFORM pg_catalog.set_config(
        'app.policy_bundle_id', exact_policy_bundle_id::text, true
    );

    SELECT candidate.* INTO current_session
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_session_id
      AND candidate.user_id = exact_actor_user_id
      AND candidate.status = 'ACTIVE'
      AND transaction_timestamp() < candidate.idle_expires_at
      AND transaction_timestamp() < candidate.absolute_expires_at;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code', 'AUTHENTICATION_REQUIRED');
    END IF;

    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = current_session.family_id
      AND candidate.user_id = exact_actor_user_id
      AND candidate.status = 'ACTIVE'
      AND candidate.current_generation = current_session.generation;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code', 'AUTHENTICATION_REQUIRED');
    END IF;

    SELECT candidate.* INTO user_row
    FROM iam.users AS candidate
    WHERE candidate.id = exact_actor_user_id
      AND candidate.status IN ('PENDING_ENROLLMENT','ACTIVE');
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code', 'AUTHENTICATION_REQUIRED');
    END IF;

    IF current_session.rotation_reason IN ('STEP_UP','ENROLLMENT')
       AND current_session.verified_for_invitation_id = exact_invitation_id THEN
        predecessor := current_session;
    ELSIF current_session.rotation_reason = 'INVITATION_ACCEPT'
          AND current_session.predecessor_session_id IS NOT NULL THEN
        SELECT candidate.* INTO predecessor
        FROM iam.sessions AS candidate
        WHERE candidate.id = current_session.predecessor_session_id
          AND candidate.user_id = exact_actor_user_id
          AND candidate.family_id = current_session.family_id
          AND candidate.rotation_reason IN ('STEP_UP','ENROLLMENT')
          AND candidate.verified_for_invitation_id = exact_invitation_id;
    END IF;
    IF predecessor.id IS NULL
       OR predecessor.auth_transaction_id IS NULL
       OR predecessor.verified_contact_point_id IS NULL
       OR predecessor.verified_at IS NULL THEN
        RETURN jsonb_build_object(
            'decision_code', 'ACCESS_INVITATION_UNAVAILABLE'
        );
    END IF;

    PERFORM pg_catalog.set_config(
        'app.auth_transaction_id',
        predecessor.auth_transaction_id::text,
        true
    );
    SELECT candidate.* INTO auth_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = predecessor.auth_transaction_id
      AND candidate.status = 'SUCCEEDED'
      AND candidate.invitation_id = exact_invitation_id
      AND candidate.expected_contact_point_id
            = predecessor.verified_contact_point_id
      AND candidate.succeeded_at IS NOT NULL
      AND transaction_timestamp() < candidate.deadline
      AND (
          (
              predecessor.rotation_reason = 'STEP_UP'
              AND user_row.status = 'ACTIVE'
              AND candidate.purpose = 'STEP_UP'
              AND candidate.expected_user_id = exact_actor_user_id
              AND candidate.initiating_user_id = exact_actor_user_id
          )
          OR (
              predecessor.rotation_reason = 'ENROLLMENT'
              AND user_row.status = 'PENDING_ENROLLMENT'
              AND candidate.purpose = 'ENROLLMENT'
              AND candidate.initiating_session_id IS NULL
              AND candidate.initiating_user_id IS NULL
              AND candidate.expected_user_id IS NULL
          )
      );
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'decision_code', 'ACCESS_INVITATION_UNAVAILABLE'
        );
    END IF;

    SELECT candidate.* INTO invitation_row
    FROM iam.access_invitations AS candidate
    WHERE candidate.id = exact_invitation_id
      AND candidate.purpose = 'ORGANIZATION_MEMBERSHIP'
      AND candidate.organization_id IS NOT NULL
      AND candidate.target_role IN ('ORG_ADMIN','DEMAND_OWNER')
      AND candidate.recipient_contact_id
            = predecessor.verified_contact_point_id
      AND candidate.recipient_contact_id
            = auth_row.expected_contact_point_id
      AND (
          predecessor.rotation_reason = 'STEP_UP'
          OR (
              predecessor.rotation_reason = 'ENROLLMENT'
              AND candidate.target_role = 'DEMAND_OWNER'
              AND NOT candidate.is_initial_admin
          )
      )
      AND (
          (candidate.status = 'ISSUED'
           AND candidate.aggregate_version = auth_row.invitation_version
           AND transaction_timestamp() < candidate.expires_at)
          OR (candidate.status = 'ACCEPTED'
              AND candidate.accepted_by_user_id = exact_actor_user_id)
      );
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'decision_code', 'ACCESS_INVITATION_UNAVAILABLE'
        );
    END IF;

    SELECT selector.* INTO selector_row
    FROM iam.policy_selectors AS selector
    JOIN iam.policy_bundles AS bundle
      ON bundle.id = selector.current_bundle_id
     AND bundle.selector_digest = selector.selector_digest
     AND bundle.status = 'ACTIVE'
     AND bundle.effective_at <= transaction_timestamp()
     AND (
         bundle.effective_until IS NULL
         OR transaction_timestamp() < bundle.effective_until
     )
    WHERE selector.selector_digest = invitation_row.policy_selector_digest
      AND selector.current_bundle_id = exact_policy_bundle_id
      AND selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
      AND selector.scope_type = 'ORGANIZATION_ROLE'
      AND selector.target_role = invitation_row.target_role;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code', 'POLICY_BUNDLE_CHANGED');
    END IF;

    SELECT count(*) INTO required_count
    FROM iam.policy_bundle_documents AS member
    JOIN iam.policy_documents AS document ON document.id = member.document_id
    WHERE member.bundle_id = exact_policy_bundle_id
      AND member.required
      AND document.status = 'ACTIVE'
      AND document.legal_effect IN (
          'NOTICE_ACKNOWLEDGEMENT', 'CONTRACT_ACCEPTANCE'
      );
    SELECT count(*) INTO selected_count
    FROM jsonb_array_elements(exact_selection->'policy_acceptances') AS choice
    JOIN iam.policy_bundle_documents AS member
      ON member.bundle_id = exact_policy_bundle_id
     AND member.document_id = (choice->>'document_id')::uuid
     AND member.required
    JOIN iam.policy_documents AS document
      ON document.id = member.document_id
     AND document.status = 'ACTIVE'
     AND document.legal_effect IN (
         'NOTICE_ACKNOWLEDGEMENT', 'CONTRACT_ACCEPTANCE'
     )
     AND encode(document.content_sha256, 'hex') = choice->>'content_sha256'
    WHERE jsonb_typeof(choice) = 'object'
      AND (SELECT array_agg(key ORDER BY key)
           FROM jsonb_object_keys(choice) AS item(key))
            = ARRAY['content_sha256','document_id']::text[];
    IF required_count = 0
       OR selected_count <> required_count
       OR jsonb_array_length(exact_selection->'policy_acceptances')
            <> required_count THEN
        RETURN jsonb_build_object(
            'decision_code', 'POLICY_CONFIGURATION_UNAVAILABLE'
        );
    END IF;

    SELECT COALESCE(
        jsonb_agg(member.document_id::text ORDER BY member.position),
        '[]'::jsonb
    )
    INTO missing_documents
    FROM iam.policy_bundle_documents AS member
    JOIN iam.policy_documents AS document ON document.id = member.document_id
    WHERE member.bundle_id = exact_policy_bundle_id
      AND member.required
      AND document.legal_effect IN (
          'NOTICE_ACKNOWLEDGEMENT', 'CONTRACT_ACCEPTANCE'
      )
      AND NOT EXISTS (
          SELECT 1 FROM iam.policy_acceptances AS accepted
          WHERE accepted.user_id = exact_actor_user_id
            AND accepted.document_id = document.id
            AND accepted.content_sha256 = document.content_sha256
            AND accepted.bundle_id = exact_policy_bundle_id
      );

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(exact_selection->'consent_choices') AS choice
        LEFT JOIN iam.consent_offers AS offer
          ON offer.id = (choice->>'consent_offer_id')::uuid
         AND offer.bundle_id = exact_policy_bundle_id
         AND offer.document_id = (choice->>'document_id')::uuid
         AND encode(offer.document_content_sha256,'hex')
                = choice->>'content_sha256'
        WHERE jsonb_typeof(choice) <> 'object'
           OR offer.id IS NULL
           OR (SELECT array_agg(key ORDER BY key)
               FROM jsonb_object_keys(choice) AS item(key))
                <> ARRAY['consent_offer_id','content_sha256','document_id']::text[]
    ) THEN
        RETURN jsonb_build_object(
            'decision_code', 'POLICY_CONFIGURATION_UNAVAILABLE'
        );
    END IF;

    SELECT COALESCE(jsonb_agg(offer.id::text ORDER BY offer.id),'[]'::jsonb)
    INTO missing_offers
    FROM jsonb_array_elements(exact_selection->'consent_choices') AS choice
    JOIN iam.consent_offers AS offer
      ON offer.id = (choice->>'consent_offer_id')::uuid
    WHERE NOT EXISTS (
        SELECT 1 FROM iam.consent_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_user_id
          AND grant_row.consent_offer_id = offer.id
          AND grant_row.policy_bundle_id = exact_policy_bundle_id
          AND grant_row.status = 'ACTIVE'
          AND grant_row.expires_at > transaction_timestamp()
    );

    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED',
        'actor_user_id',exact_actor_user_id::text,
        'session_id',exact_session_id::text,
        'session_family_id',current_session.family_id::text,
        'auth_transaction_id',auth_row.id::text,
        'invitation_id',invitation_row.id::text,
        'organization_id',invitation_row.organization_id::text,
        'policy_selector_digest',encode(invitation_row.policy_selector_digest,'hex'),
        'policy_bundle_id',exact_policy_bundle_id::text,
        'current_generation',family_row.current_generation,
        'user_status',user_row.status,
        'target_role',invitation_row.target_role,
        'invitation_status',invitation_row.status,
        'missing_policy_document_ids',missing_documents,
        'missing_consent_offer_ids',missing_offers
    );
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RETURN jsonb_build_object(
            'decision_code', 'POLICY_CONFIGURATION_UNAVAILABLE'
        );
END
$function$;

REVOKE ALL ON FUNCTION iam_api.resolve_accept_receipt_principal_v1(
    uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_accept_receipt_principal_v1(
    uuid,uuid
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
    uuid,uuid,uuid,uuid,jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
    uuid,uuid,uuid,uuid,jsonb
) FROM iam_onboarding;
