-- IAM 0034: fixed ORG_ADMIN management programs and authenticated STEP_UP.

-- STEP_UP has exactly two closed shapes: invitation-bound or generic same-user
-- reauthentication.  Partial invitation coordinates remain impossible.
ALTER TABLE iam.auth_transactions
    DROP CONSTRAINT ck_auth_transaction_purpose_shape;

ALTER TABLE iam.auth_transactions
    ADD CONSTRAINT ck_auth_transaction_purpose_shape CHECK (
        (
            purpose = 'LOGIN'
            AND invitation_id IS NULL
            AND invitation_version IS NULL
            AND expected_contact_point_id IS NULL
            AND (
                (
                    initiating_session_id IS NULL
                    AND initiating_user_id IS NULL
                    AND expected_user_id IS NULL
                )
                OR (
                    initiating_session_id IS NOT NULL
                    AND initiating_user_id IS NOT NULL
                    AND expected_user_id = initiating_user_id
                )
            )
        )
        OR (
            purpose = 'ENROLLMENT'
            AND initiating_session_id IS NULL
            AND initiating_user_id IS NULL
            AND expected_user_id IS NULL
            AND invitation_id IS NOT NULL
            AND invitation_version IS NOT NULL
            AND expected_contact_point_id IS NOT NULL
        )
        OR (
            purpose = 'STEP_UP'
            AND initiating_session_id IS NOT NULL
            AND initiating_user_id IS NOT NULL
            AND expected_user_id = initiating_user_id
            AND (
                (
                    invitation_id IS NOT NULL
                    AND invitation_version IS NOT NULL
                    AND expected_contact_point_id IS NOT NULL
                )
                OR (
                    invitation_id IS NULL
                    AND invitation_version IS NULL
                    AND expected_contact_point_id IS NULL
                )
            )
        )
    );

-- SECURITY DEFINER OIDC completion is limited to one transaction, user and
-- Session family installed by the fixed adapter context.
CREATE POLICY rls_oidc_exact_transaction_definer_v3
ON iam.auth_transactions
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND id::text = NULLIF(
        current_setting('app.auth_transaction_id', true), ''
    )
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.auth_transaction_id', true), '')
);

CREATE POLICY rls_oidc_exact_session_definer_v3
ON iam.sessions
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND (
        id::text = NULLIF(current_setting('app.session_id', true), '')
        OR family_id::text = NULLIF(
            current_setting('app.session_family_id', true), ''
        )
    )
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND family_id::text = NULLIF(
        current_setting('app.session_family_id', true), ''
    )
);

CREATE POLICY rls_oidc_exact_family_definer_v3
ON iam.session_families
FOR ALL TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND id::text = NULLIF(
        current_setting('app.session_family_id', true), ''
    )
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND id::text = NULLIF(
        current_setting('app.session_family_id', true), ''
    )
);

CREATE POLICY rls_oidc_exact_invitation_definer_v3
ON iam.access_invitations
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

-- PostgreSQL requires an UPDATE policy for SELECT ... FOR UPDATE even when
-- the fixed STEP_UP finalizer only locks, rather than mutates, the Invitation.
-- Keep that capability bound to the same single frozen protocol coordinate.
CREATE POLICY rls_oidc_exact_invitation_lock_definer_v3
ON iam.access_invitations
FOR UPDATE TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
)
WITH CHECK (
    id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

CREATE POLICY rls_oidc_exact_contact_definer_v3
ON iam.contact_points
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                  current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.recipient_contact_id = contact_points.id
    )
);

-- Invitation STEP_UP is also the single point where a newly issued,
-- unbound contact becomes verified for the authenticated existing User.
-- PostgreSQL requires a dedicated UPDATE policy for both the row lock and
-- the narrow user/verification binding mutation.
CREATE POLICY rls_oidc_exact_contact_bind_definer_v3
ON iam.contact_points
FOR UPDATE TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                  current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.recipient_contact_id = contact_points.id
    )
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                  current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.recipient_contact_id = contact_points.id
    )
);

CREATE FUNCTION iam_api.resolve_oidc_generic_step_up_session_v1(
    exact_auth_transaction_id uuid,
    exact_expected_user_id uuid,
    exact_initiating_session_id uuid
)
RETURNS TABLE (
    user_id uuid,
    initiating_session_id uuid,
    session_family_id uuid,
    current_generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    transaction_row iam.auth_transactions%ROWTYPE;
    session_row iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_auth_transaction_id IS NULL
       OR exact_expected_user_id IS NULL
       OR exact_initiating_session_id IS NULL
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE'
       OR NULLIF(current_setting('app.auth_transaction_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_expected_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_initiating_session_id::text THEN
        RETURN;
    END IF;

    SELECT candidate.* INTO transaction_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = exact_auth_transaction_id
      AND candidate.protocol_version = 2
      AND candidate.purpose = 'STEP_UP'
      AND candidate.status = 'EXCHANGING'
      AND candidate.aggregate_version = 2
      AND candidate.expected_user_id = exact_expected_user_id
      AND candidate.initiating_user_id = exact_expected_user_id
      AND candidate.initiating_session_id = exact_initiating_session_id
      AND candidate.invitation_id IS NULL
      AND candidate.invitation_version IS NULL
      AND candidate.expected_contact_point_id IS NULL
      AND transaction_timestamp() < candidate.deadline;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT candidate.* INTO session_row
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_initiating_session_id
      AND candidate.user_id = exact_expected_user_id
      AND candidate.status = 'ACTIVE'
      AND transaction_timestamp() < candidate.idle_expires_at
      AND transaction_timestamp() < candidate.absolute_expires_at;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM pg_catalog.set_config(
        'app.session_family_id', session_row.family_id::text, true
    );

    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = session_row.family_id
      AND candidate.user_id = exact_expected_user_id
      AND candidate.status = 'ACTIVE'
      AND candidate.current_generation = session_row.generation;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    user_id := exact_expected_user_id;
    initiating_session_id := exact_initiating_session_id;
    session_family_id := family_row.id;
    current_generation := family_row.current_generation;
    RETURN NEXT;
END
$function$;

-- Single fixed write program for the five public ORG_ADMIN commands.  It
-- resolves retained receipt candidates before any mutation, serializes every
-- write in one Organization, re-proves authority and SafetyHold snapshots
-- under locks, then completes receipt/audit/outbox atomically.
CREATE FUNCTION iam_api.execute_organization_admin_v1(
    exact_operation text,
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_target_id uuid,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_original_actor_id uuid,
    exact_expected_version bigint,
    exact_idempotency_key_digest bytea,
    exact_idempotency_key_digest_key_id text,
    exact_payload_hash bytea,
    exact_payload_hash_key_id text,
    exact_retain_until timestamptz,
    new_audit_event_id uuid,
    new_outbox_event_id uuid,
    new_secondary_outbox_event_id uuid,
    new_recipient_contact_id uuid,
    exact_recipient_binding_digest bytea,
    exact_recipient_binding_digest_key_id text,
    exact_masked_recipient_label text,
    exact_invitation_expires_at timestamptz,
    exact_invitation_token_nonce bytea,
    exact_invitation_token_key_id text,
    exact_invitation_token_format_version text,
    exact_target_role_or_reason_code text,
    exact_resume_hold_action text,
    exact_resume_hold_target_type text,
    exact_resume_hold_target_id uuid,
    exact_resume_hold_target_version bigint,
    exact_resume_hold_organization_id uuid,
    exact_resume_hold_policy_version text,
    exact_resume_hold_evaluated_at timestamptz,
    exact_resume_hold_valid_until timestamptz,
    exact_resume_hold_snapshot_digest bytea,
    exact_idempotency_candidate_key_ids text[],
    exact_idempotency_candidate_digests bytea[],
    exact_payload_candidate_key_ids text[],
    exact_payload_candidate_digests bytea[],
    exact_issue_hold_action text,
    exact_issue_hold_target_type text,
    exact_issue_hold_target_id uuid,
    exact_issue_hold_target_version bigint,
    exact_issue_hold_organization_id uuid,
    exact_issue_hold_policy_version text,
    exact_issue_hold_evaluated_at timestamptz,
    exact_issue_hold_valid_until timestamptz,
    exact_issue_hold_snapshot_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    server_now timestamptz := transaction_timestamp();
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
    existing infra.command_receipts%ROWTYPE;
    receipt_count integer;
    decision text;
    organization_row iam.organizations%ROWTYPE;
    actor_session iam.sessions%ROWTYPE;
    target_invitation iam.access_invitations%ROWTYPE;
    target_membership iam.memberships%ROWTYPE;
    target_user iam.users%ROWTYPE;
    target_grant iam.membership_role_grants%ROWTYPE;
    selector_row iam.policy_selectors%ROWTYPE;
    bundle_row iam.policy_bundles%ROWTYPE;
    snapshot jsonb;
    grant_count integer;
    active_admin_count integer;
    target_is_active_admin boolean;
    before_status text;
    after_status text;
    before_version bigint;
    after_version bigint;
    target_kind text;
    canonical_path text;
    result_schema_name text;
    result_http_status integer;
    result_entity_tag text;
    safe_response jsonb;
    event_type text;
    event_payload jsonb;
    outbox_event jsonb;
    secondary_event_payload jsonb;
    secondary_outbox_event jsonb;
    reconstruction jsonb;
    audit_attributes jsonb := '{}'::jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_operation NOT IN (
            'IssueAccessInvitation','RevokeAccessInvitation',
            'SuspendMembership','ResumeMembership','RevokeMembership'
       )
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_organization_id IS NULL
       OR exact_target_id IS NULL
       OR exact_command_id IS NULL
       OR exact_correlation_id IS NULL
       OR exact_causation_id IS DISTINCT FROM exact_command_id
       OR exact_trace_id IS NULL
       OR exact_expected_version < 1
       OR new_audit_event_id IS NULL
       OR new_outbox_event_id IS NULL
       OR new_audit_event_id = new_outbox_event_id
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_retain_until <= server_now
       OR cardinality(exact_idempotency_candidate_key_ids)
            NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_candidate_digests)
            <> cardinality(exact_idempotency_candidate_key_ids)
       OR cardinality(exact_payload_candidate_key_ids)
            NOT BETWEEN 1 AND 16
       OR cardinality(exact_payload_candidate_digests)
            <> cardinality(exact_payload_candidate_key_ids)
       OR exact_idempotency_candidate_key_ids[1]
            IS DISTINCT FROM exact_idempotency_key_digest_key_id
       OR exact_idempotency_candidate_digests[1]
            IS DISTINCT FROM exact_idempotency_key_digest
       OR exact_payload_candidate_key_ids[1]
            IS DISTINCT FROM exact_payload_hash_key_id
       OR exact_payload_candidate_digests[1]
            IS DISTINCT FROM exact_payload_hash
       OR NOT iam.text_array_is_unique_nonnull(
            exact_idempotency_candidate_key_ids
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_candidate_digests) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_candidate_key_ids) AS item(value)
            WHERE item.value IS NULL OR item.value = ''
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_candidate_digests) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'ORGANIZATION_ADMIN'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_target_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.expected_version', true), '')
            IS DISTINCT FROM exact_expected_version::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_organization_admin_exact_context',
            MESSAGE = 'organization administration context is invalid';
    END IF;

    IF exact_operation = 'IssueAccessInvitation' THEN
        IF exact_target_role_or_reason_code NOT IN ('ORG_ADMIN','DEMAND_OWNER')
           OR new_recipient_contact_id IS NULL
           OR new_recipient_contact_id IN (
                exact_target_id,exact_command_id,new_audit_event_id,
                new_outbox_event_id
           )
           OR octet_length(exact_recipient_binding_digest) <> 32
           OR exact_recipient_binding_digest_key_id IS NULL
           OR exact_masked_recipient_label IS NULL
           OR length(exact_masked_recipient_label) NOT BETWEEN 3 AND 80
           OR exact_invitation_expires_at <= server_now
           OR octet_length(exact_invitation_token_nonce) <> 32
           OR exact_invitation_token_key_id IS NULL
           OR exact_invitation_token_format_version
                <> 'access-invitation-token-v1'
           OR exact_resume_hold_action IS NOT NULL
           OR exact_resume_hold_target_type IS NOT NULL
           OR exact_resume_hold_target_id IS NOT NULL
           OR exact_resume_hold_target_version IS NOT NULL
           OR exact_resume_hold_organization_id IS NOT NULL
           OR exact_resume_hold_policy_version IS NOT NULL
           OR exact_resume_hold_evaluated_at IS NOT NULL
           OR exact_resume_hold_valid_until IS NOT NULL
           OR exact_resume_hold_snapshot_digest IS NOT NULL THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
    ELSE
        IF new_recipient_contact_id IS NOT NULL
           OR exact_recipient_binding_digest IS NOT NULL
           OR exact_recipient_binding_digest_key_id IS NOT NULL
           OR exact_masked_recipient_label IS NOT NULL
           OR exact_invitation_expires_at IS NOT NULL
           OR exact_invitation_token_nonce IS NOT NULL
           OR exact_invitation_token_key_id IS NOT NULL
           OR exact_invitation_token_format_version IS NOT NULL
           OR exact_target_role_or_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
           OR exact_issue_hold_action IS NOT NULL
           OR exact_issue_hold_target_type IS NOT NULL
           OR exact_issue_hold_target_id IS NOT NULL
           OR exact_issue_hold_target_version IS NOT NULL
           OR exact_issue_hold_organization_id IS NOT NULL
           OR exact_issue_hold_policy_version IS NOT NULL
           OR exact_issue_hold_evaluated_at IS NOT NULL
           OR exact_issue_hold_valid_until IS NOT NULL
           OR exact_issue_hold_snapshot_digest IS NOT NULL THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        IF exact_operation <> 'ResumeMembership' AND (
            exact_resume_hold_action IS NOT NULL
            OR exact_resume_hold_target_type IS NOT NULL
            OR exact_resume_hold_target_id IS NOT NULL
            OR exact_resume_hold_target_version IS NOT NULL
            OR exact_resume_hold_organization_id IS NOT NULL
            OR exact_resume_hold_policy_version IS NOT NULL
            OR exact_resume_hold_evaluated_at IS NOT NULL
            OR exact_resume_hold_valid_until IS NOT NULL
            OR exact_resume_hold_snapshot_digest IS NOT NULL
        ) THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
    END IF;

    IF (
        exact_operation = 'RevokeMembership'
        AND (
            new_secondary_outbox_event_id IS NULL
            OR new_secondary_outbox_event_id IN (
                exact_target_id,exact_command_id,new_audit_event_id,
                new_outbox_event_id
            )
        )
    ) OR (
        exact_operation <> 'RevokeMembership'
        AND new_secondary_outbox_event_id IS NOT NULL
    ) THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key
    FOR UPDATE;
    IF NOT FOUND
       OR key_policy.active_canonicalization_version
            <> 'restricted-canonical-json-v1'
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_idempotency_candidate_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_idempotency_key_ids) AS item(value)
          )
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_payload_candidate_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_payload_hash_key_ids) AS item(value)
          ) THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    -- The public target resolver uses an earlier read-only transaction.  Lock
    -- and re-prove the current principal and ORG_ADMIN authority before any
    -- completed receipt can be disclosed.  Exact replay deliberately does
    -- not re-check the target's current business state: the receipt binds the
    -- historical outcome, while this graph proves who may read it now.
    SELECT * INTO organization_row
    FROM iam.organizations
    WHERE id = exact_organization_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
    END IF;
    PERFORM id FROM iam.memberships
    WHERE organization_id = exact_organization_id
    ORDER BY id FOR UPDATE;
    PERFORM id FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
    ORDER BY id FOR UPDATE;
    SELECT * INTO actor_session
    FROM iam.sessions
    WHERE id = exact_session_id AND user_id = exact_actor_user_id
    FOR UPDATE;
    PERFORM id FROM iam.session_families
    WHERE id = actor_session.family_id AND user_id = exact_actor_user_id
    FOR UPDATE;
    PERFORM id FROM iam.users
    WHERE id = exact_actor_user_id
    FOR UPDATE;
    decision := iam_api.organization_admin_authority_decision_v1(
        exact_actor_user_id,exact_session_id,exact_organization_id,true
    );
    IF decision <> 'AUTHORIZED' THEN
        RETURN jsonb_build_object('decision_code',decision);
    END IF;

    SELECT count(*) INTO receipt_count
    FROM infra.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_name IN (
          'IssueAccessInvitation','RevokeAccessInvitation',
          'SuspendMembership','ResumeMembership','RevokeMembership'
      )
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(
              exact_idempotency_candidate_digests, 1
          ) AS slot(index)
          WHERE exact_idempotency_candidate_key_ids[slot.index]
                    = receipt.idempotency_key_digest_key_id
            AND exact_idempotency_candidate_digests[slot.index]
                    = receipt.idempotency_key_digest
      );
    IF receipt_count > 1 THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    ELSIF receipt_count = 1 THEN
        SELECT receipt.* INTO existing
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_name IN (
              'IssueAccessInvitation','RevokeAccessInvitation',
              'SuspendMembership','ResumeMembership','RevokeMembership'
          )
          AND receipt.command_version = 1
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_candidate_digests, 1
              ) AS slot(index)
              WHERE exact_idempotency_candidate_key_ids[slot.index]
                        = receipt.idempotency_key_digest_key_id
                AND exact_idempotency_candidate_digests[slot.index]
                        = receipt.idempotency_key_digest
          )
        ORDER BY receipt.id
        LIMIT 1
        FOR UPDATE;
        IF NOT EXISTS (
            SELECT 1
            FROM generate_subscripts(
                exact_payload_candidate_digests, 1
            ) AS slot(index)
            WHERE exact_payload_candidate_key_ids[slot.index]
                      = existing.payload_hash_key_id
              AND exact_payload_candidate_digests[slot.index]
                      = existing.payload_hash
        ) OR existing.command_name <> exact_operation
             OR existing.if_match_version <> exact_expected_version THEN
            RETURN jsonb_build_object('decision_code','IDEMPOTENCY_KEY_REUSED');
        END IF;
        IF existing.status = 'IN_PROGRESS' THEN
            RETURN jsonb_build_object('decision_code','COMMAND_IN_PROGRESS');
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.response_schema_version <> 1
           OR existing.reconstruction_metadata IS NOT NULL
           OR existing.safe_response_body IS NULL
           OR existing.response_entity_tag
                <> existing.safe_response_body->>'entity_tag'
           OR existing.retain_until <= server_now THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        IF exact_operation = 'IssueAccessInvitation' THEN
            IF existing.target_kind <> 'AccessInvitation'
               OR existing.http_method <> 'POST'
               OR existing.canonical_path <> '/v1/organizations/'
                    || exact_organization_id::text || '/access-invitations'
               OR existing.response_schema_name <> 'AccessInvitationAdminDto'
               OR existing.response_http_status <> 201
               OR existing.safe_response_body->>'organization_id'
                    <> exact_organization_id::text
               OR existing.safe_response_body->>'target_role'
                    <> exact_target_role_or_reason_code THEN
                RETURN jsonb_build_object(
                    'decision_code','IDEMPOTENCY_KEY_REUSED'
                );
            END IF;
            SELECT * INTO target_invitation
            FROM iam.access_invitations
            WHERE id = existing.target_id
              AND organization_id = exact_organization_id;
            IF NOT FOUND
               OR target_invitation.id::text
                    <> existing.safe_response_body->>'invitation_id'
               OR target_invitation.token_key_id IS NULL
               OR octet_length(target_invitation.token_nonce) <> 32 THEN
                RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
            END IF;
            reconstruction := jsonb_build_object(
                'nonce',encode(target_invitation.token_nonce,'hex'),
                'token_key_id',target_invitation.token_key_id,
                'token_format_version','access-invitation-token-v1',
                'expires_at',target_invitation.expires_at
            );
        ELSE
            IF existing.target_kind <> (CASE
                    WHEN exact_operation = 'RevokeAccessInvitation'
                        THEN 'AccessInvitation'
                    ELSE 'Membership'
                END)
               OR existing.target_id <> exact_target_id
               OR existing.http_method <> 'POST'
               OR existing.canonical_path <> (CASE exact_operation
                    WHEN 'RevokeAccessInvitation' THEN
                        '/v1/access-invitations/' || exact_target_id::text
                            || '/revoke'
                    WHEN 'SuspendMembership' THEN
                        '/v1/memberships/' || exact_target_id::text || '/suspend'
                    WHEN 'ResumeMembership' THEN
                        '/v1/memberships/' || exact_target_id::text || '/resume'
                    ELSE '/v1/memberships/' || exact_target_id::text || '/revoke'
                END)
               OR existing.safe_response_body->>'organization_id'
                    <> exact_organization_id::text THEN
                RETURN jsonb_build_object(
                    'decision_code','IDEMPOTENCY_KEY_REUSED'
                );
            END IF;
            reconstruction := NULL;
        END IF;
        RETURN jsonb_build_object(
            'decision_code','AUTHORIZED','replayed',true,
            'safe_response',existing.safe_response_body,
            'response_entity_tag',existing.response_entity_tag,
            'outbox_event',NULL,
            'capability_reconstruction',reconstruction
        );
    END IF;

    -- A receipt miss may write only with the database's exact current active
    -- receipt policy.  This prevents mixed-version runtime nodes from creating
    -- two receipts for one raw key during rotation.
    IF exact_idempotency_key_digest_key_id
            <> key_policy.active_idempotency_key_id
       OR exact_payload_hash_key_id <> key_policy.active_payload_hash_key_id THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    IF exact_operation = 'IssueAccessInvitation' THEN
        PERFORM selector.selector_digest
        FROM iam.policy_selectors AS selector
        WHERE selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
          AND selector.scope_type = 'ORGANIZATION_ROLE'
          AND selector.target_role = exact_target_role_or_reason_code
          AND selector.jurisdiction = organization_row.jurisdiction
        ORDER BY selector.selector_digest FOR UPDATE;
        PERFORM bundle.id
        FROM iam.policy_bundles AS bundle
        JOIN iam.policy_selectors AS selector
          ON selector.current_bundle_id = bundle.id
        WHERE selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
          AND selector.scope_type = 'ORGANIZATION_ROLE'
          AND selector.target_role = exact_target_role_or_reason_code
          AND selector.jurisdiction = organization_row.jurisdiction
        ORDER BY bundle.id FOR UPDATE OF bundle;
        snapshot := iam_api.organization_admin_issue_snapshot_v1(
            exact_actor_user_id,exact_session_id,exact_organization_id,
            exact_target_role_or_reason_code
        );
        IF snapshot->>'decision_code' <> 'AUTHORIZED' THEN RETURN snapshot; END IF;
        IF exact_issue_hold_action IS NULL
           OR exact_issue_hold_target_type IS NULL
           OR exact_issue_hold_target_id IS NULL
           OR exact_issue_hold_target_version IS NULL
           OR exact_issue_hold_organization_id IS NULL
           OR exact_issue_hold_policy_version IS NULL
           OR exact_issue_hold_evaluated_at IS NULL
           OR exact_issue_hold_valid_until IS NULL
           OR octet_length(exact_issue_hold_snapshot_digest) <> 32 THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        IF exact_issue_hold_action <> 'IssueAccessInvitation'
           OR exact_issue_hold_target_type <> 'AccessInvitation'
           OR exact_issue_hold_target_id <> exact_target_id
           OR exact_issue_hold_target_version <> 1
           OR exact_issue_hold_organization_id <> exact_organization_id
           OR exact_issue_hold_evaluated_at > server_now
           OR server_now >= exact_issue_hold_valid_until THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        IF (snapshot->>'target_version')::bigint <> exact_expected_version
           OR exact_issue_hold_snapshot_digest
                <> decode(snapshot->>'snapshot_digest','hex') THEN
            RETURN jsonb_build_object('decision_code','SAFETY_DECISION_STALE');
        END IF;
        SELECT * INTO selector_row FROM iam.policy_selectors
        WHERE selector_digest = decode(
            snapshot->>'policy_selector_digest','hex'
        );
        SELECT * INTO bundle_row FROM iam.policy_bundles
        WHERE id = (snapshot->>'policy_bundle_id')::uuid;
        IF organization_row.aggregate_version <> exact_expected_version THEN
            RETURN jsonb_build_object('decision_code','SAFETY_DECISION_STALE');
        END IF;
        before_status := NULL;
        after_status := 'ISSUED';
        before_version := NULL;
        after_version := 1;
        target_kind := 'AccessInvitation';
        canonical_path := '/v1/organizations/' || exact_organization_id::text
            || '/access-invitations';
        result_schema_name := 'AccessInvitationAdminDto';
        result_http_status := 201;
        result_entity_tag := '"v1"';

        INSERT INTO iam.contact_points (
            id,user_id,contact_type,locator_ciphertext,
            locator_encryption_key_id,locator_encryption_algorithm,
            binding_digest,binding_digest_key_id,verified_at,retention_until,
            created_at,updated_at
        ) VALUES (
            new_recipient_contact_id,NULL,'EMAIL',NULL,NULL,NULL,
            exact_recipient_binding_digest,
            exact_recipient_binding_digest_key_id,NULL,
            exact_invitation_expires_at,server_now,server_now
        );
        INSERT INTO iam.access_invitations (
            id,purpose,organization_id,target_scope,target_role,
            is_initial_admin,recipient_contact_id,masked_recipient_label,
            policy_selector_digest,issued_policy_bundle_id,status,expires_at,
            issuer_kind,issuer_user_id,token_nonce,token_key_id,
            accepted_by_user_id,terminal_at,terminal_reason_code,
            aggregate_version,created_at,updated_at
        ) VALUES (
            exact_target_id,'ORGANIZATION_MEMBERSHIP',exact_organization_id,
            'ORGANIZATION',exact_target_role_or_reason_code,false,
            new_recipient_contact_id,exact_masked_recipient_label,
            selector_row.selector_digest,bundle_row.id,'ISSUED',
            exact_invitation_expires_at,'USER',exact_actor_user_id,
            exact_invitation_token_nonce,exact_invitation_token_key_id,
            NULL,NULL,NULL,1,server_now,server_now
        );
        safe_response := jsonb_build_object(
            'invitation_id',exact_target_id::text,
            'purpose','ORGANIZATION_MEMBERSHIP',
            'organization_id',exact_organization_id::text,
            'target_role',exact_target_role_or_reason_code,
            'masked_recipient_label',exact_masked_recipient_label,
            'is_initial_admin',false,'status','ISSUED',
            'expires_at',exact_invitation_expires_at,'created_at',server_now,
            'required_policy_bundle_id',bundle_row.id::text,
            'aggregate_version',1,'entity_tag',result_entity_tag
        );
        event_type := 'AccessInvitationIssued';
        event_payload := jsonb_build_object(
            'invitation_binding',jsonb_build_object(
                'invitation_id',exact_target_id::text,
                'bound_invitation_version',1,
                'issued_policy_bundle_id',bundle_row.id::text,
                'purpose','ORGANIZATION_MEMBERSHIP',
                'target_scope','ORGANIZATION',
                'target_role',exact_target_role_or_reason_code,
                'is_initial_admin',false
            ),
            'status','ISSUED','expires_at',exact_invitation_expires_at
        );
        audit_attributes := jsonb_build_object(
            'safety_hold',jsonb_build_object(
                'action',exact_issue_hold_action,
                'target_type',exact_issue_hold_target_type,
                'target_id',exact_issue_hold_target_id::text,
                'target_version',exact_issue_hold_target_version,
                'organization_id',exact_issue_hold_organization_id::text,
                'policy_version',exact_issue_hold_policy_version,
                'evaluated_at',exact_issue_hold_evaluated_at,
                'valid_until',exact_issue_hold_valid_until,
                'snapshot_digest',encode(
                    exact_issue_hold_snapshot_digest,'hex'
                )
            )
        );
        reconstruction := jsonb_build_object(
            'nonce',encode(exact_invitation_token_nonce,'hex'),
            'token_key_id',exact_invitation_token_key_id,
            'token_format_version','access-invitation-token-v1',
            'expires_at',exact_invitation_expires_at
        );
    ELSIF exact_operation = 'RevokeAccessInvitation' THEN
        SELECT * INTO target_invitation
        FROM iam.access_invitations
        WHERE id = exact_target_id
          AND organization_id = exact_organization_id
          AND purpose = 'ORGANIZATION_MEMBERSHIP'
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
        END IF;
        IF target_invitation.status <> 'ISSUED' THEN
            RETURN jsonb_build_object('decision_code','INVALID_STATE_TRANSITION');
        END IF;
        IF target_invitation.aggregate_version <> exact_expected_version THEN
            RETURN jsonb_build_object('decision_code','PRECONDITION_FAILED');
        END IF;
        SELECT * INTO selector_row FROM iam.policy_selectors
        WHERE selector_digest = target_invitation.policy_selector_digest
        FOR UPDATE;
        IF NOT FOUND OR selector_row.current_bundle_id IS NULL THEN
            RETURN jsonb_build_object(
                'decision_code','POLICY_CONFIGURATION_UNAVAILABLE'
            );
        END IF;
        SELECT * INTO bundle_row FROM iam.policy_bundles
        WHERE id = selector_row.current_bundle_id
          AND selector_digest = selector_row.selector_digest
          AND status = 'ACTIVE'
          AND effective_at <= server_now
          AND (effective_until IS NULL OR server_now < effective_until)
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN jsonb_build_object(
                'decision_code','POLICY_CONFIGURATION_UNAVAILABLE'
            );
        END IF;
        before_status := target_invitation.status;
        before_version := target_invitation.aggregate_version;
        after_status := 'REVOKED';
        after_version := before_version + 1;
        UPDATE iam.access_invitations
        SET status='REVOKED',terminal_at=server_now,
            terminal_reason_code=exact_target_role_or_reason_code,
            aggregate_version=after_version,updated_at=server_now
        WHERE id=exact_target_id;
        target_kind := 'AccessInvitation';
        canonical_path := '/v1/access-invitations/'
            || exact_target_id::text || '/revoke';
        result_schema_name := 'AccessInvitationAdminDto';
        result_http_status := 200;
        result_entity_tag := '"v' || after_version::text || '"';
        safe_response := jsonb_build_object(
            'invitation_id',target_invitation.id::text,
            'purpose',target_invitation.purpose,
            'organization_id',target_invitation.organization_id::text,
            'target_role',target_invitation.target_role,
            'masked_recipient_label',target_invitation.masked_recipient_label,
            'is_initial_admin',target_invitation.is_initial_admin,
            'status','REVOKED','expires_at',target_invitation.expires_at,
            'created_at',target_invitation.created_at,
            'required_policy_bundle_id',bundle_row.id::text,
            'aggregate_version',after_version,
            'entity_tag',result_entity_tag
        );
        event_type := 'AccessInvitationRevoked';
        event_payload := jsonb_build_object(
            'invitation_binding',jsonb_build_object(
                'invitation_id',target_invitation.id::text,
                'bound_invitation_version',before_version,
                'issued_policy_bundle_id',
                    target_invitation.issued_policy_bundle_id::text,
                'purpose',target_invitation.purpose,
                'target_scope',target_invitation.target_scope,
                'target_role',target_invitation.target_role,
                'is_initial_admin',target_invitation.is_initial_admin
            ),'status','REVOKED'
        );
        reconstruction := NULL;
    ELSE
        SELECT * INTO target_membership
        FROM iam.memberships
        WHERE id = exact_target_id
          AND organization_id = exact_organization_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
        END IF;
        SELECT * INTO target_user FROM iam.users
        WHERE id = target_membership.user_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        SELECT count(*) INTO grant_count
        FROM iam.membership_role_grants
        WHERE organization_id = exact_organization_id
          AND membership_id = target_membership.id
          AND user_id = target_membership.user_id
          AND role_code IN ('ORG_ADMIN','DEMAND_OWNER');
        IF grant_count <> 1 THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        SELECT * INTO target_grant
        FROM iam.membership_role_grants
        WHERE organization_id = exact_organization_id
          AND membership_id = target_membership.id
          AND user_id = target_membership.user_id
          AND role_code IN ('ORG_ADMIN','DEMAND_OWNER')
        ORDER BY id LIMIT 1 FOR UPDATE;
        IF exact_operation IN ('ResumeMembership','RevokeMembership')
           AND target_grant.revoked_at IS NOT NULL THEN
            RETURN jsonb_build_object('decision_code','INVALID_STATE_TRANSITION');
        ELSIF exact_operation = 'SuspendMembership'
              AND target_grant.revoked_at IS NOT NULL THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        IF target_membership.user_id = exact_actor_user_id THEN
            RETURN jsonb_build_object(
                'decision_code','SELF_MANAGEMENT_FORBIDDEN'
            );
        END IF;
        IF (
            exact_operation = 'SuspendMembership'
            AND target_membership.status <> 'ACTIVE'
        ) OR (
            exact_operation = 'ResumeMembership'
            AND target_membership.status <> 'SUSPENDED'
        ) OR (
            exact_operation = 'RevokeMembership'
            AND target_membership.status NOT IN ('ACTIVE','SUSPENDED')
        ) THEN
            RETURN jsonb_build_object('decision_code','INVALID_STATE_TRANSITION');
        END IF;
        IF target_membership.aggregate_version <> exact_expected_version THEN
            RETURN jsonb_build_object('decision_code','PRECONDITION_FAILED');
        END IF;
        IF exact_operation IN ('SuspendMembership','RevokeMembership')
           AND target_membership.status = 'ACTIVE'
           AND target_grant.role_code = 'ORG_ADMIN' THEN
            SELECT count(*) INTO active_admin_count
            FROM iam.memberships AS member
            JOIN iam.membership_role_grants AS grant_row
              ON grant_row.organization_id = member.organization_id
             AND grant_row.membership_id = member.id
             AND grant_row.user_id = member.user_id
            WHERE member.organization_id = exact_organization_id
              AND member.status = 'ACTIVE'
              AND grant_row.role_code = 'ORG_ADMIN'
              AND grant_row.revoked_at IS NULL;
            target_is_active_admin := true;
            IF active_admin_count <= 1 THEN
                RETURN jsonb_build_object(
                    'decision_code','LAST_ACTIVE_ORG_ADMIN'
                );
            END IF;
        END IF;
        IF exact_operation = 'ResumeMembership' THEN
            snapshot := iam_api.organization_admin_resume_snapshot_v1(
                exact_actor_user_id,exact_session_id,exact_organization_id,
                exact_target_id
            );
            IF snapshot->>'decision_code' <> 'AUTHORIZED' THEN RETURN snapshot; END IF;
            IF exact_resume_hold_action IS NULL
               OR exact_resume_hold_target_type IS NULL
               OR exact_resume_hold_target_id IS NULL
               OR exact_resume_hold_target_version IS NULL
               OR exact_resume_hold_organization_id IS NULL
               OR exact_resume_hold_policy_version IS NULL
               OR exact_resume_hold_evaluated_at IS NULL
               OR exact_resume_hold_valid_until IS NULL
               OR octet_length(exact_resume_hold_snapshot_digest) <> 32 THEN
                RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
            END IF;
            IF exact_resume_hold_action <> 'ResumeMembership'
               OR exact_resume_hold_target_type <> 'Membership'
               OR exact_resume_hold_target_id <> exact_target_id
               OR exact_resume_hold_target_version <> exact_expected_version
               OR exact_resume_hold_organization_id <> exact_organization_id
               OR exact_resume_hold_evaluated_at > server_now
               OR server_now >= exact_resume_hold_valid_until THEN
                RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
            END IF;
            IF exact_resume_hold_snapshot_digest
                    <> decode(snapshot->>'snapshot_digest','hex') THEN
                RETURN jsonb_build_object(
                    'decision_code','SAFETY_DECISION_STALE'
                );
            END IF;
            audit_attributes := jsonb_build_object(
                'safety_hold',jsonb_build_object(
                    'action',exact_resume_hold_action,
                    'target_type',exact_resume_hold_target_type,
                    'target_id',exact_resume_hold_target_id::text,
                    'target_version',exact_resume_hold_target_version,
                    'organization_id',exact_resume_hold_organization_id::text,
                    'policy_version',exact_resume_hold_policy_version,
                    'evaluated_at',exact_resume_hold_evaluated_at,
                    'valid_until',exact_resume_hold_valid_until,
                    'snapshot_digest',encode(
                        exact_resume_hold_snapshot_digest,'hex'
                    )
                )
            );
        END IF;
        before_status := target_membership.status;
        before_version := target_membership.aggregate_version;
        after_status := CASE exact_operation
            WHEN 'SuspendMembership' THEN 'SUSPENDED'
            WHEN 'ResumeMembership' THEN 'ACTIVE'
            ELSE 'REVOKED'
        END;
        after_version := before_version + 1;
        UPDATE iam.memberships
        SET status=after_status,aggregate_version=after_version,
            updated_at=server_now
        WHERE id=exact_target_id;
        IF exact_operation = 'RevokeMembership' THEN
            UPDATE iam.membership_role_grants
            SET revoked_at=server_now,
                revocation_reason_code=exact_target_role_or_reason_code,
                aggregate_version=aggregate_version+1
            WHERE id=target_grant.id;
        END IF;
        target_kind := 'Membership';
        canonical_path := '/v1/memberships/' || exact_target_id::text
            || CASE exact_operation
                WHEN 'SuspendMembership' THEN '/suspend'
                WHEN 'ResumeMembership' THEN '/resume'
                ELSE '/revoke'
            END;
        result_schema_name := 'MembershipAdminDto';
        result_http_status := 200;
        result_entity_tag := '"v' || after_version::text || '"';
        safe_response := jsonb_build_object(
            'membership_id',target_membership.id::text,
            'organization_id',target_membership.organization_id::text,
            'user_id',target_membership.user_id::text,
            'display_handle',target_user.display_handle,
            'status',after_status,
            'roles',jsonb_build_array(target_grant.role_code),
            'aggregate_version',after_version,
            'entity_tag',result_entity_tag
        );
        event_type := CASE exact_operation
            WHEN 'SuspendMembership' THEN 'MembershipSuspended'
            WHEN 'ResumeMembership' THEN 'MembershipResumed'
            ELSE 'MembershipRevoked'
        END;
        event_payload := jsonb_build_object(
            'membership_id',target_membership.id::text,
            'user_id',target_membership.user_id::text,
            'status',after_status
        );
        IF exact_operation = 'RevokeMembership' THEN
            secondary_event_payload := jsonb_build_object(
                'membership_id',target_membership.id::text,
                'user_id',target_membership.user_id::text,
                'membership_role_grant_id',target_grant.id::text,
                'target_role',target_grant.role_code
            );
        END IF;
        reconstruction := NULL;
    END IF;

    INSERT INTO infra.command_receipts (
        id,principal_kind,principal_id,command_name,command_version,
        idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,
        payload_hash_key_id,canonicalization_version,target_kind,target_id,
        http_method,canonical_path,if_match_version,status,
        response_schema_version,safe_response_body,reconstruction_metadata,
        created_at,retain_until,completed_at,response_http_status,
        response_schema_name,response_entity_tag,current_user_entity_tag
    ) VALUES (
        exact_command_id,'USER',exact_actor_user_id,exact_operation,1,
        exact_idempotency_key_digest,exact_idempotency_key_digest_key_id,
        exact_payload_hash,exact_payload_hash_key_id,
        'restricted-canonical-json-v1',target_kind,exact_target_id,'POST',
        canonical_path,exact_expected_version,'IN_PROGRESS',NULL,NULL,NULL,
        server_now,exact_retain_until,NULL,NULL,NULL,NULL,NULL
    );

    INSERT INTO audit.audit_events (
        event_id,occurred_at,actor_kind,actor_id,original_actor_id,
        action_code,target_kind,target_id,organization_id,before_status,
        after_status,before_version,after_version,role_code,purpose_code,
        reason_code,auth_strength_code,result_code,command_id,correlation_id,
        causation_id,trace_id,safe_attributes
    ) VALUES (
        new_audit_event_id,server_now,'USER',exact_actor_user_id,
        exact_original_actor_id,exact_operation,target_kind,exact_target_id,
        exact_organization_id,before_status,after_status,before_version,
        after_version,
        CASE
            WHEN exact_operation = 'IssueAccessInvitation'
                THEN exact_target_role_or_reason_code
            WHEN target_kind = 'Membership' THEN target_grant.role_code
            ELSE target_invitation.target_role
        END,
        CASE WHEN target_kind = 'AccessInvitation'
            THEN 'ORGANIZATION_MEMBERSHIP' ELSE NULL END,
        CASE WHEN exact_operation = 'IssueAccessInvitation'
            THEN NULL ELSE exact_target_role_or_reason_code END,
        actor_session.acr_code,'SUCCEEDED',exact_command_id,
        exact_correlation_id,exact_causation_id,exact_trace_id,
        audit_attributes
    );

    outbox_event := jsonb_build_object(
        'event_id',new_outbox_event_id::text,'event_type',event_type,
        'schema_version',1,'occurred_at',server_now,
        'aggregate_type',target_kind,
        'aggregate_id',exact_target_id::text,
        'aggregate_version',after_version,'actor_kind','USER',
        'actor_id',exact_actor_user_id::text,
        'original_actor_id',exact_original_actor_id,
        'correlation_id',exact_correlation_id::text,
        'causation_id',exact_causation_id::text,
        'trace_id',exact_trace_id::text,
        'organization_id',exact_organization_id::text,
        'payload',event_payload
    );
    INSERT INTO infra.outbox_events (
        event_id,event_type,schema_version,occurred_at,aggregate_type,
        aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,
        correlation_id,causation_id,trace_id,organization_id,payload,
        delivery_status,attempt_count,available_at,lease_owner,lease_until,
        published_at,last_error_code,created_at
    ) VALUES (
        new_outbox_event_id,event_type,1,server_now,target_kind,
        exact_target_id,after_version,'USER',exact_actor_user_id,
        exact_original_actor_id,exact_correlation_id,exact_causation_id,
        exact_trace_id,exact_organization_id,event_payload,'PENDING',0,
        server_now,NULL,NULL,NULL,NULL,server_now
    );

    IF exact_operation = 'RevokeMembership' THEN
        secondary_outbox_event := jsonb_build_object(
            'event_id',new_secondary_outbox_event_id::text,
            'event_type','MembershipRolesRevoked',
            'schema_version',1,'occurred_at',server_now,
            'aggregate_type','Membership',
            'aggregate_id',exact_target_id::text,
            'aggregate_version',after_version,'actor_kind','USER',
            'actor_id',exact_actor_user_id::text,
            'original_actor_id',exact_original_actor_id,
            'correlation_id',exact_correlation_id::text,
            'causation_id',exact_causation_id::text,
            'trace_id',exact_trace_id::text,
            'organization_id',exact_organization_id::text,
            'payload',secondary_event_payload
        );
        INSERT INTO infra.outbox_events (
            event_id,event_type,schema_version,occurred_at,aggregate_type,
            aggregate_id,aggregate_version,actor_kind,actor_id,
            original_actor_id,correlation_id,causation_id,trace_id,
            organization_id,payload,delivery_status,attempt_count,
            available_at,lease_owner,lease_until,published_at,last_error_code,
            created_at
        ) VALUES (
            new_secondary_outbox_event_id,'MembershipRolesRevoked',1,
            server_now,'Membership',exact_target_id,after_version,'USER',
            exact_actor_user_id,exact_original_actor_id,exact_correlation_id,
            exact_causation_id,exact_trace_id,exact_organization_id,
            secondary_event_payload,'PENDING',0,server_now,NULL,NULL,NULL,NULL,
            server_now
        );
    END IF;

    UPDATE infra.command_receipts
    SET status='COMPLETED',response_schema_version=1,
        safe_response_body=safe_response,reconstruction_metadata=NULL,
        completed_at=server_now,
        response_http_status=result_http_status,
        response_schema_name=result_schema_name,
        response_entity_tag=result_entity_tag,
        current_user_entity_tag=NULL
    WHERE id=exact_command_id;

    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED','replayed',false,
        'safe_response',safe_response,
        'response_entity_tag',result_entity_tag,
        'outbox_event',outbox_event,
        'secondary_outbox_event',secondary_outbox_event,
        'capability_reconstruction',reconstruction
    );
EXCEPTION
    WHEN unique_violation THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
END
$function$;

-- Fixed same-organization administration capability for iam_app.  The
-- schema-owner policies remain bounded by server-installed actor/session/org
-- coordinates; no request body can select an authority role.
ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_organization_admin_response CHECK (
    command_name NOT IN (
        'IssueAccessInvitation','RevokeAccessInvitation',
        'SuspendMembership','ResumeMembership','RevokeMembership'
    )
    OR (
        command_version = 1
        AND principal_kind = 'USER'
        AND http_method = 'POST'
        AND if_match_version >= 1
        AND reconstruction_metadata IS NULL
        AND (
            (
                command_name IN (
                    'IssueAccessInvitation','RevokeAccessInvitation'
                )
                AND target_kind = 'AccessInvitation'
            )
            OR (
                command_name IN (
                    'SuspendMembership','ResumeMembership','RevokeMembership'
                )
                AND target_kind = 'Membership'
            )
        )
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
                AND response_http_status = CASE
                    WHEN command_name = 'IssueAccessInvitation' THEN 201
                    ELSE 200
                END
                AND response_schema_name = CASE
                    WHEN command_name IN (
                        'IssueAccessInvitation','RevokeAccessInvitation'
                    ) THEN 'AccessInvitationAdminDto'
                    ELSE 'MembershipAdminDto'
                END
                AND response_entity_tag ~ '^"v[1-9][0-9]*"$'
                AND current_user_entity_tag IS NULL
                AND safe_response_body->>'entity_tag' = response_entity_tag
                AND safe_response_body->>'aggregate_version'
                    ~ '^[1-9][0-9]*$'
                AND safe_response_body->>(CASE
                    WHEN target_kind = 'AccessInvitation'
                        THEN 'invitation_id'
                    ELSE 'membership_id'
                END) = target_id::text
            )
        )
        AND (
            (
                command_name = 'IssueAccessInvitation'
                AND canonical_path ~ '^/v1/organizations/'
                    '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
                    '[0-9a-f]{4}-[0-9a-f]{12}/access-invitations$'
            )
            OR (
                command_name = 'RevokeAccessInvitation'
                AND canonical_path = '/v1/access-invitations/'
                    || target_id::text || '/revoke'
            )
            OR (
                command_name = 'SuspendMembership'
                AND canonical_path = '/v1/memberships/'
                    || target_id::text || '/suspend'
            )
            OR (
                command_name = 'ResumeMembership'
                AND canonical_path = '/v1/memberships/'
                    || target_id::text || '/resume'
            )
            OR (
                command_name = 'RevokeMembership'
                AND canonical_path = '/v1/memberships/'
                    || target_id::text || '/revoke'
            )
        )
    )
);

CREATE POLICY rls_org_admin_user_definer_v1 ON iam.users
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND (
        id::text = NULLIF(current_setting('app.actor_user_id', true), '')
        OR EXISTS (
            SELECT 1 FROM iam.memberships AS member
            WHERE member.organization_id::text = NULLIF(
                      current_setting('app.organization_id', true), ''
                  )
              AND member.user_id = users.id
        )
    )
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    OR EXISTS (
        SELECT 1 FROM iam.memberships AS member
        WHERE member.organization_id::text = NULLIF(
                  current_setting('app.organization_id', true), ''
              )
          AND member.user_id = users.id
    )
);
CREATE POLICY rls_org_admin_session_definer_v1 ON iam.sessions
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_org_admin_family_definer_v1 ON iam.session_families
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_org_admin_organization_definer_v1 ON iam.organizations
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.organization_id', true), '')
);
CREATE POLICY rls_org_admin_membership_definer_v1 ON iam.memberships
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND (
        id::text = NULLIF(current_setting('app.target_id', true), '')
        OR organization_id::text = NULLIF(
            current_setting('app.organization_id', true), ''
        )
    )
)
WITH CHECK (
    organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
);
CREATE POLICY rls_org_admin_grant_definer_v1 ON iam.membership_role_grants
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
)
WITH CHECK (
    organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
);
CREATE POLICY rls_org_admin_invitation_definer_v1 ON iam.access_invitations
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_TARGET_RESOLVE',
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
    AND (
        id::text = NULLIF(current_setting('app.target_id', true), '')
        OR organization_id::text = NULLIF(
            current_setting('app.organization_id', true), ''
        )
    )
)
WITH CHECK (
    organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
);
CREATE POLICY rls_org_admin_contact_definer_v1 ON iam.contact_points
FOR INSERT TO schema_owner WITH CHECK (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'IssueAccessInvitation'
    AND user_id IS NULL
);
CREATE POLICY rls_org_admin_selector_definer_v1 ON iam.policy_selectors
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE', 'ORGANIZATION_ADMIN'
    )
)
WITH CHECK (true);
CREATE POLICY rls_org_admin_bundle_definer_v1 ON iam.policy_bundles
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE', 'ORGANIZATION_ADMIN'
    )
)
WITH CHECK (true);
CREATE POLICY rls_org_admin_receipt_definer_v1 ON infra.command_receipts
FOR ALL TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE', 'ORGANIZATION_ADMIN'
    )
    AND principal_kind = 'USER'
    AND principal_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
)
WITH CHECK (
    principal_kind = 'USER'
    AND principal_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
);
CREATE POLICY rls_org_admin_key_policy_definer_v1
ON infra.iam_receipt_key_policy
FOR SELECT TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND singleton_key
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'ORGANIZATION_ADMIN_ISSUE_RESOLVE',
        'ORGANIZATION_ADMIN_RESUME_RESOLVE',
        'ORGANIZATION_ADMIN'
    )
);
CREATE POLICY rls_org_admin_key_policy_lock_definer_v1
ON infra.iam_receipt_key_policy
FOR UPDATE TO schema_owner USING (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND singleton_key
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_ADMIN'
)
WITH CHECK (singleton_key);
CREATE POLICY rls_org_admin_audit_definer_v1 ON audit.audit_events
FOR INSERT TO schema_owner WITH CHECK (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_ADMIN'
    AND actor_kind = 'USER'
    AND actor_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND command_id::text = NULLIF(current_setting('app.command_id', true), '')
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
);
CREATE POLICY rls_org_admin_outbox_definer_v1 ON infra.outbox_events
FOR INSERT TO schema_owner WITH CHECK (
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_ADMIN'
    AND actor_kind = 'USER'
    AND actor_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND causation_id::text = NULLIF(current_setting('app.command_id', true), '')
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
);

CREATE FUNCTION iam_api.organization_admin_authority_decision_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    require_recent_mfa boolean
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    session_row iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    actor_status text;
    organization_status text;
    authority_count integer;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_organization_id IS NULL THEN
        RETURN 'SERVICE_UNAVAILABLE';
    END IF;
    SELECT candidate.* INTO session_row
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_session_id
      AND candidate.user_id = exact_actor_user_id;
    IF NOT FOUND OR session_row.status <> 'ACTIVE' THEN
        RETURN 'AUTHENTICATION_REQUIRED';
    END IF;
    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = session_row.family_id
      AND candidate.user_id = exact_actor_user_id;
    IF NOT FOUND OR family_row.status <> 'ACTIVE'
       OR family_row.current_generation <> session_row.generation THEN
        RETURN 'AUTHENTICATION_REQUIRED';
    END IF;
    IF transaction_timestamp() >= session_row.idle_expires_at
       OR transaction_timestamp() >= session_row.absolute_expires_at THEN
        RETURN 'SESSION_EXPIRED';
    END IF;
    SELECT status INTO actor_status FROM iam.users
    WHERE id = exact_actor_user_id;
    IF NOT FOUND OR actor_status <> 'ACTIVE' THEN
        RETURN 'AUTHENTICATION_REQUIRED';
    END IF;
    IF require_recent_mfa AND (
        session_row.auth_time > transaction_timestamp()
        OR session_row.auth_time
            <= transaction_timestamp() - interval '10 minutes'
        OR session_row.acr_code NOT IN (
            'urn:desire:acr:mfa',
            'urn:desire:acr:synthetic-internal-sandbox:mfa'
        )
        OR NOT (
            session_row.amr_codes
            && ARRAY['otp','mfa','webauthn','hwk']::text[]
        )
    ) THEN
        RETURN 'MFA_STEP_UP_REQUIRED';
    END IF;
    SELECT status INTO organization_status FROM iam.organizations
    WHERE id = exact_organization_id;
    IF NOT FOUND OR organization_status <> 'ACTIVE' THEN
        RETURN 'RESOURCE_NOT_FOUND';
    END IF;
    SELECT count(*) INTO authority_count
    FROM iam.memberships AS member
    JOIN iam.membership_role_grants AS grant_row
      ON grant_row.organization_id = member.organization_id
     AND grant_row.membership_id = member.id
     AND grant_row.user_id = member.user_id
    WHERE member.organization_id = exact_organization_id
      AND member.user_id = exact_actor_user_id
      AND member.status = 'ACTIVE'
      AND grant_row.role_code = 'ORG_ADMIN'
      AND grant_row.revoked_at IS NULL;
    IF authority_count = 0 THEN RETURN 'RESOURCE_NOT_FOUND'; END IF;
    IF authority_count <> 1 THEN RETURN 'SERVICE_UNAVAILABLE'; END IF;
    RETURN 'AUTHORIZED';
END
$function$;

CREATE FUNCTION iam_api.resolve_organization_admin_target_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_id uuid,
    exact_operation text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    resolved_organization_id uuid;
    decision text;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_operation NOT IN (
            'RevokeAccessInvitation','SuspendMembership',
            'ResumeMembership','RevokeMembership'
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'ORGANIZATION_ADMIN_TARGET_RESOLVE'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_target_id::text THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    IF exact_operation = 'RevokeAccessInvitation' THEN
        SELECT organization_id INTO resolved_organization_id
        FROM iam.access_invitations
        WHERE id = exact_target_id
          AND purpose = 'ORGANIZATION_MEMBERSHIP'
          AND organization_id IS NOT NULL;
    ELSE
        SELECT organization_id INTO resolved_organization_id
        FROM iam.memberships
        WHERE id = exact_target_id;
    END IF;
    IF resolved_organization_id IS NULL THEN
        RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
    END IF;
    PERFORM pg_catalog.set_config(
        'app.organization_id', resolved_organization_id::text, true
    );
    decision := iam_api.organization_admin_authority_decision_v1(
        exact_actor_user_id,exact_session_id,resolved_organization_id,true
    );
    IF decision <> 'AUTHORIZED' THEN
        RETURN jsonb_build_object('decision_code',decision);
    END IF;
    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED',
        'organization_id',resolved_organization_id::text
    );
END
$function$;

-- Receipt-first Issue snapshot.  The digest covers every authority, Session,
-- organization and role-specific current-policy fact that the write program
-- will lock and recheck after external SafetyHold evaluation.
CREATE FUNCTION iam_api.organization_admin_issue_snapshot_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_target_role text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    actor_session iam.sessions%ROWTYPE;
    actor_family iam.session_families%ROWTYPE;
    actor_user iam.users%ROWTYPE;
    organization_row iam.organizations%ROWTYPE;
    actor_membership iam.memberships%ROWTYPE;
    actor_grant iam.membership_role_grants%ROWTYPE;
    selector_row iam.policy_selectors%ROWTYPE;
    bundle_row iam.policy_bundles%ROWTYPE;
    candidate_count integer;
    facts jsonb;
BEGIN
    IF exact_target_role NOT IN ('ORG_ADMIN','DEMAND_OWNER') THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO actor_session FROM iam.sessions
    WHERE id = exact_session_id AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO actor_family FROM iam.session_families
    WHERE id = actor_session.family_id AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO actor_user FROM iam.users WHERE id = exact_actor_user_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO organization_row FROM iam.organizations
    WHERE id = exact_organization_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
    END IF;
    SELECT * INTO actor_membership FROM iam.memberships
    WHERE organization_id = exact_organization_id
      AND user_id = exact_actor_user_id AND status = 'ACTIVE';
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
    END IF;
    SELECT count(*) INTO candidate_count
    FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
      AND membership_id = actor_membership.id
      AND user_id = exact_actor_user_id
      AND role_code = 'ORG_ADMIN' AND revoked_at IS NULL;
    IF candidate_count = 0 THEN
        RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
    ELSIF candidate_count <> 1 THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO actor_grant
    FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
      AND membership_id = actor_membership.id
      AND user_id = exact_actor_user_id
      AND role_code = 'ORG_ADMIN' AND revoked_at IS NULL
    ORDER BY id LIMIT 1;

    SELECT count(*) INTO candidate_count
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
    WHERE selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
      AND selector.scope_type = 'ORGANIZATION_ROLE'
      AND selector.target_role = exact_target_role
      AND selector.jurisdiction = organization_row.jurisdiction;
    IF candidate_count <> 1 THEN
        RETURN jsonb_build_object(
            'decision_code','POLICY_CONFIGURATION_UNAVAILABLE'
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
    WHERE selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
      AND selector.scope_type = 'ORGANIZATION_ROLE'
      AND selector.target_role = exact_target_role
      AND selector.jurisdiction = organization_row.jurisdiction
    ORDER BY selector.selector_digest
    LIMIT 1;
    SELECT * INTO bundle_row FROM iam.policy_bundles
    WHERE id = selector_row.current_bundle_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'decision_code','POLICY_CONFIGURATION_UNAVAILABLE'
        );
    END IF;

    facts := jsonb_build_object(
        'actor_session',jsonb_build_array(actor_session.id,actor_session.status,
            actor_session.aggregate_version,actor_session.generation,
            actor_session.auth_time,actor_session.acr_code,actor_session.amr_codes,
            actor_session.idle_expires_at,actor_session.absolute_expires_at),
        'actor_family',jsonb_build_array(actor_family.id,actor_family.status,
            actor_family.aggregate_version,actor_family.current_generation),
        'actor_user',jsonb_build_array(actor_user.id,actor_user.status,
            actor_user.aggregate_version),
        'organization',jsonb_build_array(organization_row.id,
            organization_row.status,organization_row.aggregate_version,
            organization_row.jurisdiction),
        'actor_membership',jsonb_build_array(actor_membership.id,
            actor_membership.status,actor_membership.aggregate_version),
        'actor_grant',jsonb_build_array(actor_grant.id,actor_grant.role_code,
            actor_grant.revoked_at,actor_grant.aggregate_version),
        'selector',jsonb_build_array(encode(selector_row.selector_digest,'hex'),
            selector_row.access_purpose,selector_row.scope_type,
            selector_row.target_role,selector_row.jurisdiction,
            selector_row.locale,selector_row.current_bundle_id,
            selector_row.aggregate_version),
        'bundle',jsonb_build_array(bundle_row.id,bundle_row.status,
            bundle_row.effective_at,bundle_row.effective_until,
            bundle_row.aggregate_version)
    );
    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED',
        'target_version',organization_row.aggregate_version,
        'policy_selector_digest',encode(selector_row.selector_digest,'hex'),
        'policy_bundle_id',bundle_row.id::text,
        'snapshot_digest',encode(
            pg_catalog.sha256(pg_catalog.convert_to(facts::text,'UTF8')),'hex'
        )
    );
END
$function$;

CREATE FUNCTION iam_api.resolve_organization_admin_issue_scope_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_idempotency_key_digests bytea[],
    exact_idempotency_key_digest_key_ids text[],
    exact_payload_hashes bytea[],
    exact_payload_hash_key_ids text[],
    exact_target_role text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, iam_api
AS $function$
DECLARE
    decision text;
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
    existing infra.command_receipts%ROWTYPE;
    replay_invitation iam.access_invitations%ROWTYPE;
    receipt_count integer;
    snapshot jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_target_role NOT IN ('ORG_ADMIN','DEMAND_OWNER')
       OR cardinality(exact_idempotency_key_digests) NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hashes) NOT BETWEEN 1 AND 16
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR EXISTS (
            SELECT 1 FROM unnest(exact_idempotency_key_digests) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_payload_hashes) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR NOT iam.text_array_is_unique_nonnull(
            exact_idempotency_key_digest_key_ids
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_payload_hash_key_ids) AS item(value)
            WHERE item.value IS NULL OR item.value = ''
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'ORGANIZATION_ADMIN_ISSUE_RESOLVE'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'IssueAccessInvitation'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_organization_id::text THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key;
    IF NOT FOUND
       OR key_policy.active_canonicalization_version
            <> 'restricted-canonical-json-v1'
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_idempotency_key_ids) AS item(value)
          )
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_payload_hash_key_ids) AS item(value)
          ) THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    decision := iam_api.organization_admin_authority_decision_v1(
        exact_actor_user_id,exact_session_id,exact_organization_id,true
    );
    IF decision <> 'AUTHORIZED' THEN
        RETURN jsonb_build_object('decision_code',decision);
    END IF;

    SELECT count(*) INTO receipt_count
    FROM infra.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_name = 'IssueAccessInvitation'
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(exact_idempotency_key_digests, 1) AS slot(index)
          WHERE exact_idempotency_key_digest_key_ids[slot.index]
                    = receipt.idempotency_key_digest_key_id
            AND exact_idempotency_key_digests[slot.index]
                    = receipt.idempotency_key_digest
      );
    IF receipt_count > 1 THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    ELSIF receipt_count = 1 THEN
        SELECT receipt.* INTO existing
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = 'IssueAccessInvitation'
          AND receipt.command_version = 1
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_key_digests, 1
              ) AS slot(index)
              WHERE exact_idempotency_key_digest_key_ids[slot.index]
                        = receipt.idempotency_key_digest_key_id
                AND exact_idempotency_key_digests[slot.index]
                        = receipt.idempotency_key_digest
          )
        ORDER BY receipt.id
        LIMIT 1;
        IF NOT EXISTS (
            SELECT 1
            FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
            WHERE exact_payload_hash_key_ids[slot.index]
                      = existing.payload_hash_key_id
              AND exact_payload_hashes[slot.index] = existing.payload_hash
        ) THEN
            RETURN jsonb_build_object('decision_code','IDEMPOTENCY_KEY_REUSED');
        END IF;
        IF existing.status = 'IN_PROGRESS' THEN
            RETURN jsonb_build_object('decision_code','COMMAND_IN_PROGRESS');
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.target_kind <> 'AccessInvitation'
           OR existing.http_method <> 'POST'
           OR existing.canonical_path <> '/v1/organizations/'
                || exact_organization_id::text || '/access-invitations'
           OR existing.if_match_version IS NULL
           OR existing.response_schema_version <> 1
           OR existing.response_schema_name <> 'AccessInvitationAdminDto'
           OR existing.response_http_status <> 201
           OR existing.reconstruction_metadata IS NOT NULL
           OR existing.safe_response_body->>'organization_id'
                <> exact_organization_id::text
           OR existing.safe_response_body->>'target_role' <> exact_target_role
           OR existing.safe_response_body->>'invitation_id'
                <> existing.target_id::text
           OR existing.response_entity_tag
                <> existing.safe_response_body->>'entity_tag'
           OR existing.retain_until <= transaction_timestamp() THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        SELECT invitation.* INTO replay_invitation
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = existing.target_id
          AND invitation.organization_id = exact_organization_id;
        IF NOT FOUND
           OR replay_invitation.token_key_id IS NULL
           OR octet_length(replay_invitation.token_nonce) <> 32
           OR replay_invitation.expires_at
                <> (existing.safe_response_body->>'expires_at')::timestamptz
           OR replay_invitation.id::text
                <> existing.safe_response_body->>'invitation_id' THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        RETURN jsonb_build_object(
            'decision_code','REPLAY',
            'organization_id',exact_organization_id::text,
            'target_version',existing.if_match_version,
            'snapshot_digest',encode(
                pg_catalog.sha256(pg_catalog.convert_to(
                    'organization-admin-issue-replay-v1','UTF8'
                )),'hex'
            ),
            'safe_response',existing.safe_response_body,
            'response_entity_tag',existing.response_entity_tag,
            'capability_reconstruction',jsonb_build_object(
                'nonce',encode(replay_invitation.token_nonce,'hex'),
                'token_key_id',replay_invitation.token_key_id,
                'token_format_version','access-invitation-token-v1',
                'expires_at',replay_invitation.expires_at
            )
        );
    END IF;

    snapshot := iam_api.organization_admin_issue_snapshot_v1(
        exact_actor_user_id,exact_session_id,exact_organization_id,
        exact_target_role
    );
    IF snapshot->>'decision_code' <> 'AUTHORIZED' THEN RETURN snapshot; END IF;
    RETURN jsonb_build_object(
        'decision_code','MISS',
        'organization_id',exact_organization_id::text,
        'target_version',(snapshot->>'target_version')::bigint,
        'snapshot_digest',snapshot->>'snapshot_digest'
    );
END
$function$;

CREATE FUNCTION iam_api.organization_admin_resume_snapshot_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_target_membership_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    actor_session iam.sessions%ROWTYPE;
    actor_family iam.session_families%ROWTYPE;
    actor_user iam.users%ROWTYPE;
    organization_row iam.organizations%ROWTYPE;
    actor_membership iam.memberships%ROWTYPE;
    actor_grant iam.membership_role_grants%ROWTYPE;
    target_membership iam.memberships%ROWTYPE;
    target_grant iam.membership_role_grants%ROWTYPE;
    target_user iam.users%ROWTYPE;
    candidate_count integer;
    actor_grant_id uuid;
    target_grant_id uuid;
    facts jsonb;
BEGIN
    SELECT * INTO actor_session FROM iam.sessions
    WHERE id = exact_session_id AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE'); END IF;
    SELECT * INTO actor_family FROM iam.session_families
    WHERE id = actor_session.family_id AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE'); END IF;
    SELECT * INTO actor_user FROM iam.users WHERE id = exact_actor_user_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE'); END IF;
    SELECT * INTO organization_row FROM iam.organizations
    WHERE id = exact_organization_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE'); END IF;
    SELECT * INTO actor_membership FROM iam.memberships
    WHERE organization_id = exact_organization_id
      AND user_id = exact_actor_user_id AND status = 'ACTIVE';
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND'); END IF;
    SELECT count(*) INTO candidate_count
    FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
      AND membership_id = actor_membership.id
      AND user_id = exact_actor_user_id
      AND role_code = 'ORG_ADMIN' AND revoked_at IS NULL;
    IF candidate_count = 0 THEN RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND'); END IF;
    IF candidate_count <> 1 THEN RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE'); END IF;
    SELECT id INTO actor_grant_id
    FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
      AND membership_id = actor_membership.id
      AND user_id = exact_actor_user_id
      AND role_code = 'ORG_ADMIN' AND revoked_at IS NULL
    ORDER BY id
    LIMIT 1;
    SELECT * INTO actor_grant FROM iam.membership_role_grants
    WHERE id = actor_grant_id;
    SELECT * INTO target_membership FROM iam.memberships
    WHERE id = exact_target_membership_id
      AND organization_id = exact_organization_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND'); END IF;
    SELECT count(*) INTO candidate_count
    FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
      AND membership_id = target_membership.id
      AND user_id = target_membership.user_id
      AND role_code IN ('ORG_ADMIN','DEMAND_OWNER');
    IF candidate_count <> 1 THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT id INTO target_grant_id
    FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
      AND membership_id = target_membership.id
      AND user_id = target_membership.user_id
      AND role_code IN ('ORG_ADMIN','DEMAND_OWNER')
    ORDER BY id
    LIMIT 1;
    SELECT * INTO target_grant FROM iam.membership_role_grants
    WHERE id = target_grant_id;
    SELECT * INTO target_user FROM iam.users WHERE id = target_membership.user_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE'); END IF;

    facts := jsonb_build_object(
        'actor_session',jsonb_build_array(actor_session.id,actor_session.status,
            actor_session.aggregate_version,actor_session.generation,
            actor_session.auth_time,actor_session.acr_code,actor_session.amr_codes,
            actor_session.idle_expires_at,actor_session.absolute_expires_at),
        'actor_family',jsonb_build_array(actor_family.id,actor_family.status,
            actor_family.aggregate_version,actor_family.current_generation),
        'actor_user',jsonb_build_array(actor_user.id,actor_user.status,
            actor_user.aggregate_version),
        'organization',jsonb_build_array(organization_row.id,
            organization_row.status,organization_row.aggregate_version),
        'actor_membership',jsonb_build_array(actor_membership.id,
            actor_membership.status,actor_membership.aggregate_version),
        'actor_grant',jsonb_build_array(actor_grant.id,actor_grant.role_code,
            actor_grant.revoked_at,actor_grant.aggregate_version),
        'target_membership',jsonb_build_array(target_membership.id,
            target_membership.organization_id,target_membership.user_id,
            target_membership.status,target_membership.aggregate_version),
        'target_grant',jsonb_build_array(target_grant.id,target_grant.role_code,
            target_grant.revoked_at,target_grant.aggregate_version),
        'target_user',jsonb_build_array(target_user.id,target_user.status,
            target_user.display_handle,target_user.aggregate_version)
    );
    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED',
        'target_version',target_membership.aggregate_version,
        'target_status',target_membership.status,
        'target_role',target_grant.role_code,
        'target_grant_active',(target_grant.revoked_at IS NULL),
        'snapshot_digest',encode(
            pg_catalog.sha256(pg_catalog.convert_to(facts::text,'UTF8')),'hex'
        )
    );
END
$function$;

CREATE FUNCTION iam_api.resolve_organization_admin_resume_scope_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_target_membership_id uuid,
    exact_idempotency_key_digests bytea[],
    exact_idempotency_key_digest_key_ids text[],
    exact_payload_hashes bytea[],
    exact_payload_hash_key_ids text[]
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, iam_api
AS $function$
DECLARE
    decision text;
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
    existing infra.command_receipts%ROWTYPE;
    receipt_count integer;
    snapshot jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR cardinality(exact_idempotency_key_digests) NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hashes) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR EXISTS (
            SELECT 1 FROM unnest(exact_idempotency_key_digests) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR EXISTS (
            SELECT 1 FROM unnest(exact_payload_hashes) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR NOT iam.text_array_is_unique_nonnull(
            exact_idempotency_key_digest_key_ids
       )
       OR NOT iam.text_array_is_unique_nonnull(exact_payload_hash_key_ids)
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'ORGANIZATION_ADMIN_RESUME_RESOLVE'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'ResumeMembership'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_target_membership_id::text THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key;
    IF NOT FOUND
       OR key_policy.active_canonicalization_version
            <> 'restricted-canonical-json-v1'
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_idempotency_key_ids) AS item(value)
          )
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_payload_hash_key_ids) AS item(value)
          ) THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;
    decision := iam_api.organization_admin_authority_decision_v1(
        exact_actor_user_id,exact_session_id,exact_organization_id,true
    );
    IF decision <> 'AUTHORIZED' THEN
        RETURN jsonb_build_object('decision_code',decision);
    END IF;
    SELECT count(*) INTO receipt_count
    FROM infra.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_name = 'ResumeMembership'
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(exact_idempotency_key_digests, 1) AS slot(index)
          WHERE exact_idempotency_key_digest_key_ids[slot.index]
                    = receipt.idempotency_key_digest_key_id
            AND exact_idempotency_key_digests[slot.index]
                    = receipt.idempotency_key_digest
      );
    IF receipt_count > 1 THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    ELSIF receipt_count = 1 THEN
        SELECT receipt.* INTO existing
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = 'ResumeMembership'
          AND receipt.command_version = 1
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_key_digests, 1
              ) AS slot(index)
              WHERE exact_idempotency_key_digest_key_ids[slot.index]
                        = receipt.idempotency_key_digest_key_id
                AND exact_idempotency_key_digests[slot.index]
                        = receipt.idempotency_key_digest
          )
        ORDER BY receipt.id
        LIMIT 1;
        IF NOT EXISTS (
            SELECT 1
            FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
            WHERE exact_payload_hash_key_ids[slot.index]
                      = existing.payload_hash_key_id
              AND exact_payload_hashes[slot.index] = existing.payload_hash
        ) THEN
            RETURN jsonb_build_object('decision_code','IDEMPOTENCY_KEY_REUSED');
        END IF;
        IF existing.status = 'IN_PROGRESS' THEN
            RETURN jsonb_build_object('decision_code','COMMAND_IN_PROGRESS');
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.target_kind <> 'Membership'
           OR existing.target_id <> exact_target_membership_id
           OR existing.http_method <> 'POST'
           OR existing.canonical_path <> '/v1/memberships/'
                || exact_target_membership_id::text || '/resume'
           OR existing.if_match_version IS NULL
           OR existing.response_schema_version <> 1
           OR existing.response_schema_name <> 'MembershipAdminDto'
           OR existing.response_http_status <> 200
           OR existing.reconstruction_metadata IS NOT NULL
           OR existing.safe_response_body->>'membership_id'
                <> exact_target_membership_id::text
           OR existing.safe_response_body->>'organization_id'
                <> exact_organization_id::text
           OR existing.response_entity_tag
                <> existing.safe_response_body->>'entity_tag'
           OR existing.retain_until <= transaction_timestamp() THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        RETURN jsonb_build_object(
            'decision_code','REPLAY',
            'organization_id',exact_organization_id::text,
            'target_version',existing.if_match_version,
            'snapshot_digest',encode(
                pg_catalog.sha256(pg_catalog.convert_to(
                    'organization-admin-resume-replay-v1','UTF8'
                )),'hex'
            )
        );
    END IF;
    snapshot := iam_api.organization_admin_resume_snapshot_v1(
        exact_actor_user_id,exact_session_id,exact_organization_id,
        exact_target_membership_id
    );
    IF snapshot->>'decision_code' <> 'AUTHORIZED' THEN RETURN snapshot; END IF;
    IF existing.id IS NULL AND (
        snapshot->>'target_status' <> 'SUSPENDED'
        OR (snapshot->>'target_grant_active')::boolean IS NOT TRUE
    ) THEN
        RETURN jsonb_build_object('decision_code','INVALID_STATE_TRANSITION');
    END IF;
    RETURN jsonb_build_object(
        'decision_code','MISS',
        'organization_id',exact_organization_id::text,
        'target_version',(snapshot->>'target_version')::bigint,
        'snapshot_digest',snapshot->>'snapshot_digest'
    );
END
$function$;

CREATE FUNCTION iam_api.resolve_oidc_step_up_session_v1(
    exact_auth_transaction_id uuid,
    exact_invitation_id uuid,
    exact_expected_user_id uuid,
    exact_initiating_session_id uuid
)
RETURNS TABLE (
    user_id uuid,
    initiating_session_id uuid,
    session_family_id uuid,
    current_generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    transaction_row iam.auth_transactions%ROWTYPE;
    invitation_row iam.access_invitations%ROWTYPE;
    session_row iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE'
       OR NULLIF(current_setting('app.auth_transaction_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.target_invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_expected_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_initiating_session_id::text THEN
        RETURN;
    END IF;

    SELECT candidate.* INTO transaction_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = exact_auth_transaction_id
      AND candidate.protocol_version = 2
      AND candidate.purpose = 'STEP_UP'
      AND candidate.status = 'EXCHANGING'
      AND candidate.aggregate_version = 2
      AND candidate.expected_user_id = exact_expected_user_id
      AND candidate.initiating_user_id = exact_expected_user_id
      AND candidate.initiating_session_id = exact_initiating_session_id
      AND candidate.invitation_id = exact_invitation_id
      AND transaction_timestamp() < candidate.deadline;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT candidate.* INTO invitation_row
    FROM iam.access_invitations AS candidate
    WHERE candidate.id = exact_invitation_id
      AND candidate.status = 'ISSUED'
      AND candidate.aggregate_version = transaction_row.invitation_version
      AND candidate.recipient_contact_id
            = transaction_row.expected_contact_point_id
      AND transaction_timestamp() < candidate.expires_at;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT candidate.* INTO session_row
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_initiating_session_id
      AND candidate.user_id = exact_expected_user_id
      AND candidate.status = 'ACTIVE'
      AND transaction_timestamp() < candidate.idle_expires_at
      AND transaction_timestamp() < candidate.absolute_expires_at;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_catalog.set_config(
        'app.session_family_id', session_row.family_id::text, true
    );
    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = session_row.family_id
      AND candidate.user_id = exact_expected_user_id
      AND candidate.status = 'ACTIVE'
      AND candidate.current_generation = session_row.generation;
    IF NOT FOUND THEN RETURN; END IF;

    user_id := exact_expected_user_id;
    initiating_session_id := exact_initiating_session_id;
    session_family_id := family_row.id;
    current_generation := family_row.current_generation;
    RETURN NEXT;
END
$function$;

CREATE POLICY rls_oidc_exact_audit_definer_v3
ON audit.audit_events
FOR INSERT TO schema_owner
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND target_kind = 'AuthTransaction'
    AND target_id::text = NULLIF(
        current_setting('app.auth_transaction_id', true), ''
    )
    AND command_id = target_id
    AND causation_id = command_id
);

-- Invitation-bound STEP_UP freezes the exact Invitation/contact tuple at
-- BEGIN and rechecks it under write locks before rotating the Session family.
-- The generic finalizer below is deliberately a different function and cannot
-- consume this protocol shape.
CREATE FUNCTION iam_api.finalize_oidc_invitation_step_up_v1(
    exact_auth_transaction_id uuid,
    exact_exchange_owner_id uuid,
    exact_invitation_id uuid,
    exact_invitation_version bigint,
    exact_expected_contact_point_id uuid,
    exact_expected_contact_type text,
    exact_expected_contact_binding_digest bytea,
    exact_expected_contact_binding_key_id text,
    exact_expected_user_id uuid,
    exact_initiating_session_id uuid,
    exact_session_family_id uuid,
    exact_predecessor_generation bigint,
    exact_provider_issuer text,
    exact_subject_digest bytea,
    exact_subject_digest_key_id text,
    exact_verified_contact_type text,
    exact_verified_contact_binding_digest bytea,
    exact_verified_contact_binding_key_id text,
    new_session_id uuid,
    new_handle_digest bytea,
    new_handle_digest_key_id text,
    new_csrf_salt bytea,
    new_csrf_key_id text,
    new_csrf_digest bytea,
    exact_auth_time timestamptz,
    exact_token_issued_at timestamptz,
    exact_token_expires_at timestamptz,
    exact_acr_code text,
    exact_amr_codes text[],
    new_audit_event_id uuid,
    exact_system_actor_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (
    decision_code text,
    session_id uuid,
    session_family_id uuid,
    user_id uuid,
    user_status text,
    generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, audit
AS $function$
DECLARE
    transaction_row iam.auth_transactions%ROWTYPE;
    invitation_row iam.access_invitations%ROWTYPE;
    contact_row iam.contact_points%ROWTYPE;
    predecessor iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    resolved_user_id uuid;
    resolved_user_status text;
    server_now timestamptz := transaction_timestamp();
    next_generation bigint;
    valid boolean := true;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE'
       OR NULLIF(current_setting('app.auth_transaction_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.target_invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_expected_user_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.session_family_id', true), '')
            IS DISTINCT FROM exact_session_family_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM new_session_id::text
       OR NULLIF(current_setting('app.oidc_subject_issuer', true), '')
            IS DISTINCT FROM exact_provider_issuer
       OR decode(
            NULLIF(current_setting('app.oidc_subject_digest', true), ''), 'hex'
          ) IS DISTINCT FROM exact_subject_digest
       OR NULLIF(current_setting('app.oidc_subject_digest_key_id', true), '')
            IS DISTINCT FROM exact_subject_digest_key_id
       OR exact_invitation_version < 1
       OR exact_predecessor_generation < 1
       OR exact_expected_contact_type <> 'EMAIL'
       OR exact_verified_contact_type <> 'EMAIL'
       OR octet_length(exact_expected_contact_binding_digest) <> 32
       OR octet_length(exact_verified_contact_binding_digest) <> 32
       OR exact_expected_contact_binding_digest
            IS DISTINCT FROM exact_verified_contact_binding_digest
       OR exact_expected_contact_binding_key_id
            IS DISTINCT FROM exact_verified_contact_binding_key_id
       OR octet_length(exact_subject_digest) <> 32
       OR octet_length(new_handle_digest) <> 32
       OR octet_length(new_csrf_salt) <> 32
       OR octet_length(new_csrf_digest) <> 32
       OR exact_token_issued_at >= exact_token_expires_at
       OR exact_auth_time > server_now
       OR exact_token_issued_at > server_now + interval '2 minutes'
       OR exact_token_expires_at <= server_now
       OR cardinality(exact_amr_codes) NOT BETWEEN 1 AND 16
       OR NOT iam.text_array_is_unique_nonnull(exact_amr_codes) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_oidc_invitation_step_up_exact_context',
            MESSAGE = 'invitation STEP_UP context is invalid';
    END IF;

    SELECT candidate.* INTO transaction_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = exact_auth_transaction_id
    FOR UPDATE;
    IF NOT FOUND THEN
        decision_code := 'AUTHENTICATION_REJECTED';
        RETURN NEXT;
        RETURN;
    END IF;

    valid := transaction_row.protocol_version = 2
        AND transaction_row.purpose = 'STEP_UP'
        AND transaction_row.attempt = 1
        AND transaction_row.status = 'EXCHANGING'
        AND transaction_row.aggregate_version = 2
        AND transaction_row.exchange_owner_id = exact_exchange_owner_id
        AND transaction_row.provider_issuer = exact_provider_issuer
        AND transaction_row.expected_user_id = exact_expected_user_id
        AND transaction_row.initiating_user_id = exact_expected_user_id
        AND transaction_row.initiating_session_id
            = exact_initiating_session_id
        AND transaction_row.invitation_id = exact_invitation_id
        AND transaction_row.invitation_version = exact_invitation_version
        AND transaction_row.expected_contact_point_id
            = exact_expected_contact_point_id
        AND server_now < transaction_row.deadline;

    SELECT candidate.* INTO invitation_row
    FROM iam.access_invitations AS candidate
    WHERE candidate.id = exact_invitation_id
    FOR UPDATE;
    valid := valid AND FOUND
        AND invitation_row.status = 'ISSUED'
        AND invitation_row.aggregate_version = exact_invitation_version
        AND invitation_row.recipient_contact_id
            = exact_expected_contact_point_id
        AND server_now < invitation_row.expires_at;

    SELECT candidate.* INTO contact_row
    FROM iam.contact_points AS candidate
    WHERE candidate.id = exact_expected_contact_point_id
    FOR UPDATE;
    valid := valid AND FOUND
        AND contact_row.contact_type = exact_expected_contact_type
        AND contact_row.binding_digest
            = exact_expected_contact_binding_digest
        AND contact_row.binding_digest_key_id
            = exact_expected_contact_binding_key_id
        AND (
            contact_row.user_id IS NULL
            OR contact_row.user_id = exact_expected_user_id
        );

    SELECT candidate.* INTO predecessor
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_initiating_session_id
      AND candidate.user_id = exact_expected_user_id
      AND candidate.family_id = exact_session_family_id
    FOR UPDATE;
    valid := valid AND FOUND
        AND predecessor.status = 'ACTIVE'
        AND predecessor.generation = exact_predecessor_generation
        AND server_now < predecessor.idle_expires_at
        AND server_now < predecessor.absolute_expires_at;

    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = exact_session_family_id
      AND candidate.user_id = exact_expected_user_id
    FOR UPDATE;
    valid := valid AND FOUND
        AND family_row.status = 'ACTIVE'
        AND family_row.current_generation = exact_predecessor_generation;

    SELECT identity.user_id, account.status
    INTO resolved_user_id, resolved_user_status
    FROM iam.external_identities AS identity
    JOIN iam.users AS account ON account.id = identity.user_id
    WHERE identity.issuer = exact_provider_issuer
      AND identity.subject_digest = exact_subject_digest
      AND identity.subject_digest_key_id = exact_subject_digest_key_id
      AND identity.status = 'ACTIVE'
      AND identity.user_id = exact_expected_user_id
      AND account.status = 'ACTIVE'
    FOR UPDATE OF identity, account;
    valid := valid AND FOUND;

    IF NOT valid THEN
        IF transaction_row.id IS NOT NULL
           AND transaction_row.protocol_version = 2
           AND transaction_row.purpose = 'STEP_UP'
           AND transaction_row.attempt = 1
           AND transaction_row.status = 'EXCHANGING'
           AND transaction_row.aggregate_version = 2
           AND transaction_row.exchange_owner_id = exact_exchange_owner_id
           AND transaction_row.provider_issuer = exact_provider_issuer
           AND transaction_row.expected_user_id = exact_expected_user_id
           AND transaction_row.initiating_user_id = exact_expected_user_id
           AND transaction_row.initiating_session_id
                = exact_initiating_session_id
           AND transaction_row.invitation_id = exact_invitation_id
           AND transaction_row.invitation_version = exact_invitation_version
           AND transaction_row.expected_contact_point_id
                = exact_expected_contact_point_id THEN
            UPDATE iam.auth_transactions
            SET status = 'FAILED', provider_error_class = 'REJECTED',
                succeeded_at = NULL, aggregate_version = 3,
                updated_at = server_now
            WHERE id = exact_auth_transaction_id;
            INSERT INTO audit.audit_events (
                event_id,occurred_at,actor_kind,actor_id,original_actor_id,
                action_code,target_kind,target_id,organization_id,before_status,
                after_status,before_version,after_version,role_code,purpose_code,
                reason_code,auth_strength_code,result_code,command_id,
                correlation_id,causation_id,trace_id,safe_attributes
            ) VALUES (
                new_audit_event_id,server_now,'SYSTEM',exact_system_actor_id,NULL,
                'CompleteOidcAuthentication','AuthTransaction',
                exact_auth_transaction_id,NULL,'EXCHANGING','FAILED',2,3,NULL,
                'STEP_UP',NULL,NULL,'FAILED',exact_auth_transaction_id,
                exact_correlation_id,exact_auth_transaction_id,exact_trace_id,
                jsonb_build_object('step_up_kind','INVITATION')
            );
        END IF;
        decision_code := 'AUTHENTICATION_REJECTED';
        RETURN NEXT;
        RETURN;
    END IF;

    UPDATE iam.contact_points AS contact
    SET user_id = exact_expected_user_id,
        verified_at = COALESCE(contact.verified_at, server_now),
        updated_at = CASE
            WHEN contact.user_id IS NULL OR contact.verified_at IS NULL
                THEN server_now
            ELSE contact.updated_at
        END
    WHERE contact.id = exact_expected_contact_point_id
      AND (
          contact.user_id IS NULL
          OR contact.user_id = exact_expected_user_id
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_oidc_invitation_contact_binding',
            MESSAGE = 'invitation contact binding is invalid';
    END IF;

    next_generation := exact_predecessor_generation + 1;
    UPDATE iam.sessions
    SET status = 'REVOKED', revoked_at = server_now,
        revocation_reason_code = 'STEP_UP_ROTATED', updated_at = server_now,
        aggregate_version = aggregate_version + 1
    WHERE id = exact_initiating_session_id;

    UPDATE iam.session_families
    SET current_generation = next_generation, updated_at = server_now,
        aggregate_version = aggregate_version + 1
    WHERE id = exact_session_family_id;

    INSERT INTO iam.sessions (
        id,user_id,family_id,generation,predecessor_session_id,
        handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,
        verified_contact_point_id,verified_at,verified_for_invitation_id,
        auth_transaction_id,auth_time,acr_code,amr_codes,created_at,
        last_activity_at,idle_expires_at,absolute_expires_at,updated_at,
        device_label,status,rotation_reason,revoked_at,
        revocation_reason_code,aggregate_version
    ) VALUES (
        new_session_id,exact_expected_user_id,exact_session_family_id,
        next_generation,exact_initiating_session_id,new_handle_digest,
        new_handle_digest_key_id,new_csrf_salt,new_csrf_key_id,new_csrf_digest,
        exact_expected_contact_point_id,server_now,exact_invitation_id,
        exact_auth_transaction_id,exact_auth_time,exact_acr_code,
        exact_amr_codes,server_now,server_now,
        LEAST(server_now + interval '30 minutes', predecessor.absolute_expires_at),
        predecessor.absolute_expires_at,server_now,predecessor.device_label,
        'ACTIVE','STEP_UP',NULL,NULL,1
    );

    UPDATE iam.auth_transactions
    SET status = 'SUCCEEDED', succeeded_at = server_now,
        provider_error_class = NULL, aggregate_version = 3,
        updated_at = server_now
    WHERE id = exact_auth_transaction_id;

    INSERT INTO audit.audit_events (
        event_id,occurred_at,actor_kind,actor_id,original_actor_id,
        action_code,target_kind,target_id,organization_id,before_status,
        after_status,before_version,after_version,role_code,purpose_code,
        reason_code,auth_strength_code,result_code,command_id,correlation_id,
        causation_id,trace_id,safe_attributes
    ) VALUES (
        new_audit_event_id,server_now,'SYSTEM',exact_system_actor_id,NULL,
        'CompleteOidcAuthentication','AuthTransaction',
        exact_auth_transaction_id,NULL,'EXCHANGING','SUCCEEDED',2,3,NULL,
        'STEP_UP',NULL,exact_acr_code,'SUCCEEDED',exact_auth_transaction_id,
        exact_correlation_id,exact_auth_transaction_id,exact_trace_id,
        jsonb_build_object('step_up_kind','INVITATION')
    );

    decision_code := 'AUTHORIZED';
    session_id := new_session_id;
    session_family_id := exact_session_family_id;
    user_id := exact_expected_user_id;
    user_status := resolved_user_status;
    generation := next_generation;
    RETURN NEXT;
END
$function$;

CREATE FUNCTION iam_api.finalize_oidc_generic_step_up_v1(
    exact_auth_transaction_id uuid,
    exact_exchange_owner_id uuid,
    exact_expected_user_id uuid,
    exact_initiating_session_id uuid,
    exact_session_family_id uuid,
    exact_predecessor_generation bigint,
    exact_provider_issuer text,
    exact_subject_digest bytea,
    exact_subject_digest_key_id text,
    new_session_id uuid,
    new_handle_digest bytea,
    new_handle_digest_key_id text,
    new_csrf_salt bytea,
    new_csrf_key_id text,
    new_csrf_digest bytea,
    exact_auth_time timestamptz,
    exact_token_issued_at timestamptz,
    exact_token_expires_at timestamptz,
    exact_acr_code text,
    exact_amr_codes text[],
    new_audit_event_id uuid,
    exact_system_actor_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (
    decision_code text,
    session_id uuid,
    session_family_id uuid,
    user_id uuid,
    user_status text,
    generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, audit
AS $function$
DECLARE
    transaction_row iam.auth_transactions%ROWTYPE;
    predecessor iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    resolved_user_id uuid;
    resolved_user_status text;
    server_now timestamptz := transaction_timestamp();
    next_generation bigint;
    valid boolean := true;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE'
       OR NULLIF(current_setting('app.auth_transaction_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_expected_user_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.session_family_id', true), '')
            IS DISTINCT FROM exact_session_family_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM new_session_id::text
       OR NULLIF(current_setting('app.oidc_subject_issuer', true), '')
            IS DISTINCT FROM exact_provider_issuer
       OR decode(
            NULLIF(current_setting('app.oidc_subject_digest', true), ''), 'hex'
          ) IS DISTINCT FROM exact_subject_digest
       OR NULLIF(current_setting('app.oidc_subject_digest_key_id', true), '')
            IS DISTINCT FROM exact_subject_digest_key_id
       OR exact_predecessor_generation < 1
       OR octet_length(exact_subject_digest) <> 32
       OR octet_length(new_handle_digest) <> 32
       OR octet_length(new_csrf_salt) <> 32
       OR octet_length(new_csrf_digest) <> 32
       OR exact_token_issued_at >= exact_token_expires_at
       OR exact_auth_time > server_now
       OR exact_token_issued_at > server_now + interval '2 minutes'
       OR exact_token_expires_at <= server_now
       OR cardinality(exact_amr_codes) NOT BETWEEN 1 AND 16
       OR NOT iam.text_array_is_unique_nonnull(exact_amr_codes) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_oidc_generic_step_up_exact_context',
            MESSAGE = 'generic STEP_UP context is invalid';
    END IF;

    SELECT candidate.* INTO transaction_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = exact_auth_transaction_id
    FOR UPDATE;
    IF NOT FOUND THEN
        decision_code := 'AUTHENTICATION_REJECTED';
        RETURN NEXT;
        RETURN;
    END IF;

    valid := transaction_row.protocol_version = 2
        AND transaction_row.purpose = 'STEP_UP'
        AND transaction_row.attempt = 1
        AND transaction_row.status = 'EXCHANGING'
        AND transaction_row.aggregate_version = 2
        AND transaction_row.exchange_owner_id = exact_exchange_owner_id
        AND transaction_row.provider_issuer = exact_provider_issuer
        AND transaction_row.expected_user_id = exact_expected_user_id
        AND transaction_row.initiating_user_id = exact_expected_user_id
        AND transaction_row.initiating_session_id = exact_initiating_session_id
        AND transaction_row.invitation_id IS NULL
        AND transaction_row.invitation_version IS NULL
        AND transaction_row.expected_contact_point_id IS NULL
        AND server_now < transaction_row.deadline;

    SELECT candidate.* INTO predecessor
    FROM iam.sessions AS candidate
    WHERE candidate.id = exact_initiating_session_id
      AND candidate.user_id = exact_expected_user_id
      AND candidate.family_id = exact_session_family_id
    FOR UPDATE;
    valid := valid AND FOUND
        AND predecessor.status = 'ACTIVE'
        AND predecessor.generation = exact_predecessor_generation
        AND server_now < predecessor.idle_expires_at
        AND server_now < predecessor.absolute_expires_at;

    SELECT candidate.* INTO family_row
    FROM iam.session_families AS candidate
    WHERE candidate.id = exact_session_family_id
      AND candidate.user_id = exact_expected_user_id
    FOR UPDATE;
    valid := valid AND FOUND
        AND family_row.status = 'ACTIVE'
        AND family_row.current_generation = exact_predecessor_generation;

    SELECT identity.user_id, account.status
    INTO resolved_user_id, resolved_user_status
    FROM iam.external_identities AS identity
    JOIN iam.users AS account ON account.id = identity.user_id
    WHERE identity.issuer = exact_provider_issuer
      AND identity.subject_digest = exact_subject_digest
      AND identity.subject_digest_key_id = exact_subject_digest_key_id
      AND identity.status = 'ACTIVE'
      AND identity.user_id = exact_expected_user_id
      AND account.status = 'ACTIVE'
    FOR UPDATE OF identity, account;
    valid := valid AND FOUND;

    IF NOT valid THEN
        IF transaction_row.id IS NOT NULL
           AND transaction_row.protocol_version = 2
           AND transaction_row.purpose = 'STEP_UP'
           AND transaction_row.attempt = 1
           AND transaction_row.status = 'EXCHANGING'
           AND transaction_row.aggregate_version = 2
           AND transaction_row.exchange_owner_id = exact_exchange_owner_id
           AND transaction_row.provider_issuer = exact_provider_issuer
           AND transaction_row.expected_user_id = exact_expected_user_id
           AND transaction_row.initiating_user_id = exact_expected_user_id
           AND transaction_row.initiating_session_id = exact_initiating_session_id
           AND transaction_row.invitation_id IS NULL
           AND transaction_row.invitation_version IS NULL
           AND transaction_row.expected_contact_point_id IS NULL THEN
            UPDATE iam.auth_transactions
            SET status = 'FAILED',
                provider_error_class = 'REJECTED',
                succeeded_at = NULL,
                aggregate_version = 3,
                updated_at = server_now
            WHERE id = exact_auth_transaction_id;
            INSERT INTO audit.audit_events (
                event_id,occurred_at,actor_kind,actor_id,original_actor_id,
                action_code,target_kind,target_id,organization_id,before_status,
                after_status,before_version,after_version,role_code,purpose_code,
                reason_code,auth_strength_code,result_code,command_id,
                correlation_id,causation_id,trace_id,safe_attributes
            ) VALUES (
                new_audit_event_id,server_now,'SYSTEM',exact_system_actor_id,NULL,
                'CompleteOidcAuthentication','AuthTransaction',
                exact_auth_transaction_id,NULL,'EXCHANGING','FAILED',2,3,NULL,
                'STEP_UP',NULL,NULL,'FAILED',exact_auth_transaction_id,
                exact_correlation_id,exact_auth_transaction_id,exact_trace_id,
                '{}'::jsonb
            );
        END IF;
        decision_code := 'AUTHENTICATION_REJECTED';
        RETURN NEXT;
        RETURN;
    END IF;

    next_generation := exact_predecessor_generation + 1;
    UPDATE iam.sessions
    SET status = 'REVOKED',
        revoked_at = server_now,
        revocation_reason_code = 'STEP_UP_ROTATED',
        updated_at = server_now,
        aggregate_version = aggregate_version + 1
    WHERE id = exact_initiating_session_id;

    UPDATE iam.session_families
    SET current_generation = next_generation,
        updated_at = server_now,
        aggregate_version = aggregate_version + 1
    WHERE id = exact_session_family_id;

    INSERT INTO iam.sessions (
        id,user_id,family_id,generation,predecessor_session_id,
        handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,
        verified_contact_point_id,verified_at,verified_for_invitation_id,
        auth_transaction_id,auth_time,acr_code,amr_codes,created_at,
        last_activity_at,idle_expires_at,absolute_expires_at,updated_at,
        device_label,status,rotation_reason,revoked_at,
        revocation_reason_code,aggregate_version
    ) VALUES (
        new_session_id,exact_expected_user_id,exact_session_family_id,
        next_generation,exact_initiating_session_id,new_handle_digest,
        new_handle_digest_key_id,new_csrf_salt,new_csrf_key_id,new_csrf_digest,
        NULL,NULL,NULL,exact_auth_transaction_id,exact_auth_time,exact_acr_code,
        exact_amr_codes,server_now,server_now,
        LEAST(server_now + interval '30 minutes', predecessor.absolute_expires_at),
        predecessor.absolute_expires_at,server_now,predecessor.device_label,
        'ACTIVE','STEP_UP',NULL,NULL,1
    );

    UPDATE iam.auth_transactions
    SET status = 'SUCCEEDED',
        succeeded_at = server_now,
        provider_error_class = NULL,
        aggregate_version = 3,
        updated_at = server_now
    WHERE id = exact_auth_transaction_id;

    INSERT INTO audit.audit_events (
        event_id,occurred_at,actor_kind,actor_id,original_actor_id,
        action_code,target_kind,target_id,organization_id,before_status,
        after_status,before_version,after_version,role_code,purpose_code,
        reason_code,auth_strength_code,result_code,command_id,correlation_id,
        causation_id,trace_id,safe_attributes
    ) VALUES (
        new_audit_event_id,server_now,'SYSTEM',exact_system_actor_id,NULL,
        'CompleteOidcAuthentication','AuthTransaction',
        exact_auth_transaction_id,NULL,'EXCHANGING','SUCCEEDED',2,3,NULL,
        'STEP_UP',NULL,exact_acr_code,'SUCCEEDED',exact_auth_transaction_id,
        exact_correlation_id,exact_auth_transaction_id,exact_trace_id,
        jsonb_build_object('step_up_kind','GENERIC')
    );

    decision_code := 'AUTHORIZED';
    session_id := new_session_id;
    session_family_id := exact_session_family_id;
    user_id := exact_expected_user_id;
    user_status := resolved_user_status;
    generation := next_generation;
    RETURN NEXT;
END
$function$;

-- Browser Accept scope resolver.  It accepts the canonical browser shape:
-- every required non-CONSENT_TEXT document in the immutable bundle, including
-- documents the User accepted previously.  The returned projection contains
-- only the subset still missing from storage.
CREATE POLICY rls_accept_receipt_principal_session_definer_v1
ON iam.sessions FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND NULLIF(current_setting('app.command_name', true), '')
        = 'AcceptAccessInvitation'
    AND NULLIF(current_setting('app.command_version', true), '') = '1'
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_accept_receipt_principal_family_definer_v1
ON iam.session_families FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND NULLIF(current_setting('app.command_name', true), '')
        = 'AcceptAccessInvitation'
    AND NULLIF(current_setting('app.command_version', true), '') = '1'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND EXISTS (
        SELECT 1 FROM iam.sessions AS exact_session
        WHERE exact_session.id::text = NULLIF(
                  current_setting('app.session_id', true), ''
              )
          AND exact_session.user_id = session_families.user_id
          AND exact_session.family_id = session_families.id
    )
);
CREATE POLICY rls_accept_receipt_principal_user_definer_v1
ON iam.users FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND NULLIF(current_setting('app.command_name', true), '')
        = 'AcceptAccessInvitation'
    AND NULLIF(current_setting('app.command_version', true), '') = '1'
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

-- A receipt miss may write only while holding the singleton policy row and
-- only with the database's exact active receipt keys. This closes the gap
-- between retained-key replay preflight and the later Accept write
-- transaction during key rotation.
CREATE POLICY rls_accept_key_policy_definer_v1
ON infra.iam_receipt_key_policy FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND singleton_key
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND NULLIF(current_setting('app.command_name', true), '')
        = 'AcceptAccessInvitation'
    AND NULLIF(current_setting('app.command_version', true), '') = '1'
);
CREATE POLICY rls_accept_key_policy_lock_definer_v1
ON infra.iam_receipt_key_policy FOR UPDATE TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND singleton_key
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND NULLIF(current_setting('app.command_name', true), '')
        = 'AcceptAccessInvitation'
    AND NULLIF(current_setting('app.command_version', true), '') = '1'
)
WITH CHECK (singleton_key);

CREATE FUNCTION iam_api.lock_accept_receipt_key_policy_v1(
    exact_active_idempotency_key_id text,
    exact_active_payload_hash_key_id text,
    exact_active_canonicalization_version text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, infra
AS $function$
DECLARE
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'ACCEPT'
       OR NULLIF(current_setting('app.command_name', true), '')
            IS DISTINCT FROM 'AcceptAccessInvitation'
       OR NULLIF(current_setting('app.command_version', true), '')
            IS DISTINCT FROM '1'
       OR NULLIF(current_setting('app.command_id', true), '') IS NULL
       OR exact_active_idempotency_key_id IS NULL
       OR exact_active_payload_hash_key_id IS NULL
       OR exact_active_canonicalization_version IS NULL THEN
        RETURN false;
    END IF;
    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    RETURN key_policy.active_idempotency_key_id
                = exact_active_idempotency_key_id
        AND key_policy.active_payload_hash_key_id
                = exact_active_payload_hash_key_id
        AND key_policy.active_canonicalization_version
                = exact_active_canonicalization_version;
END
$function$;

CREATE FUNCTION iam_api.resolve_accept_receipt_principal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    session_row iam.sessions%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    user_row iam.users%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
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
    SELECT * INTO session_row FROM iam.sessions
    WHERE id = exact_session_id AND user_id = exact_actor_user_id;
    IF NOT FOUND
       OR session_row.status <> 'ACTIVE'
       OR transaction_timestamp() >= session_row.idle_expires_at
       OR transaction_timestamp() >= session_row.absolute_expires_at THEN
        RETURN jsonb_build_object('decision_code','AUTHENTICATION_REQUIRED');
    END IF;
    SELECT * INTO family_row FROM iam.session_families
    WHERE id = session_row.family_id AND user_id = exact_actor_user_id;
    IF NOT FOUND
       OR family_row.status <> 'ACTIVE'
       OR family_row.current_generation <> session_row.generation THEN
        RETURN jsonb_build_object('decision_code','AUTHENTICATION_REQUIRED');
    END IF;
    SELECT * INTO user_row FROM iam.users WHERE id = exact_actor_user_id;
    IF NOT FOUND OR user_row.status <> 'ACTIVE' THEN
        RETURN jsonb_build_object('decision_code','AUTHENTICATION_REQUIRED');
    END IF;
    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED',
        'actor_user_id',exact_actor_user_id::text,
        'session_id',exact_session_id::text,
        'session_family_id',family_row.id::text
    );
END
$function$;

CREATE POLICY rls_accept_scope_session_definer_v1 ON iam.sessions
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_scope_family_definer_v1 ON iam.session_families
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_scope_auth_definer_v1 ON iam.auth_transactions
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND expected_user_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND invitation_id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

CREATE POLICY rls_accept_scope_invitation_definer_v1 ON iam.access_invitations
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

CREATE POLICY rls_accept_scope_selector_definer_v1 ON iam.policy_selectors
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
);
CREATE POLICY rls_accept_scope_bundle_definer_v1 ON iam.policy_bundles
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND id::text = NULLIF(current_setting('app.policy_bundle_id', true), '')
);
CREATE POLICY rls_accept_scope_bundle_document_definer_v1
ON iam.policy_bundle_documents FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND bundle_id::text = NULLIF(
        current_setting('app.policy_bundle_id', true), ''
    )
);
CREATE POLICY rls_accept_scope_document_definer_v1 ON iam.policy_documents
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND EXISTS (
        SELECT 1 FROM iam.policy_bundle_documents AS member
        WHERE member.bundle_id = NULLIF(
                  current_setting('app.policy_bundle_id', true), ''
              )::uuid
          AND member.document_id = policy_documents.id
    )
);
CREATE POLICY rls_accept_scope_acceptance_definer_v1 ON iam.policy_acceptances
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_accept_scope_offer_definer_v1 ON iam.consent_offers
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND bundle_id::text = NULLIF(
        current_setting('app.policy_bundle_id', true), ''
    )
);
CREATE POLICY rls_accept_scope_consent_definer_v1 ON iam.consent_grants
FOR SELECT TO schema_owner USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'ORGANIZATION_INVITATION_ACCEPT_RESOLVE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND policy_bundle_id::text = NULLIF(
        current_setting('app.policy_bundle_id', true), ''
    )
);

CREATE FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
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

    IF current_session.rotation_reason = 'STEP_UP'
       AND current_session.verified_for_invitation_id = exact_invitation_id THEN
        predecessor := current_session;
    ELSIF current_session.rotation_reason = 'INVITATION_ACCEPT'
          AND current_session.predecessor_session_id IS NOT NULL THEN
        SELECT candidate.* INTO predecessor
        FROM iam.sessions AS candidate
        WHERE candidate.id = current_session.predecessor_session_id
          AND candidate.user_id = exact_actor_user_id
          AND candidate.family_id = current_session.family_id
          AND candidate.rotation_reason = 'STEP_UP'
          AND candidate.verified_for_invitation_id = exact_invitation_id;
    END IF;
    IF predecessor.id IS NULL OR predecessor.auth_transaction_id IS NULL THEN
        RETURN jsonb_build_object(
            'decision_code', 'ACCESS_INVITATION_UNAVAILABLE'
        );
    END IF;

    SELECT candidate.* INTO auth_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = predecessor.auth_transaction_id
      AND candidate.purpose = 'STEP_UP'
      AND candidate.status = 'SUCCEEDED'
      AND candidate.expected_user_id = exact_actor_user_id
      AND candidate.invitation_id = exact_invitation_id
      AND candidate.succeeded_at IS NOT NULL;
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
      AND (
          (candidate.status = 'ISSUED'
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

    SELECT COALESCE(jsonb_agg(member.document_id::text ORDER BY member.position),'[]')
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

    SELECT COALESCE(jsonb_agg(offer.id::text ORDER BY offer.id),'[]')
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

-- Every IAM0034 program is closed to the one runtime role that owns its
-- protocol. Keep these grants explicit so catalog probes cannot mistake a
-- restored/default ACL for protocol authority.
REVOKE ALL ON FUNCTION iam_api.resolve_oidc_generic_step_up_session_v1(
    uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_oidc_generic_step_up_session_v1(
    uuid,uuid,uuid
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.resolve_oidc_step_up_session_v1(
    uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_oidc_step_up_session_v1(
    uuid,uuid,uuid,uuid
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.finalize_oidc_invitation_step_up_v1(
    uuid,uuid,uuid,bigint,uuid,text,bytea,text,uuid,uuid,uuid,bigint,
    text,bytea,text,text,bytea,text,uuid,bytea,text,bytea,text,bytea,
    timestamptz,timestamptz,timestamptz,text,text[],uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.finalize_oidc_invitation_step_up_v1(
    uuid,uuid,uuid,bigint,uuid,text,bytea,text,uuid,uuid,uuid,bigint,
    text,bytea,text,text,bytea,text,uuid,bytea,text,bytea,text,bytea,
    timestamptz,timestamptz,timestamptz,text,text[],uuid,uuid,uuid,uuid
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.finalize_oidc_generic_step_up_v1(
    uuid,uuid,uuid,uuid,uuid,bigint,text,bytea,text,uuid,bytea,text,
    bytea,text,bytea,timestamptz,timestamptz,timestamptz,text,text[],
    uuid,uuid,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.finalize_oidc_generic_step_up_v1(
    uuid,uuid,uuid,uuid,uuid,bigint,text,bytea,text,uuid,bytea,text,
    bytea,text,bytea,timestamptz,timestamptz,timestamptz,text,text[],
    uuid,uuid,uuid,uuid
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.resolve_accept_receipt_principal_v1(
    uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_accept_receipt_principal_v1(
    uuid,uuid
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.lock_accept_receipt_key_policy_v1(
    text,text,text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.lock_accept_receipt_key_policy_v1(
    text,text,text
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
    uuid,uuid,uuid,uuid,jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
    uuid,uuid,uuid,uuid,jsonb
) TO iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.organization_admin_authority_decision_v1(
    uuid,uuid,uuid,boolean
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.organization_admin_issue_snapshot_v1(
    uuid,uuid,uuid,text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.organization_admin_resume_snapshot_v1(
    uuid,uuid,uuid,uuid
) FROM PUBLIC;

REVOKE ALL ON FUNCTION iam_api.resolve_organization_admin_target_v1(
    uuid,uuid,uuid,text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_organization_admin_target_v1(
    uuid,uuid,uuid,text
) TO iam_app;

REVOKE ALL ON FUNCTION iam_api.resolve_organization_admin_issue_scope_v1(
    uuid,uuid,uuid,bytea[],text[],bytea[],text[],text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_organization_admin_issue_scope_v1(
    uuid,uuid,uuid,bytea[],text[],bytea[],text[],text
) TO iam_app;

REVOKE ALL ON FUNCTION iam_api.resolve_organization_admin_resume_scope_v1(
    uuid,uuid,uuid,uuid,bytea[],text[],bytea[],text[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_organization_admin_resume_scope_v1(
    uuid,uuid,uuid,uuid,bytea[],text[],bytea[],text[]
) TO iam_app;

REVOKE ALL ON FUNCTION iam_api.execute_organization_admin_v1(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.execute_organization_admin_v1(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea
) TO iam_app;
