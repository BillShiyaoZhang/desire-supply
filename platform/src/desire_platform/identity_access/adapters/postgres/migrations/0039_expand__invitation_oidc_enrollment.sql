-- IAM 0039: invitation-bound anonymous OIDC ENROLLMENT.
--
-- This fixed program creates only the identity/session proof needed to reach
-- the existing invitation-acceptance flow.  Membership and Role authority are
-- deliberately outside this transaction.

CREATE POLICY rls_oidc_enrollment_user_insert_definer_v1
ON iam.users
FOR INSERT TO schema_owner
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status = 'PENDING_ENROLLMENT'
    AND aggregate_version = 1
);

-- The advisory subject lock below serializes same-subject enrollment.  This
-- policy lets the definer observe a conflict even if a retained digest key ID
-- differs; issuer + digest is the database uniqueness boundary.
CREATE POLICY rls_oidc_enrollment_identity_conflict_definer_v1
ON iam.external_identities
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND issuer = NULLIF(current_setting('app.oidc_subject_issuer', true), '')
    AND subject_digest = decode(
        NULLIF(current_setting('app.oidc_subject_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_oidc_enrollment_identity_insert_definer_v1
ON iam.external_identities
FOR INSERT TO schema_owner
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND issuer = NULLIF(current_setting('app.oidc_subject_issuer', true), '')
    AND subject_digest = decode(
        NULLIF(current_setting('app.oidc_subject_digest', true), ''),
        'hex'
    )
    AND subject_digest_key_id = NULLIF(
        current_setting('app.oidc_subject_digest_key_id', true),
        ''
    )
    AND status = 'ACTIVE'
);

-- Recovery may inspect only a prior ENROLLMENT Session for the exact resolved
-- pending User and the exact Invitation frozen in the new AuthTransaction.
-- This prevents a second invitation for the same email from taking over a
-- pending identity created by a different invitation.
CREATE POLICY rls_oidc_enrollment_recovery_session_select_definer_v1
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND verified_for_invitation_id::text = NULLIF(
        current_setting('app.target_invitation_id', true), ''
    )
);

CREATE FUNCTION iam_api.finalize_oidc_invitation_enrollment_v1(
    exact_auth_transaction_id uuid,
    exact_exchange_owner_id uuid,
    exact_invitation_id uuid,
    exact_invitation_version bigint,
    exact_expected_contact_point_id uuid,
    exact_expected_contact_type text,
    exact_expected_contact_binding_digest bytea,
    exact_expected_contact_binding_key_id text,
    exact_provider_issuer text,
    exact_subject_digest bytea,
    exact_subject_digest_key_id text,
    exact_verified_contact_type text,
    exact_verified_contact_binding_digest bytea,
    exact_verified_contact_binding_key_id text,
    new_user_id uuid,
    new_external_identity_id uuid,
    new_session_family_id uuid,
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
    server_now timestamptz := transaction_timestamp();
    transaction_found boolean := false;
    invitation_found boolean := false;
    contact_found boolean := false;
    owned_transaction boolean := false;
    identity_conflict boolean := false;
    identity_locked boolean := false;
    recovered_enrollment boolean := false;
    resolved_user_id uuid;
    resolved_external_identity_id uuid;
    resolved_subject_digest_key_id text;
    resolved_identity_status text;
    resolved_user_status text;
    valid boolean := false;
BEGIN
    IF exact_auth_transaction_id IS NULL
       OR exact_exchange_owner_id IS NULL
       OR exact_invitation_id IS NULL
       OR exact_expected_contact_point_id IS NULL
       OR new_user_id IS NULL
       OR new_external_identity_id IS NULL
       OR new_session_family_id IS NULL
       OR new_session_id IS NULL
       OR new_audit_event_id IS NULL
       OR exact_system_actor_id IS NULL
       OR exact_correlation_id IS NULL
       OR exact_trace_id IS NULL
       OR session_user IS DISTINCT FROM 'iam_onboarding'
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
            IS DISTINCT FROM new_user_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM new_user_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text
       OR NULLIF(current_setting('app.session_family_id', true), '')
            IS DISTINCT FROM new_session_family_id::text
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
       OR exact_expected_contact_type IS DISTINCT FROM 'EMAIL'
       OR exact_verified_contact_type IS DISTINCT FROM 'EMAIL'
       OR octet_length(exact_expected_contact_binding_digest) <> 32
       OR octet_length(exact_verified_contact_binding_digest) <> 32
       OR exact_expected_contact_binding_digest
            IS DISTINCT FROM exact_verified_contact_binding_digest
       OR exact_expected_contact_binding_key_id
            IS DISTINCT FROM exact_verified_contact_binding_key_id
       OR length(exact_expected_contact_binding_key_id) = 0
       OR octet_length(exact_subject_digest) <> 32
       OR length(exact_subject_digest_key_id) = 0
       OR exact_provider_issuer !~ '^https://'
       OR octet_length(new_handle_digest) <> 32
       OR length(new_handle_digest_key_id) = 0
       OR octet_length(new_csrf_salt) <> 32
       OR length(new_csrf_key_id) = 0
       OR octet_length(new_csrf_digest) <> 32
       OR exact_token_issued_at >= exact_token_expires_at
       OR exact_auth_time > server_now
       OR exact_token_issued_at > server_now + interval '2 minutes'
       OR exact_token_expires_at <= server_now
       OR length(exact_acr_code) = 0
       OR cardinality(exact_amr_codes) NOT BETWEEN 1 AND 16
       OR NOT iam.text_array_is_unique_nonnull(exact_amr_codes) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_oidc_invitation_enrollment_exact_context',
            MESSAGE = 'invitation ENROLLMENT context is invalid';
    END IF;

    SELECT candidate.* INTO transaction_row
    FROM iam.auth_transactions AS candidate
    WHERE candidate.id = exact_auth_transaction_id
    FOR UPDATE;
    transaction_found := FOUND;
    owned_transaction := transaction_found
        AND transaction_row.protocol_version = 2
        AND transaction_row.purpose = 'ENROLLMENT'
        AND transaction_row.attempt = 1
        AND transaction_row.status = 'EXCHANGING'
        AND transaction_row.aggregate_version = 2
        AND transaction_row.exchange_owner_id = exact_exchange_owner_id
        AND transaction_row.invitation_id = exact_invitation_id
        AND transaction_row.invitation_version = exact_invitation_version
        AND transaction_row.expected_contact_point_id
            = exact_expected_contact_point_id;
    valid := COALESCE(
        owned_transaction
        AND transaction_row.initiating_session_id IS NULL
        AND transaction_row.initiating_user_id IS NULL
        AND transaction_row.expected_user_id IS NULL
        AND transaction_row.expected_contact_type = exact_expected_contact_type
        AND transaction_row.expected_contact_binding_digest
            = exact_expected_contact_binding_digest
        AND transaction_row.expected_contact_binding_key_id
            = exact_expected_contact_binding_key_id
        AND transaction_row.provider_issuer = exact_provider_issuer
        AND server_now < transaction_row.deadline,
        false
    );

    SELECT candidate.* INTO invitation_row
    FROM iam.access_invitations AS candidate
    WHERE candidate.id = exact_invitation_id
    FOR UPDATE;
    invitation_found := FOUND;
    valid := COALESCE(
        valid
        AND invitation_found
        AND invitation_row.status = 'ISSUED'
        AND invitation_row.aggregate_version = exact_invitation_version
        AND invitation_row.recipient_contact_id
            = exact_expected_contact_point_id
        AND invitation_row.purpose = 'ORGANIZATION_MEMBERSHIP'
        AND invitation_row.organization_id IS NOT NULL
        AND invitation_row.target_scope = 'ORGANIZATION'
        AND invitation_row.target_role = 'DEMAND_OWNER'
        AND NOT invitation_row.is_initial_admin
        AND server_now < invitation_row.expires_at,
        false
    );

    SELECT candidate.* INTO contact_row
    FROM iam.contact_points AS candidate
    WHERE candidate.id = exact_expected_contact_point_id
    FOR UPDATE;
    contact_found := FOUND;
    valid := COALESCE(
        valid
        AND contact_found
        AND contact_row.contact_type = 'EMAIL'
        AND contact_row.binding_digest
            = exact_expected_contact_binding_digest
        AND contact_row.binding_digest_key_id
            = exact_expected_contact_binding_key_id,
        false
    );

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            exact_provider_issuer || ':' || encode(exact_subject_digest, 'hex'),
            0
        )
    );
    SELECT identity.id, identity.user_id, identity.subject_digest_key_id,
           identity.status
    INTO resolved_external_identity_id, resolved_user_id,
         resolved_subject_digest_key_id, resolved_identity_status
    FROM iam.external_identities AS identity
    WHERE identity.issuer = exact_provider_issuer
      AND identity.subject_digest = exact_subject_digest;
    identity_conflict := FOUND;

    IF identity_conflict THEN
        -- A previously committed ENROLLMENT may have lost its HTTP response
        -- before the browser received the Session handle.  Permit only the
        -- same provider proof and already-bound verified recipient to recover
        -- that still-authority-free PENDING User.  Any ACTIVE/SUSPENDED User,
        -- different digest key, or different recipient remains closed.
        IF resolved_subject_digest_key_id = exact_subject_digest_key_id THEN
            SELECT identity.id, identity.user_id, identity.status
            INTO resolved_external_identity_id, resolved_user_id,
                 resolved_identity_status
            FROM iam.external_identities AS identity
            WHERE identity.issuer = exact_provider_issuer
              AND identity.subject_digest = exact_subject_digest
              AND identity.subject_digest_key_id = exact_subject_digest_key_id
            FOR UPDATE;
            identity_locked := FOUND;
        END IF;
        IF identity_locked THEN
            SELECT candidate.status
            INTO resolved_user_status
            FROM iam.users AS candidate
            WHERE candidate.id = resolved_user_id
            FOR UPDATE;
        END IF;
        recovered_enrollment := identity_locked AND FOUND
            AND resolved_identity_status = 'ACTIVE'
            AND resolved_user_status = 'PENDING_ENROLLMENT'
            AND contact_row.user_id = resolved_user_id
            AND contact_row.verified_at IS NOT NULL;
        IF recovered_enrollment THEN
            PERFORM set_config(
                'app.actor_user_id', resolved_user_id::text, true
            );
            PERFORM set_config(
                'app.target_user_id', resolved_user_id::text, true
            );
            SELECT EXISTS (
                SELECT 1
                FROM iam.sessions AS prior_session
                WHERE prior_session.user_id = resolved_user_id
                  AND prior_session.verified_contact_point_id
                        = exact_expected_contact_point_id
                  AND prior_session.verified_for_invitation_id
                        = exact_invitation_id
                  AND prior_session.rotation_reason = 'ENROLLMENT'
                  AND prior_session.auth_transaction_id IS NOT NULL
            ) INTO recovered_enrollment;
        END IF;
        valid := valid AND recovered_enrollment;
    ELSE
        resolved_user_id := new_user_id;
        valid := valid AND contact_row.user_id IS NULL;
    END IF;

    IF NOT valid THEN
        IF owned_transaction THEN
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
                'ENROLLMENT',NULL,NULL,'FAILED',exact_auth_transaction_id,
                exact_correlation_id,exact_auth_transaction_id,exact_trace_id,
                jsonb_build_object('enrollment_kind','INVITATION')
            );
        END IF;
        decision_code := 'AUTHENTICATION_REJECTED';
        RETURN NEXT;
        RETURN;
    END IF;

    IF recovered_enrollment THEN
        PERFORM set_config('app.actor_user_id', resolved_user_id::text, true);
        PERFORM set_config('app.target_user_id', resolved_user_id::text, true);
    ELSE
        INSERT INTO iam.users (
            id,status,display_handle,aggregate_version,created_at,updated_at
        ) VALUES (
            resolved_user_id,'PENDING_ENROLLMENT',
            'pending_' || replace(resolved_user_id::text, '-', ''),1,
            server_now,server_now
        );

        INSERT INTO iam.external_identities (
            id,user_id,issuer,subject_digest,subject_digest_key_id,verified_at,
            status,created_at
        ) VALUES (
            new_external_identity_id,resolved_user_id,exact_provider_issuer,
            exact_subject_digest,exact_subject_digest_key_id,server_now,
            'ACTIVE',server_now
        );

        UPDATE iam.contact_points AS exact_contact
        SET user_id = resolved_user_id, verified_at = server_now,
            updated_at = server_now
        WHERE exact_contact.id = exact_expected_contact_point_id
          AND exact_contact.user_id IS NULL
          AND exact_contact.contact_type = 'EMAIL'
          AND exact_contact.binding_digest
                = exact_expected_contact_binding_digest
          AND exact_contact.binding_digest_key_id
                = exact_expected_contact_binding_key_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_oidc_invitation_enrollment_contact_binding',
                MESSAGE = 'invitation ENROLLMENT contact binding is invalid';
        END IF;
    END IF;

    INSERT INTO iam.session_families (
        id,user_id,status,current_generation,revoked_at,
        revocation_reason_code,aggregate_version,created_at,updated_at
    ) VALUES (
        new_session_family_id,resolved_user_id,'ACTIVE',1,NULL,NULL,1,
        server_now,server_now
    );

    INSERT INTO iam.sessions (
        id,user_id,family_id,generation,predecessor_session_id,
        handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,
        verified_contact_point_id,verified_at,verified_for_invitation_id,
        auth_transaction_id,auth_time,acr_code,amr_codes,created_at,
        last_activity_at,idle_expires_at,absolute_expires_at,updated_at,
        device_label,status,rotation_reason,revoked_at,
        revocation_reason_code,aggregate_version
    ) VALUES (
        new_session_id,resolved_user_id,new_session_family_id,1,NULL,
        new_handle_digest,new_handle_digest_key_id,new_csrf_salt,
        new_csrf_key_id,new_csrf_digest,exact_expected_contact_point_id,
        server_now,exact_invitation_id,exact_auth_transaction_id,
        exact_auth_time,exact_acr_code,exact_amr_codes,server_now,server_now,
        server_now + interval '30 minutes',server_now + interval '12 hours',
        server_now,'Browser','ACTIVE','ENROLLMENT',NULL,NULL,1
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
        'ENROLLMENT',NULL,exact_acr_code,'SUCCEEDED',exact_auth_transaction_id,
        exact_correlation_id,exact_auth_transaction_id,exact_trace_id,
        jsonb_build_object('enrollment_kind','INVITATION')
    );

    decision_code := 'AUTHORIZED';
    session_id := new_session_id;
    session_family_id := new_session_family_id;
    user_id := resolved_user_id;
    user_status := 'PENDING_ENROLLMENT';
    generation := 1;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.finalize_oidc_invitation_enrollment_v1(
    uuid,uuid,uuid,bigint,uuid,text,bytea,text,text,bytea,text,text,bytea,text,
    uuid,uuid,uuid,uuid,bytea,text,bytea,text,bytea,timestamptz,timestamptz,
    timestamptz,text,text[],uuid,uuid,uuid,uuid
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION iam_api.finalize_oidc_invitation_enrollment_v1(
    uuid,uuid,uuid,bigint,uuid,text,bytea,text,text,bytea,text,text,bytea,text,
    uuid,uuid,uuid,uuid,bytea,text,bytea,text,bytea,timestamptz,timestamptz,
    timestamptz,text,text[],uuid,uuid,uuid,uuid
) TO iam_onboarding;
