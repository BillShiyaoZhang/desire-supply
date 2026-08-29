-- IAM 0030: ACCESS_ADMIN configuration of synthetic platform duties.
--
-- This online capability is deliberately limited to accounts in the one active
-- INTERNAL_SANDBOX bootstrap and to the five closed platform duties.  User and
-- organization roles remain invitation/policy-bound and are not writable here.

ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_sandbox_platform_duty_admin CHECK (
    command_name NOT IN ('GrantPlatformDuty', 'RevokePlatformDuty')
    OR (
        command_version = 1
        AND principal_kind = 'USER'
        AND target_kind = 'User'
        AND target_id <> principal_id
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
                AND response_http_status = 200
                AND response_schema_name = 'PlatformUserAdminDto'
                AND response_entity_tag ~ '^"v[1-9][0-9]*"$'
                AND current_user_entity_tag = response_entity_tag
                AND safe_response_body ->> 'user_id' = target_id::text
                AND safe_response_body ->> 'aggregate_version'
                    ~ '^[1-9][0-9]*$'
                AND safe_response_body ->> 'entity_tag' = response_entity_tag
                AND safe_response_body ->> 'status' IN ('ACTIVE', 'SUSPENDED')
                AND safe_response_body ->> 'revoked_session_count' = '0'
                AND safe_response_body ->> 'revoked_session_family_count' = '0'
            )
        )
        AND canonical_path = '/v1/app/admin/accounts/' || target_id::text
            || '/platform-duties/'
            || split_part(split_part(canonical_path, '/platform-duties/', 2), '/', 1)
            || CASE command_name
                WHEN 'GrantPlatformDuty' THEN '/grant'
                ELSE '/revoke'
            END
        AND split_part(split_part(canonical_path, '/platform-duties/', 2), '/', 1)
            IN (
                'ACCESS_ADMIN', 'OPERATIONS_REVIEWER', 'FINANCE_OPERATOR',
                'TRUST_OFFICER', 'APPEAL_REVIEWER'
            )
    )
);

CREATE FUNCTION iam.internal_sandbox_platform_duty_admin_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT
    session_user = 'iam_app'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'INTERNAL_SANDBOX_PLATFORM_DUTY_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'GRANT_PLATFORM_DUTY', 'REVOKE_PLATFORM_DUTY'
    )
    AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.target_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_user_id', true), '')
        <> NULLIF(current_setting('app.target_user_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.duty_code', true), '') IN (
        'ACCESS_ADMIN', 'OPERATIONS_REVIEWER', 'FINANCE_OPERATOR',
        'TRUST_OFFICER', 'APPEAL_REVIEWER'
    )
$function$;

ALTER FUNCTION iam.internal_sandbox_platform_duty_admin_context_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam.internal_sandbox_platform_duty_admin_context_v1()
FROM PUBLIC;

-- FORCE RLS remains active for SECURITY DEFINER reads.
CREATE POLICY rls_sandbox_duty_admin_bootstrap_state_definer
ON infra.iam_sandbox_bootstrap_state
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_platform_duty_admin_context_v1());

CREATE POLICY rls_sandbox_duty_admin_bootstrap_accounts_definer
ON infra.iam_sandbox_bootstrap_accounts
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_platform_duty_admin_context_v1());

CREATE POLICY rls_sandbox_duty_admin_users_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    iam.internal_sandbox_platform_duty_admin_context_v1()
    AND (
        id::text IN (
            NULLIF(current_setting('app.actor_user_id', true), ''),
            NULLIF(current_setting('app.target_user_id', true), '')
        )
        OR EXISTS (
            SELECT 1
            FROM iam.platform_duty_grants AS access_grant
            WHERE access_grant.user_id = users.id
              AND access_grant.duty_code = 'ACCESS_ADMIN'
              AND access_grant.revoked_at IS NULL
        )
    )
);

CREATE POLICY rls_sandbox_duty_admin_families_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    iam.internal_sandbox_platform_duty_admin_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_sandbox_duty_admin_sessions_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    iam.internal_sandbox_platform_duty_admin_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_sandbox_duty_admin_grants_definer
ON iam.platform_duty_grants
FOR ALL TO schema_owner
USING (
    iam.internal_sandbox_platform_duty_admin_context_v1()
    AND (
        duty_code = 'ACCESS_ADMIN'
        OR (
            user_id::text = NULLIF(
                current_setting('app.target_user_id', true), ''
            )
            AND duty_code = NULLIF(current_setting('app.duty_code', true), '')
        )
    )
);

CREATE FUNCTION iam_api.lock_internal_sandbox_platform_duty_admin_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_user_id uuid,
    exact_operation text,
    exact_expected_version bigint,
    exact_duty_code text,
    replay_existing boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    actor_family iam.session_families%ROWTYPE;
    actor_session iam.sessions%ROWTYPE;
    actor_user iam.users%ROWTYPE;
    target_user iam.users%ROWTYPE;
    locked_user iam.users%ROWTYPE;
    locked_grant iam.platform_duty_grants%ROWTYPE;
    target_grant iam.platform_duty_grants%ROWTYPE;
    actor_admin_count integer := 0;
    active_admin_count integer := 0;
    active_target_grant_count integer := 0;
    active_state_count integer := 0;
    active_account_count integer := 0;
    stored_account_count integer := 0;
    actor_is_synthetic boolean := false;
    target_is_synthetic boolean := false;
BEGIN
    IF exact_actor_user_id IS NOT NULL
       AND exact_actor_user_id = exact_target_user_id THEN
        RETURN jsonb_build_object(
            'decision_code', 'SELF_MANAGEMENT_FORBIDDEN'
        );
    END IF;
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_target_user_id IS NULL
       OR exact_expected_version IS NULL
       OR exact_expected_version < 1
       OR exact_operation NOT IN (
            'GRANT_PLATFORM_DUTY', 'REVOKE_PLATFORM_DUTY'
       )
       OR exact_duty_code NOT IN (
            'ACCESS_ADMIN', 'OPERATIONS_REVIEWER', 'FINANCE_OPERATOR',
            'TRUST_OFFICER', 'APPEAL_REVIEWER'
       )
       OR replay_existing IS NULL
       OR NOT iam.internal_sandbox_platform_duty_admin_context_v1()
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_target_user_id::text
       OR NULLIF(current_setting('app.expected_version', true), '')
            IS DISTINCT FROM exact_expected_version::text
       OR NULLIF(current_setting('app.duty_code', true), '')
            IS DISTINCT FROM exact_duty_code THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_sandbox_platform_duty_admin_exact_context',
            MESSAGE = 'sandbox platform duty administration context is invalid';
    END IF;

    SELECT count(*), COALESCE(sum(state.account_count), 0)
    INTO active_state_count, active_account_count
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.status = 'ACTIVE';

    SELECT count(*)
    INTO stored_account_count
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision;

    IF active_state_count <> 1
       OR active_account_count NOT BETWEEN 2 AND 16
       OR stored_account_count <> active_account_count THEN
        RETURN jsonb_build_object('decision_code', 'SERVICE_UNAVAILABLE');
    END IF;

    SELECT
        bool_or(account.user_id = exact_actor_user_id),
        bool_or(account.user_id = exact_target_user_id)
    INTO actor_is_synthetic, target_is_synthetic
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision
    WHERE account.user_id IN (exact_actor_user_id, exact_target_user_id);

    IF NOT COALESCE(actor_is_synthetic, false) THEN
        RETURN jsonb_build_object('decision_code', 'RESOURCE_NOT_FOUND');
    END IF;
    IF NOT COALESCE(target_is_synthetic, false) THEN
        RETURN jsonb_build_object('decision_code', 'RESOURCE_NOT_FOUND');
    END IF;

    SELECT family.*
    INTO actor_family
    FROM iam.session_families AS family
    JOIN iam.sessions AS candidate_session
      ON candidate_session.family_id = family.id
     AND candidate_session.user_id = family.user_id
    WHERE candidate_session.id = exact_session_id
      AND candidate_session.user_id = exact_actor_user_id
    FOR UPDATE OF family;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code', 'AUTHENTICATION_REQUIRED');
    END IF;

    SELECT session_row.*
    INTO actor_session
    FROM iam.sessions AS session_row
    WHERE session_row.id = exact_session_id
      AND session_row.user_id = exact_actor_user_id
      AND session_row.family_id = actor_family.id
    FOR UPDATE;
    IF NOT FOUND
       OR actor_session.status <> 'ACTIVE'
       OR actor_family.status <> 'ACTIVE'
       OR actor_session.generation <> actor_family.current_generation THEN
        RETURN jsonb_build_object('decision_code', 'AUTHENTICATION_REQUIRED');
    END IF;
    IF transaction_timestamp() >= actor_session.idle_expires_at
       OR transaction_timestamp() >= actor_session.absolute_expires_at THEN
        RETURN jsonb_build_object('decision_code', 'SESSION_EXPIRED');
    END IF;

    FOR locked_user IN
        SELECT account.*
        FROM iam.users AS account
        WHERE account.id IN (exact_actor_user_id, exact_target_user_id)
        ORDER BY account.id
        FOR UPDATE
    LOOP
        IF locked_user.id = exact_actor_user_id THEN
            actor_user := locked_user;
        ELSIF locked_user.id = exact_target_user_id THEN
            target_user := locked_user;
        END IF;
    END LOOP;

    IF actor_user.id IS NULL OR actor_user.status <> 'ACTIVE' THEN
        RETURN jsonb_build_object('decision_code', 'AUTHENTICATION_REQUIRED');
    END IF;
    IF target_user.id IS NULL
       OR target_user.status NOT IN ('ACTIVE', 'SUSPENDED') THEN
        RETURN jsonb_build_object('decision_code', 'RESOURCE_NOT_FOUND');
    END IF;
    IF actor_session.auth_time > transaction_timestamp()
       OR actor_session.auth_time
            <= transaction_timestamp() - interval '10 minutes'
       OR lower(actor_session.acr_code) NOT LIKE '%mfa%'
       OR NOT (
            actor_session.amr_codes
            && ARRAY['otp', 'mfa', 'webauthn', 'hwk']::text[]
       ) THEN
        RETURN jsonb_build_object('decision_code', 'MFA_STEP_UP_REQUIRED');
    END IF;

    FOR locked_grant IN
        SELECT access_grant.*
        FROM iam.platform_duty_grants AS access_grant
        WHERE access_grant.duty_code = 'ACCESS_ADMIN'
          AND access_grant.granted_at <= transaction_timestamp()
          AND access_grant.revoked_at IS NULL
          AND (
              access_grant.expires_at IS NULL
              OR transaction_timestamp() < access_grant.expires_at
          )
        ORDER BY access_grant.id
        FOR UPDATE
    LOOP
        IF locked_grant.user_id = exact_actor_user_id THEN
            actor_admin_count := actor_admin_count + 1;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM iam.users AS active_admin
            WHERE active_admin.id = locked_grant.user_id
              AND active_admin.status = 'ACTIVE'
        ) THEN
            active_admin_count := active_admin_count + 1;
        END IF;
    END LOOP;

    IF actor_admin_count = 0 THEN
        RETURN jsonb_build_object('decision_code', 'RESOURCE_NOT_FOUND');
    ELSIF actor_admin_count <> 1 THEN
        RETURN jsonb_build_object('decision_code', 'SERVICE_UNAVAILABLE');
    END IF;

    FOR locked_grant IN
        SELECT duty.*
        FROM iam.platform_duty_grants AS duty
        WHERE duty.user_id = exact_target_user_id
          AND duty.duty_code = exact_duty_code
          AND duty.granted_at <= transaction_timestamp()
          AND duty.revoked_at IS NULL
          AND (
              duty.expires_at IS NULL
              OR transaction_timestamp() < duty.expires_at
          )
        ORDER BY duty.id
        FOR UPDATE
    LOOP
        active_target_grant_count := active_target_grant_count + 1;
        target_grant := locked_grant;
    END LOOP;

    IF active_target_grant_count > 1 THEN
        RETURN jsonb_build_object('decision_code', 'SERVICE_UNAVAILABLE');
    END IF;

    IF NOT replay_existing THEN
        IF target_user.aggregate_version <> exact_expected_version THEN
            RETURN jsonb_build_object('decision_code', 'PRECONDITION_FAILED');
        END IF;
        IF exact_operation = 'GRANT_PLATFORM_DUTY'
           AND active_target_grant_count <> 0 THEN
            RETURN jsonb_build_object(
                'decision_code', 'INVALID_STATE_TRANSITION'
            );
        END IF;
        IF exact_operation = 'REVOKE_PLATFORM_DUTY'
           AND active_target_grant_count <> 1 THEN
            RETURN jsonb_build_object(
                'decision_code', 'INVALID_STATE_TRANSITION'
            );
        END IF;
        IF exact_operation = 'REVOKE_PLATFORM_DUTY'
           AND exact_duty_code = 'ACCESS_ADMIN'
           AND target_user.status = 'ACTIVE'
           AND active_admin_count <= 1 THEN
            RETURN jsonb_build_object(
                'decision_code', 'LAST_ACTIVE_ACCESS_ADMIN'
            );
        END IF;
    END IF;

    RETURN jsonb_build_object(
        'decision_code', 'AUTHORIZED',
        'actor_acr_code', actor_session.acr_code,
        'target_user', jsonb_build_object(
            'user_id', target_user.id::text,
            'display_handle', target_user.display_handle,
            'status', target_user.status,
            'aggregate_version', target_user.aggregate_version
        ),
        'platform_duty_grant', CASE
            WHEN active_target_grant_count = 1 THEN jsonb_build_object(
                'grant_id', target_grant.id::text,
                'aggregate_version', target_grant.aggregate_version
            )
            ELSE NULL
        END
    );
END
$function$;

ALTER FUNCTION iam_api.lock_internal_sandbox_platform_duty_admin_v1(
    uuid, uuid, uuid, text, bigint, text, boolean
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam_api.lock_internal_sandbox_platform_duty_admin_v1(
        uuid, uuid, uuid, text, bigint, text, boolean
    )
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam_api.lock_internal_sandbox_platform_duty_admin_v1(
        uuid, uuid, uuid, text, bigint, text, boolean
    )
TO iam_app;

CREATE FUNCTION iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
SELECT
    iam.internal_sandbox_platform_duty_admin_context_v1()
    AND EXISTS (
        SELECT 1
        FROM iam.users AS actor_user
        JOIN infra.iam_sandbox_bootstrap_accounts AS actor_account
          ON actor_account.user_id = actor_user.id
        JOIN infra.iam_sandbox_bootstrap_state AS actor_state
          ON actor_state.bootstrap_id = actor_account.bootstrap_id
         AND actor_state.status = 'ACTIVE'
         AND actor_state.revision = actor_account.manifest_revision
        JOIN iam.sessions AS actor_session
          ON actor_session.id = NULLIF(
                current_setting('app.session_id', true), ''
             )::uuid
         AND actor_session.user_id = actor_user.id
        JOIN iam.session_families AS actor_family
          ON actor_family.id = actor_session.family_id
         AND actor_family.user_id = actor_session.user_id
        JOIN iam.platform_duty_grants AS actor_duty
          ON actor_duty.user_id = actor_user.id
         AND actor_duty.duty_code = 'ACCESS_ADMIN'
        WHERE actor_user.id = NULLIF(
                  current_setting('app.actor_user_id', true), ''
              )::uuid
          AND actor_user.status = 'ACTIVE'
          AND actor_session.status = 'ACTIVE'
          AND actor_session.generation = actor_family.current_generation
          AND actor_session.auth_time <= transaction_timestamp()
          AND actor_session.auth_time
                > transaction_timestamp() - interval '10 minutes'
          AND lower(actor_session.acr_code) LIKE '%mfa%'
          AND actor_session.amr_codes
                && ARRAY['otp', 'mfa', 'webauthn', 'hwk']::text[]
          AND actor_session.last_activity_at < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.absolute_expires_at
          AND actor_family.status = 'ACTIVE'
          AND actor_duty.granted_at <= transaction_timestamp()
          AND actor_duty.revoked_at IS NULL
          AND (
              actor_duty.expires_at IS NULL
              OR transaction_timestamp() < actor_duty.expires_at
          )
    )
    AND EXISTS (
        SELECT 1
        FROM infra.iam_sandbox_bootstrap_accounts AS target_account
        JOIN infra.iam_sandbox_bootstrap_state AS target_state
          ON target_state.bootstrap_id = target_account.bootstrap_id
         AND target_state.status = 'ACTIVE'
         AND target_state.revision = target_account.manifest_revision
        WHERE target_account.user_id = NULLIF(
                  current_setting('app.target_user_id', true), ''
              )::uuid
    )
$function$;

ALTER FUNCTION iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
TO iam_app;

CREATE FUNCTION iam.enforce_internal_sandbox_platform_duty_user_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
BEGIN
    IF NULLIF(current_setting('app.scope_kind', true), '')
        IS DISTINCT FROM 'INTERNAL_SANDBOX_PLATFORM_DUTY_ADMIN' THEN
        RETURN NEW;
    END IF;
    IF session_user IS DISTINCT FROM 'iam_app'
       OR NOT iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
       OR OLD.id::text IS DISTINCT FROM NULLIF(
            current_setting('app.target_user_id', true), ''
       )
       OR OLD.aggregate_version::text IS DISTINCT FROM NULLIF(
            current_setting('app.expected_version', true), ''
       )
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.display_handle IS DISTINCT FROM OLD.display_handle
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_sandbox_platform_duty_user_transition',
            MESSAGE = 'invalid sandbox platform duty User transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_sandbox_platform_duty_user_transition
BEFORE UPDATE ON iam.users
FOR EACH ROW EXECUTE FUNCTION
    iam.enforce_internal_sandbox_platform_duty_user_transition();

CREATE FUNCTION iam.enforce_internal_sandbox_platform_duty_grant_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
BEGIN
    IF NULLIF(current_setting('app.scope_kind', true), '')
        IS DISTINCT FROM 'INTERNAL_SANDBOX_PLATFORM_DUTY_ADMIN' THEN
        RETURN NEW;
    END IF;
    IF session_user IS DISTINCT FROM 'iam_app'
       OR NOT iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
       OR NEW.user_id::text IS DISTINCT FROM NULLIF(
            current_setting('app.target_user_id', true), ''
       )
       OR NEW.duty_code IS DISTINCT FROM NULLIF(
            current_setting('app.duty_code', true), ''
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_sandbox_platform_duty_grant_transition',
            MESSAGE = 'invalid sandbox platform duty grant transition';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NULLIF(current_setting('app.operation', true), '')
                IS DISTINCT FROM 'GRANT_PLATFORM_DUTY'
           OR NEW.granted_by_kind <> 'USER'
           OR NEW.granted_by_id::text IS DISTINCT FROM NULLIF(
                current_setting('app.actor_user_id', true), ''
           )
           OR NEW.granted_at IS DISTINCT FROM transaction_timestamp()
           OR NEW.expires_at IS NOT NULL
           OR NEW.revoked_at IS NOT NULL
           OR NEW.revocation_reason_code IS NOT NULL
           OR NEW.aggregate_version <> 1
           OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
           OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_sandbox_platform_duty_grant_transition',
                MESSAGE = 'invalid sandbox platform duty grant insert';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NULLIF(current_setting('app.operation', true), '')
                IS DISTINCT FROM 'REVOKE_PLATFORM_DUTY'
           OR OLD.revoked_at IS NOT NULL
           OR NEW.id IS DISTINCT FROM OLD.id
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.duty_code IS DISTINCT FROM OLD.duty_code
           OR NEW.granted_by_kind IS DISTINCT FROM OLD.granted_by_kind
           OR NEW.granted_by_id IS DISTINCT FROM OLD.granted_by_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
           OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.revoked_at IS DISTINCT FROM transaction_timestamp()
           OR NEW.revocation_reason_code IS DISTINCT FROM NULLIF(
                current_setting('app.reason_code', true), ''
           )
           OR NEW.aggregate_version <> OLD.aggregate_version + 1
           OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_sandbox_platform_duty_grant_transition',
                MESSAGE = 'invalid sandbox platform duty grant revocation';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_sandbox_platform_duty_grant_transition
BEFORE INSERT OR UPDATE ON iam.platform_duty_grants
FOR EACH ROW EXECUTE FUNCTION
    iam.enforce_internal_sandbox_platform_duty_grant_transition();

GRANT INSERT, UPDATE ON iam.platform_duty_grants TO iam_app;

CREATE POLICY rls_sandbox_duty_admin_user_select
ON iam.users
FOR SELECT TO iam_app
USING (
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

CREATE POLICY rls_sandbox_duty_admin_user_update
ON iam.users
FOR UPDATE TO iam_app
USING (
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status IN ('ACTIVE', 'SUSPENDED')
);

CREATE POLICY rls_sandbox_duty_admin_grant_select
ON iam.platform_duty_grants
FOR SELECT TO iam_app
USING (
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND duty_code = NULLIF(current_setting('app.duty_code', true), '')
);

CREATE POLICY rls_sandbox_duty_admin_grant_insert
ON iam.platform_duty_grants
FOR INSERT TO iam_app
WITH CHECK (
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
    AND NULLIF(current_setting('app.operation', true), '')
        = 'GRANT_PLATFORM_DUTY'
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND duty_code = NULLIF(current_setting('app.duty_code', true), '')
    AND granted_by_kind = 'USER'
    AND granted_by_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND revoked_at IS NULL
);

CREATE POLICY rls_sandbox_duty_admin_grant_update
ON iam.platform_duty_grants
FOR UPDATE TO iam_app
USING (
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
    AND NULLIF(current_setting('app.operation', true), '')
        = 'REVOKE_PLATFORM_DUTY'
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND duty_code = NULLIF(current_setting('app.duty_code', true), '')
    AND revoked_at IS NULL
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND duty_code = NULLIF(current_setting('app.duty_code', true), '')
    AND revoked_at = transaction_timestamp()
    AND revocation_reason_code = NULLIF(
        current_setting('app.reason_code', true), ''
    )
);

CREATE POLICY rls_sandbox_duty_admin_receipt
ON infra.command_receipts
FOR ALL TO iam_app
USING (
    iam_api.internal_sandbox_platform_duty_admin_authorized_v1()
    AND principal_kind = 'USER'
    AND principal_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND target_kind = 'User'
    AND target_id::text = NULLIF(
        current_setting('app.target_user_id', true), ''
    )
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = 1
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true), ''
    )
    AND idempotency_key_digest = decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''), 'hex'
    )
)
WITH CHECK (
    principal_kind = 'USER'
    AND principal_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND target_kind = 'User'
    AND target_id::text = NULLIF(
        current_setting('app.target_user_id', true), ''
    )
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = 1
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true), ''
    )
    AND idempotency_key_digest = decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''), 'hex'
    )
);

-- V2 keeps roleless synthetic accounts visible and admits the complete closed
-- set of three invitation-bound roles plus five platform duties.
CREATE FUNCTION iam_api.read_internal_sandbox_account_workbench_v2(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_user_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    operation_name text;
    active_state_count integer;
    active_account_count integer;
    stored_account_count integer;
    expected_result_count integer;
    actor_authorized boolean;
    result_document jsonb;
BEGIN
    operation_name := NULLIF(current_setting('app.operation', true), '');
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'INTERNAL_SANDBOX_ACCOUNT_ADMIN_READ'
       OR operation_name NOT IN ('LIST_ACCOUNTS', 'GET_ACCOUNT')
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
       OR current_setting('transaction_read_only') IS DISTINCT FROM 'on'
       OR current_setting('transaction_isolation')
            IS DISTINCT FROM 'repeatable read'
       OR (
            operation_name = 'LIST_ACCOUNTS'
            AND (
                exact_target_user_id IS NOT NULL
                OR NULLIF(
                    current_setting('app.target_user_id', true), ''
                ) IS NOT NULL
            )
       )
       OR (
            operation_name = 'GET_ACCOUNT'
            AND (
                exact_target_user_id IS NULL
                OR exact_target_user_id = zero_uuid
                OR NULLIF(
                    current_setting('app.target_user_id', true), ''
                ) IS DISTINCT FROM exact_target_user_id::text
            )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_sandbox_account_workbench_v2_context',
            MESSAGE = 'internal sandbox account workbench v2 context is invalid';
    END IF;

    SELECT count(*), COALESCE(sum(state.account_count), 0)
    INTO active_state_count, active_account_count
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.status = 'ACTIVE';

    SELECT count(*)
    INTO stored_account_count
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision;

    IF active_state_count <> 1
       OR active_account_count NOT BETWEEN 1 AND 16
       OR stored_account_count <> active_account_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_sandbox_account_workbench_v2_bootstrap',
            MESSAGE = 'internal sandbox account workbench v2 bootstrap is invalid';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM iam.users AS actor_user
        JOIN infra.iam_sandbox_bootstrap_accounts AS actor_account
          ON actor_account.user_id = actor_user.id
        JOIN infra.iam_sandbox_bootstrap_state AS actor_state
          ON actor_state.bootstrap_id = actor_account.bootstrap_id
         AND actor_state.status = 'ACTIVE'
         AND actor_state.revision = actor_account.manifest_revision
        JOIN iam.sessions AS actor_session
          ON actor_session.id = exact_session_id
         AND actor_session.user_id = actor_user.id
        JOIN iam.session_families AS actor_family
          ON actor_family.id = actor_session.family_id
         AND actor_family.user_id = actor_session.user_id
        JOIN iam.platform_duty_grants AS actor_duty
          ON actor_duty.user_id = actor_user.id
         AND actor_duty.duty_code = 'ACCESS_ADMIN'
        WHERE actor_user.id = exact_actor_user_id
          AND actor_user.status = 'ACTIVE'
          AND actor_session.status = 'ACTIVE'
          AND actor_session.generation = actor_family.current_generation
          AND actor_session.auth_time <= transaction_timestamp()
          AND actor_session.last_activity_at <= transaction_timestamp()
          AND actor_session.last_activity_at < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.absolute_expires_at
          AND actor_family.status = 'ACTIVE'
          AND actor_duty.granted_at <= transaction_timestamp()
          AND actor_duty.revoked_at IS NULL
          AND (
              actor_duty.expires_at IS NULL
              OR transaction_timestamp() < actor_duty.expires_at
          )
    ) INTO actor_authorized;

    IF NOT actor_authorized THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_sandbox_account_workbench_v2_authority',
            MESSAGE = 'internal sandbox account workbench v2 authority unavailable';
    END IF;

    SELECT count(*)
    INTO expected_result_count
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision
    WHERE exact_target_user_id IS NULL
       OR account.user_id = exact_target_user_id;

    WITH active_accounts AS (
        SELECT account.account_code, account.user_id
        FROM infra.iam_sandbox_bootstrap_accounts AS account
        JOIN infra.iam_sandbox_bootstrap_state AS state
          ON state.bootstrap_id = account.bootstrap_id
         AND state.status = 'ACTIVE'
         AND state.revision = account.manifest_revision
        WHERE exact_target_user_id IS NULL
           OR account.user_id = exact_target_user_id
    ),
    role_edges AS (
        SELECT account.user_id, grant_row.role_code
        FROM active_accounts AS account
        JOIN iam.user_role_grants AS grant_row
          ON grant_row.user_id = account.user_id
         AND grant_row.revoked_at IS NULL
        UNION ALL
        SELECT account.user_id, grant_row.role_code
        FROM active_accounts AS account
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.user_id = account.user_id
         AND grant_row.revoked_at IS NULL
        UNION ALL
        SELECT account.user_id, grant_row.duty_code
        FROM active_accounts AS account
        JOIN iam.platform_duty_grants AS grant_row
          ON grant_row.user_id = account.user_id
         AND grant_row.revoked_at IS NULL
         AND grant_row.granted_at <= transaction_timestamp()
         AND (
             grant_row.expires_at IS NULL
             OR transaction_timestamp() < grant_row.expires_at
         )
    ),
    effective_roles AS (
        SELECT
            account.user_id,
            COALESCE(
                pg_catalog.array_agg(
                    DISTINCT edge.role_code ORDER BY edge.role_code
                ) FILTER (WHERE edge.role_code IS NOT NULL),
                ARRAY[]::text[]
            ) AS role_codes
        FROM active_accounts AS account
        LEFT JOIN role_edges AS edge ON edge.user_id = account.user_id
        GROUP BY account.user_id
        HAVING count(DISTINCT edge.role_code) BETWEEN 0 AND 8
    ),
    projected_accounts AS (
        SELECT
            account.account_code,
            exact_user.id AS user_id,
            exact_user.display_handle,
            exact_user.status,
            exact_user.aggregate_version,
            roles.role_codes,
            session_count.active_session_count,
            exact_user.created_at,
            exact_user.updated_at
        FROM active_accounts AS account
        JOIN iam.users AS exact_user
          ON exact_user.id = account.user_id
         AND exact_user.status IN ('ACTIVE', 'SUSPENDED')
        JOIN effective_roles AS roles ON roles.user_id = exact_user.id
        CROSS JOIN LATERAL (
            SELECT count(*)::integer AS active_session_count
            FROM iam.sessions AS exact_session
            JOIN iam.session_families AS exact_family
              ON exact_family.id = exact_session.family_id
             AND exact_family.user_id = exact_session.user_id
            WHERE exact_session.user_id = exact_user.id
              AND exact_session.status = 'ACTIVE'
              AND exact_session.generation = exact_family.current_generation
              AND exact_session.last_activity_at <= transaction_timestamp()
              AND exact_session.last_activity_at < exact_session.idle_expires_at
              AND transaction_timestamp() < exact_session.idle_expires_at
              AND transaction_timestamp() < exact_session.absolute_expires_at
              AND exact_family.status = 'ACTIVE'
        ) AS session_count
        WHERE session_count.active_session_count BETWEEN 0 AND 64
    ),
    account_documents AS (
        SELECT
            account.account_code,
            pg_catalog.jsonb_build_object(
                'account_code', account.account_code,
                'user_id', account.user_id::text,
                'display_handle', account.display_handle,
                'status', account.status,
                'aggregate_version', account.aggregate_version,
                'entity_tag', '"v' || account.aggregate_version::text || '"',
                'role_codes', pg_catalog.to_jsonb(account.role_codes),
                'active_session_count', account.active_session_count,
                'created_at', pg_catalog.to_jsonb(account.created_at),
                'updated_at', pg_catalog.to_jsonb(account.updated_at),
                'is_self', account.user_id = exact_actor_user_id
            ) AS document
        FROM projected_accounts AS account
    )
    SELECT pg_catalog.jsonb_build_object(
        'schema_version', 'internal-sandbox-account-admin-v1',
        'evaluated_at', pg_catalog.to_jsonb(transaction_timestamp()),
        'accounts', COALESCE(
            pg_catalog.jsonb_agg(
                account.document ORDER BY account.account_code
            ),
            '[]'::jsonb
        )
    )
    INTO result_document
    FROM account_documents AS account;

    IF pg_catalog.jsonb_typeof(result_document) <> 'object'
       OR pg_catalog.jsonb_typeof(result_document->'accounts') <> 'array'
       OR pg_catalog.jsonb_array_length(result_document->'accounts')
            <> expected_result_count
       OR (
            operation_name = 'LIST_ACCOUNTS'
            AND expected_result_count NOT BETWEEN 1 AND 16
       )
       OR (
            operation_name = 'GET_ACCOUNT'
            AND expected_result_count NOT BETWEEN 0 AND 1
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_sandbox_account_workbench_v2_projection',
            MESSAGE = 'internal sandbox account workbench v2 projection invalid';
    END IF;

    RETURN result_document;
END
$function$;

ALTER FUNCTION iam_api.read_internal_sandbox_account_workbench_v2(
    uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam_api.read_internal_sandbox_account_workbench_v2(uuid, uuid, uuid)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam_api.read_internal_sandbox_account_workbench_v2(uuid, uuid, uuid)
TO iam_app;

DO $assertions$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.lock_internal_sandbox_platform_duty_admin_v1(uuid,uuid,uuid,text,bigint,text,boolean)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.read_internal_sandbox_account_workbench_v2(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam_api.lock_internal_sandbox_platform_duty_admin_v1(uuid,uuid,uuid,text,bigint,text,boolean)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam_api.read_internal_sandbox_account_workbench_v2(uuid,uuid,uuid)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_table_privilege(
        'iam_app', 'iam.platform_duty_grants', 'SELECT,INSERT,UPDATE'
    ) OR pg_catalog.has_table_privilege(
        'iam_app', 'iam.platform_duty_grants', 'DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sandbox platform duty administration assertion failed';
    END IF;
END
$assertions$;
