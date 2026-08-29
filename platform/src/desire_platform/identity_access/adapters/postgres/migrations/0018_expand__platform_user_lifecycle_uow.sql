-- Exact iam_app boundary for ACCESS_ADMIN user/session lifecycle commands.

ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_platform_user_admin_response CHECK (
    command_name NOT IN ('SuspendUser', 'ResumeUser', 'RevokeAllSessions')
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
                AND safe_response_body ->> 'revoked_session_count'
                    ~ '^(0|[1-9][0-9]*)$'
                AND safe_response_body ->> 'revoked_session_family_count'
                    ~ '^(0|[1-9][0-9]*)$'
            )
        )
        AND (
            (
                command_name = 'SuspendUser'
                AND canonical_path = '/v1/platform/users/'
                    || target_id::text || '/suspend'
            )
            OR (
                command_name = 'ResumeUser'
                AND canonical_path = '/v1/platform/users/'
                    || target_id::text || '/resume'
            )
            OR (
                command_name = 'RevokeAllSessions'
                AND canonical_path = '/v1/platform/users/'
                    || target_id::text || '/revoke-all-sessions'
            )
        )
    )
);

-- SECURITY DEFINER functions execute as schema_owner, whose rows remain
-- constrained because every IAM table uses FORCE ROW LEVEL SECURITY.
CREATE POLICY rls_platform_admin_user_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PLATFORM_USER_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
    )
    AND (
        id::text = NULLIF(current_setting('app.actor_user_id', true), '')
        OR id::text = NULLIF(current_setting('app.target_user_id', true), '')
        OR EXISTS (
            SELECT 1
            FROM iam.platform_duty_grants AS access_grant
            WHERE access_grant.user_id = users.id
              AND access_grant.duty_code = 'ACCESS_ADMIN'
              AND access_grant.granted_at <= transaction_timestamp()
              AND access_grant.revoked_at IS NULL
              AND (
                  access_grant.expires_at IS NULL
                  OR transaction_timestamp() < access_grant.expires_at
              )
        )
    )
);

CREATE POLICY rls_platform_admin_family_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PLATFORM_USER_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
    )
    AND user_id::text IN (
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.target_user_id', true), '')
    )
);

CREATE POLICY rls_platform_admin_session_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PLATFORM_USER_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
    )
    AND user_id::text IN (
        NULLIF(current_setting('app.actor_user_id', true), ''),
        NULLIF(current_setting('app.target_user_id', true), '')
    )
);

CREATE POLICY rls_platform_admin_duty_definer
ON iam.platform_duty_grants
FOR ALL TO schema_owner
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PLATFORM_USER_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
    )
    AND duty_code = 'ACCESS_ADMIN'
);

CREATE FUNCTION iam_api.platform_user_admin_context_authorized_v1()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
SELECT
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PLATFORM_USER_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
    )
    AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.target_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_user_id', true), '')
        <> NULLIF(current_setting('app.target_user_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS actor_session
        JOIN iam.session_families AS actor_family
          ON actor_family.id = actor_session.family_id
         AND actor_family.user_id = actor_session.user_id
        JOIN iam.users AS actor_user
          ON actor_user.id = actor_session.user_id
        WHERE actor_session.id = NULLIF(
                  current_setting('app.session_id', true), ''
              )::uuid
          AND actor_session.user_id = NULLIF(
                  current_setting('app.actor_user_id', true), ''
              )::uuid
          AND actor_session.status = 'ACTIVE'
          AND actor_session.generation = actor_family.current_generation
          AND actor_session.last_activity_at < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.idle_expires_at
          AND transaction_timestamp() < actor_session.absolute_expires_at
          AND actor_session.auth_time <= transaction_timestamp()
          AND actor_session.auth_time
              > transaction_timestamp() - interval '10 minutes'
          AND lower(actor_session.acr_code) LIKE '%mfa%'
          AND actor_session.amr_codes
              && ARRAY['otp', 'mfa', 'webauthn', 'hwk']::text[]
          AND actor_family.status = 'ACTIVE'
          AND actor_user.status = 'ACTIVE'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.platform_duty_grants AS actor_grant
        WHERE actor_grant.user_id = NULLIF(
                  current_setting('app.actor_user_id', true), ''
              )::uuid
          AND actor_grant.duty_code = 'ACCESS_ADMIN'
          AND actor_grant.granted_at <= transaction_timestamp()
          AND actor_grant.revoked_at IS NULL
          AND (
              actor_grant.expires_at IS NULL
              OR transaction_timestamp() < actor_grant.expires_at
          )
    )
$function$;

CREATE FUNCTION iam_api.lock_platform_user_admin_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_user_id uuid,
    exact_operation text,
    exact_expected_version bigint,
    replay_existing boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    actor_family iam.session_families%ROWTYPE;
    actor_session iam.sessions%ROWTYPE;
    actor_user iam.users%ROWTYPE;
    target_user iam.users%ROWTYPE;
    locked_user iam.users%ROWTYPE;
    locked_grant iam.platform_duty_grants%ROWTYPE;
    actor_grant_count integer := 0;
    active_admin_count integer := 0;
    target_is_active_admin boolean := false;
    target_families jsonb := '[]'::jsonb;
    target_sessions jsonb := '[]'::jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_target_user_id IS NULL
       OR exact_actor_user_id = exact_target_user_id
       OR exact_expected_version IS NULL
       OR exact_expected_version < 1
       OR exact_operation NOT IN (
            'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'PLATFORM_USER_ADMIN'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_target_user_id::text
       OR NULLIF(current_setting('app.expected_version', true), '')
            IS DISTINCT FROM exact_expected_version::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_platform_admin_exact_context',
            MESSAGE = 'platform user administration context is invalid';
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
            actor_grant_count := actor_grant_count + 1;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM iam.users AS active_admin
            WHERE active_admin.id = locked_grant.user_id
              AND active_admin.status = 'ACTIVE'
        ) THEN
            active_admin_count := active_admin_count + 1;
            IF locked_grant.user_id = exact_target_user_id THEN
                target_is_active_admin := true;
            END IF;
        END IF;
    END LOOP;
    IF actor_grant_count = 0 THEN
        RETURN jsonb_build_object('decision_code', 'RESOURCE_NOT_FOUND');
    ELSIF actor_grant_count <> 1 THEN
        RETURN jsonb_build_object('decision_code', 'SERVICE_UNAVAILABLE');
    END IF;
    IF exact_actor_user_id = exact_target_user_id THEN
        RETURN jsonb_build_object('decision_code', 'SELF_MANAGEMENT_FORBIDDEN');
    END IF;
    IF target_user.id IS NULL THEN
        RETURN jsonb_build_object('decision_code', 'RESOURCE_NOT_FOUND');
    END IF;
    IF exact_operation = 'SUSPEND_USER'
       AND target_is_active_admin
       AND active_admin_count <= 1 THEN
        RETURN jsonb_build_object(
            'decision_code', 'LAST_ACTIVE_ACCESS_ADMIN'
        );
    END IF;

    IF NOT replay_existing THEN
        IF (
            exact_operation = 'SUSPEND_USER'
            AND target_user.status <> 'ACTIVE'
        ) OR (
            exact_operation = 'RESUME_USER'
            AND target_user.status <> 'SUSPENDED'
        ) OR (
            exact_operation = 'REVOKE_ALL_SESSIONS'
            AND target_user.status NOT IN ('ACTIVE', 'SUSPENDED')
        ) THEN
            RETURN jsonb_build_object(
                'decision_code', 'INVALID_STATE_TRANSITION'
            );
        END IF;
        IF target_user.aggregate_version <> exact_expected_version THEN
            RETURN jsonb_build_object('decision_code', 'PRECONDITION_FAILED');
        END IF;
    END IF;

    PERFORM family.id
    FROM iam.session_families AS family
    WHERE family.user_id = exact_target_user_id
      AND family.status = 'ACTIVE'
    ORDER BY family.id
    FOR UPDATE;
    PERFORM session_row.id
    FROM iam.sessions AS session_row
    WHERE session_row.user_id = exact_target_user_id
      AND session_row.status = 'ACTIVE'
    ORDER BY session_row.id
    FOR UPDATE;

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'session_family_id', family.id::text,
                'aggregate_version', family.aggregate_version
            ) ORDER BY family.id
        ),
        '[]'::jsonb
    )
    INTO target_families
    FROM iam.session_families AS family
    WHERE family.user_id = exact_target_user_id
      AND family.status = 'ACTIVE';

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'session_id', session_row.id::text,
                'session_family_id', session_row.family_id::text,
                'aggregate_version', session_row.aggregate_version
            ) ORDER BY session_row.id
        ),
        '[]'::jsonb
    )
    INTO target_sessions
    FROM iam.sessions AS session_row
    WHERE session_row.user_id = exact_target_user_id
      AND session_row.status = 'ACTIVE';

    RETURN jsonb_build_object(
        'decision_code', 'AUTHORIZED',
        'actor_acr_code', actor_session.acr_code,
        'target_user', jsonb_build_object(
            'user_id', target_user.id::text,
            'display_handle', target_user.display_handle,
            'status', target_user.status,
            'aggregate_version', target_user.aggregate_version
        ),
        'active_session_families', target_families,
        'active_sessions', target_sessions
    );
END
$function$;

CREATE FUNCTION iam.enforce_platform_admin_user_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
BEGIN
    IF NULLIF(current_setting('app.scope_kind', true), '')
        IS DISTINCT FROM 'PLATFORM_USER_ADMIN' THEN
        RETURN NEW;
    END IF;
    IF session_user IS DISTINCT FROM 'iam_app'
       OR NOT iam_api.platform_user_admin_context_authorized_v1()
       OR OLD.id::text IS DISTINCT FROM NULLIF(
            current_setting('app.target_user_id', true), ''
       )
       OR OLD.aggregate_version::text IS DISTINCT FROM NULLIF(
            current_setting('app.expected_version', true), ''
       )
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.display_handle IS DISTINCT FROM OLD.display_handle
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_platform_admin_user_transition',
            MESSAGE = 'invalid platform user administration transition';
    END IF;
    IF (
        NULLIF(current_setting('app.operation', true), '') = 'SUSPEND_USER'
        AND (OLD.status <> 'ACTIVE' OR NEW.status <> 'SUSPENDED')
    ) OR (
        NULLIF(current_setting('app.operation', true), '') = 'RESUME_USER'
        AND (OLD.status <> 'SUSPENDED' OR NEW.status <> 'ACTIVE')
    ) OR (
        NULLIF(current_setting('app.operation', true), '')
            = 'REVOKE_ALL_SESSIONS'
        AND (
            OLD.status NOT IN ('ACTIVE', 'SUSPENDED')
            OR NEW.status IS DISTINCT FROM OLD.status
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_platform_admin_user_transition',
            MESSAGE = 'invalid platform user administration state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_platform_admin_user_transition
BEFORE UPDATE ON iam.users
FOR EACH ROW EXECUTE FUNCTION iam.enforce_platform_admin_user_transition();

GRANT UPDATE (status, aggregate_version, updated_at) ON iam.users TO iam_app;
GRANT UPDATE (
    status, revoked_at, revocation_reason_code, aggregate_version, updated_at
) ON iam.session_families TO iam_app;
GRANT UPDATE (
    status, revoked_at, revocation_reason_code, aggregate_version, updated_at
) ON iam.sessions TO iam_app;

CREATE POLICY rls_platform_admin_user_select
ON iam.users
FOR SELECT TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

CREATE POLICY rls_platform_admin_user_update
ON iam.users
FOR UPDATE TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status IN ('ACTIVE', 'SUSPENDED')
);

CREATE POLICY rls_platform_admin_family_select
ON iam.session_families
FOR SELECT TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

CREATE POLICY rls_platform_admin_family_update
ON iam.session_families
FOR UPDATE TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status = 'ACTIVE'
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status = 'REVOKED'
    AND revoked_at = transaction_timestamp()
    AND revocation_reason_code = NULLIF(
        current_setting('app.reason_code', true), ''
    )
);

CREATE POLICY rls_platform_admin_session_select
ON iam.sessions
FOR SELECT TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

CREATE POLICY rls_platform_admin_session_update
ON iam.sessions
FOR UPDATE TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status = 'ACTIVE'
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status = 'REVOKED'
    AND revoked_at = transaction_timestamp()
    AND revocation_reason_code = NULLIF(
        current_setting('app.reason_code', true), ''
    )
);

CREATE POLICY rls_platform_admin_receipt
ON infra.command_receipts
FOR ALL TO iam_app
USING (
    iam_api.platform_user_admin_context_authorized_v1()
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PLATFORM_USER_ADMIN'
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

REVOKE ALL ON FUNCTION iam_api.platform_user_admin_context_authorized_v1()
FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.lock_platform_user_admin_v1(
    uuid, uuid, uuid, text, bigint, boolean
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.platform_user_admin_context_authorized_v1()
TO iam_app;
GRANT EXECUTE ON FUNCTION iam_api.lock_platform_user_admin_v1(
    uuid, uuid, uuid, text, bigint, boolean
) TO iam_app;
