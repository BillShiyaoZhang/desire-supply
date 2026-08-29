-- IAM 0032: close the synthetic account-administration boundary.
--
-- The legacy lifecycle program remains byte-frozen.  This forward migration
-- wraps it with an exact active-bootstrap target gate, adds a boolean-only
-- command-scope receipt probe, and converges expired duty rows before regrant.

CREATE FUNCTION iam.internal_sandbox_platform_user_admin_context_v2()
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
        = 'PLATFORM_USER_ADMIN'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
    )
    AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.target_user_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_user_id', true), '')
        <> NULLIF(current_setting('app.target_user_id', true), '')
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
$function$;

ALTER FUNCTION iam.internal_sandbox_platform_user_admin_context_v2()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam.internal_sandbox_platform_user_admin_context_v2()
FROM PUBLIC;

-- FORCE RLS also constrains SECURITY DEFINER reads of the bootstrap graph.
CREATE POLICY rls_sandbox_platform_user_admin_state_definer
ON infra.iam_sandbox_bootstrap_state
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_platform_user_admin_context_v2());

CREATE POLICY rls_sandbox_platform_user_admin_accounts_definer
ON infra.iam_sandbox_bootstrap_accounts
FOR SELECT TO schema_owner
USING (iam.internal_sandbox_platform_user_admin_context_v2());

CREATE FUNCTION iam_api.validate_internal_sandbox_platform_user_admin_target_v2(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_user_id uuid,
    exact_operation text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    active_state infra.iam_sandbox_bootstrap_state%ROWTYPE;
    active_state_count integer := 0;
    stored_account_count integer := 0;
    actor_found boolean := false;
    target_found boolean := false;
BEGIN
    IF exact_actor_user_id IS NOT NULL
       AND exact_actor_user_id = exact_target_user_id THEN
        RETURN 'SELF_MANAGEMENT_FORBIDDEN';
    END IF;
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_target_user_id IS NULL
       OR exact_target_user_id = zero_uuid
       OR exact_operation NOT IN (
            'SUSPEND_USER', 'RESUME_USER', 'REVOKE_ALL_SESSIONS'
       )
       OR NOT iam.internal_sandbox_platform_user_admin_context_v2()
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_target_user_id::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_sandbox_platform_user_admin_target_v2_context',
            MESSAGE = 'sandbox platform user administration context is invalid';
    END IF;

    -- Serialize with both the current v3 and the byte-frozen legacy bootstrap
    -- writers before observing the active revision.
    PERFORM pg_catalog.pg_advisory_xact_lock(1229016369, 31);
    PERFORM pg_catalog.pg_advisory_xact_lock(1229016369, 23);

    SELECT count(*)
    INTO active_state_count
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.status = 'ACTIVE';
    IF active_state_count <> 1 THEN
        RETURN 'SERVICE_UNAVAILABLE';
    END IF;

    SELECT state.*
    INTO active_state
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.status = 'ACTIVE'
    FOR SHARE;
    IF active_state.account_count NOT BETWEEN 2 AND 16 THEN
        RETURN 'SERVICE_UNAVAILABLE';
    END IF;

    SELECT count(*)
    INTO stored_account_count
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    WHERE account.bootstrap_id = active_state.bootstrap_id
      AND account.manifest_revision = active_state.revision;
    IF stored_account_count <> active_state.account_count THEN
        RETURN 'SERVICE_UNAVAILABLE';
    END IF;

    PERFORM account.user_id
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision
    WHERE account.user_id IN (exact_actor_user_id, exact_target_user_id)
    ORDER BY account.user_id
    FOR SHARE OF account;

    SELECT
        COALESCE(bool_or(account.user_id = exact_actor_user_id), false),
        COALESCE(bool_or(account.user_id = exact_target_user_id), false)
    INTO actor_found, target_found
    FROM infra.iam_sandbox_bootstrap_accounts AS account
    JOIN infra.iam_sandbox_bootstrap_state AS state
      ON state.bootstrap_id = account.bootstrap_id
     AND state.status = 'ACTIVE'
     AND state.revision = account.manifest_revision
    WHERE account.user_id IN (exact_actor_user_id, exact_target_user_id);

    IF NOT actor_found THEN
        RETURN 'SERVICE_UNAVAILABLE';
    END IF;
    IF NOT target_found THEN
        RETURN 'RESOURCE_NOT_FOUND';
    END IF;
    RETURN 'AUTHORIZED';
END
$function$;

ALTER FUNCTION
    iam_api.validate_internal_sandbox_platform_user_admin_target_v2(
        uuid, uuid, uuid, text
    )
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam_api.validate_internal_sandbox_platform_user_admin_target_v2(
        uuid, uuid, uuid, text
    )
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam_api.validate_internal_sandbox_platform_user_admin_target_v2(
        uuid, uuid, uuid, text
    )
TO iam_app;

CREATE FUNCTION iam_api.internal_sandbox_platform_user_admin_authorized_v2()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, iam_api
AS $function$
SELECT
    iam_api.platform_user_admin_context_authorized_v1()
    AND EXISTS (
        SELECT 1
        FROM infra.iam_sandbox_bootstrap_state AS state
        JOIN infra.iam_sandbox_bootstrap_accounts AS actor_account
          ON actor_account.bootstrap_id = state.bootstrap_id
         AND actor_account.manifest_revision = state.revision
        JOIN infra.iam_sandbox_bootstrap_accounts AS target_account
          ON target_account.bootstrap_id = state.bootstrap_id
         AND target_account.manifest_revision = state.revision
        WHERE state.status = 'ACTIVE'
          AND actor_account.user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
              )::uuid
          AND target_account.user_id = NULLIF(
                current_setting('app.target_user_id', true), ''
              )::uuid
          AND state.account_count BETWEEN 2 AND 16
          AND state.account_count = (
                SELECT count(*)
                FROM infra.iam_sandbox_bootstrap_accounts AS exact_account
                WHERE exact_account.bootstrap_id = state.bootstrap_id
                  AND exact_account.manifest_revision = state.revision
          )
          AND 1 = (
                SELECT count(*)
                FROM infra.iam_sandbox_bootstrap_state AS active_state
                WHERE active_state.status = 'ACTIVE'
          )
    )
$function$;

ALTER FUNCTION iam_api.internal_sandbox_platform_user_admin_authorized_v2()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
TO iam_app;

CREATE FUNCTION iam_api.lock_internal_sandbox_platform_user_admin_v2(
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
SET search_path = pg_catalog, iam_api
AS $function$
DECLARE
    target_decision text;
BEGIN
    target_decision :=
        iam_api.validate_internal_sandbox_platform_user_admin_target_v2(
            exact_actor_user_id,
            exact_session_id,
            exact_target_user_id,
            exact_operation
        );
    IF target_decision <> 'AUTHORIZED' THEN
        RETURN jsonb_build_object('decision_code', target_decision);
    END IF;
    RETURN iam_api.lock_platform_user_admin_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_target_user_id,
        exact_operation,
        exact_expected_version,
        replay_existing
    );
END
$function$;

ALTER FUNCTION iam_api.lock_internal_sandbox_platform_user_admin_v2(
    uuid, uuid, uuid, text, bigint, boolean
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.lock_internal_sandbox_platform_user_admin_v2(
    uuid, uuid, uuid, text, bigint, boolean
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.lock_internal_sandbox_platform_user_admin_v2(
    uuid, uuid, uuid, text, bigint, boolean
) TO iam_app;
REVOKE EXECUTE ON FUNCTION iam_api.lock_platform_user_admin_v1(
    uuid, uuid, uuid, text, bigint, boolean
) FROM iam_app;

-- Replace the runtime policies: the target must be in the same exact active
-- synthetic bootstrap as the authenticated ACCESS_ADMIN actor.
DROP POLICY rls_platform_admin_user_select ON iam.users;
CREATE POLICY rls_platform_admin_user_select
ON iam.users
FOR SELECT TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

DROP POLICY rls_platform_admin_user_update ON iam.users;
CREATE POLICY rls_platform_admin_user_update
ON iam.users
FOR UPDATE TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
    AND id::text = NULLIF(current_setting('app.target_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.target_user_id', true), '')
    AND status IN ('ACTIVE', 'SUSPENDED')
);

DROP POLICY rls_platform_admin_family_select ON iam.session_families;
CREATE POLICY rls_platform_admin_family_select
ON iam.session_families
FOR SELECT TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

DROP POLICY rls_platform_admin_family_update ON iam.session_families;
CREATE POLICY rls_platform_admin_family_update
ON iam.session_families
FOR UPDATE TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
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

DROP POLICY rls_platform_admin_session_select ON iam.sessions;
CREATE POLICY rls_platform_admin_session_select
ON iam.sessions
FOR SELECT TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
    AND user_id::text = NULLIF(current_setting('app.target_user_id', true), '')
);

DROP POLICY rls_platform_admin_session_update ON iam.sessions;
CREATE POLICY rls_platform_admin_session_update
ON iam.sessions
FOR UPDATE TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
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

DROP POLICY rls_platform_admin_receipt ON infra.command_receipts;
CREATE POLICY rls_platform_admin_receipt
ON infra.command_receipts
FOR ALL TO iam_app
USING (
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
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
    iam_api.internal_sandbox_platform_user_admin_authorized_v2()
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
);

CREATE OR REPLACE FUNCTION iam.enforce_platform_admin_user_transition()
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
       OR NOT iam_api.internal_sandbox_platform_user_admin_authorized_v2()
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

-- Generic audit/outbox grants stay usable for other IAM programs; restrictive
-- policies add the synthetic target condition only for this lifecycle scope.
CREATE POLICY rls_sandbox_platform_user_admin_audit_restrict
ON audit.audit_events AS RESTRICTIVE
FOR INSERT TO iam_app
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '')
        IS DISTINCT FROM 'PLATFORM_USER_ADMIN'
    OR (
        iam_api.internal_sandbox_platform_user_admin_authorized_v2()
        AND actor_kind = 'USER'
        AND actor_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
        AND action_code = NULLIF(current_setting('app.command_name', true), '')
        AND target_kind = 'User'
        AND target_id::text = NULLIF(
            current_setting('app.target_user_id', true), ''
        )
        AND command_id::text = NULLIF(
            current_setting('app.command_id', true), ''
        )
    )
);

CREATE POLICY rls_sandbox_platform_user_admin_outbox_restrict
ON infra.outbox_events AS RESTRICTIVE
FOR INSERT TO iam_app
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '')
        IS DISTINCT FROM 'PLATFORM_USER_ADMIN'
    OR (
        iam_api.internal_sandbox_platform_user_admin_authorized_v2()
        AND actor_kind = 'USER'
        AND actor_id::text = NULLIF(
            current_setting('app.actor_user_id', true), ''
        )
        AND causation_id::text = NULLIF(
            current_setting('app.command_id', true), ''
        )
        AND payload ->> 'user_id' = NULLIF(
            current_setting('app.target_user_id', true), ''
        )
        AND (
            (
                aggregate_type = 'User'
                AND aggregate_id::text = NULLIF(
                    current_setting('app.target_user_id', true), ''
                )
                AND event_type IN (
                    'UserSuspended', 'UserResumed', 'SessionsRevoked'
                )
            )
            OR (
                aggregate_type = 'Session'
                AND event_type = 'SessionRevoked'
            )
        )
    )
);

-- This SECURITY DEFINER probe returns one bit only.  It deliberately omits the
-- target from the receipt lookup so command-scope IDK conflicts cannot be hidden
-- by the safe-response RLS target binding.
CREATE FUNCTION iam_api.probe_platform_user_admin_command_receipt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_target_user_id uuid,
    exact_command_name text,
    exact_idempotency_key_digest_key_id text,
    exact_idempotency_key_digest bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, infra, iam_api
AS $function$
DECLARE
    exact_scope text;
    exact_operation text;
    authorized boolean := false;
BEGIN
    exact_scope := NULLIF(current_setting('app.scope_kind', true), '');
    exact_operation := NULLIF(current_setting('app.operation', true), '');
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_target_user_id IS NULL
       OR exact_actor_user_id = exact_target_user_id
       OR exact_idempotency_key_digest_key_id IS NULL
       OR length(exact_idempotency_key_digest_key_id) NOT BETWEEN 1 AND 64
       OR exact_idempotency_key_digest IS NULL
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_target_user_id::text
       OR NULLIF(current_setting('app.command_name', true), '')
            IS DISTINCT FROM exact_command_name
       OR NULLIF(
            current_setting('app.idempotency_key_digest_key_id', true), ''
          ) IS DISTINCT FROM exact_idempotency_key_digest_key_id
       OR decode(
            NULLIF(current_setting('app.idempotency_key_digest', true), ''),
            'hex'
          ) IS DISTINCT FROM exact_idempotency_key_digest
       OR NOT (
            (
                exact_scope = 'PLATFORM_USER_ADMIN'
                AND (
                    (exact_command_name = 'SuspendUser'
                        AND exact_operation = 'SUSPEND_USER')
                    OR (exact_command_name = 'ResumeUser'
                        AND exact_operation = 'RESUME_USER')
                    OR (exact_command_name = 'RevokeAllSessions'
                        AND exact_operation = 'REVOKE_ALL_SESSIONS')
                )
            )
            OR (
                exact_scope = 'INTERNAL_SANDBOX_PLATFORM_DUTY_ADMIN'
                AND (
                    (exact_command_name = 'GrantPlatformDuty'
                        AND exact_operation = 'GRANT_PLATFORM_DUTY')
                    OR (exact_command_name = 'RevokePlatformDuty'
                        AND exact_operation = 'REVOKE_PLATFORM_DUTY')
                )
            )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_platform_user_admin_receipt_probe_context',
            MESSAGE = 'platform user administration receipt probe is invalid';
    END IF;

    IF exact_scope = 'PLATFORM_USER_ADMIN' THEN
        authorized :=
            iam_api.internal_sandbox_platform_user_admin_authorized_v2();
    ELSE
        authorized :=
            iam_api.internal_sandbox_platform_duty_admin_authorized_v1();
    END IF;
    IF NOT authorized THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_platform_user_admin_receipt_probe_authority',
            MESSAGE = 'platform user administration receipt probe is unauthorized';
    END IF;

    RETURN EXISTS (
        SELECT 1
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = exact_command_name
          AND receipt.command_version = 1
          AND receipt.idempotency_key_digest = exact_idempotency_key_digest
    );
END
$function$;

ALTER FUNCTION iam_api.probe_platform_user_admin_command_receipt_v1(
    uuid, uuid, uuid, text, text, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.probe_platform_user_admin_command_receipt_v1(
    uuid, uuid, uuid, text, text, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.probe_platform_user_admin_command_receipt_v1(
    uuid, uuid, uuid, text, text, bytea
) TO iam_app;

-- Permit the one exact cleanup transition performed by the v2 duty lock.  The
-- old expired row is closed in the same transaction before the new row inserts.
CREATE OR REPLACE FUNCTION
    iam.enforce_internal_sandbox_platform_duty_grant_transition()
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
        IF OLD.revoked_at IS NOT NULL
           OR NEW.id IS DISTINCT FROM OLD.id
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.duty_code IS DISTINCT FROM OLD.duty_code
           OR NEW.granted_by_kind IS DISTINCT FROM OLD.granted_by_kind
           OR NEW.granted_by_id IS DISTINCT FROM OLD.granted_by_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
           OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.revoked_at IS DISTINCT FROM transaction_timestamp()
           OR NEW.aggregate_version <> OLD.aggregate_version + 1
           OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
           OR NOT (
                (
                    NULLIF(current_setting('app.operation', true), '')
                        = 'REVOKE_PLATFORM_DUTY'
                    AND NEW.revocation_reason_code IS NOT DISTINCT FROM NULLIF(
                        current_setting('app.reason_code', true), ''
                    )
                )
                OR (
                    NULLIF(current_setting('app.operation', true), '')
                        = 'GRANT_PLATFORM_DUTY'
                    AND OLD.expires_at IS NOT NULL
                    AND OLD.expires_at <= transaction_timestamp()
                    AND NEW.revocation_reason_code
                        IS NOT DISTINCT FROM 'EXPIRED_SUPERSEDED'
                )
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_sandbox_platform_duty_grant_transition',
                MESSAGE = 'invalid sandbox platform duty grant revocation';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION iam_api.lock_internal_sandbox_platform_duty_admin_v2(
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
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    plan jsonb;
    expired_grant iam.platform_duty_grants%ROWTYPE;
    locked_expired iam.platform_duty_grants%ROWTYPE;
    expired_count integer := 0;
    changed_count integer := 0;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(1229016369, 31);
    PERFORM pg_catalog.pg_advisory_xact_lock(1229016369, 23);
    plan := iam_api.lock_internal_sandbox_platform_duty_admin_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_target_user_id,
        exact_operation,
        exact_expected_version,
        exact_duty_code,
        replay_existing
    );
    IF plan ->> 'decision_code' <> 'AUTHORIZED'
       OR replay_existing
       OR exact_operation <> 'GRANT_PLATFORM_DUTY' THEN
        RETURN plan;
    END IF;

    FOR locked_expired IN
        SELECT duty.*
        FROM iam.platform_duty_grants AS duty
        WHERE duty.user_id = exact_target_user_id
          AND duty.duty_code = exact_duty_code
          AND duty.revoked_at IS NULL
        ORDER BY duty.id
        FOR UPDATE
    LOOP
        expired_count := expired_count + 1;
        expired_grant := locked_expired;
    END LOOP;
    IF expired_count > 1 THEN
        RETURN jsonb_build_object('decision_code', 'SERVICE_UNAVAILABLE');
    END IF;
    IF expired_count = 1 THEN
        IF expired_grant.granted_at > transaction_timestamp()
           OR expired_grant.expires_at IS NULL
           OR expired_grant.expires_at > transaction_timestamp() THEN
            RETURN jsonb_build_object(
                'decision_code', 'INVALID_STATE_TRANSITION'
            );
        END IF;
        UPDATE iam.platform_duty_grants
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'EXPIRED_SUPERSEDED',
            aggregate_version = aggregate_version + 1,
            updated_at = transaction_timestamp()
        WHERE id = expired_grant.id
          AND user_id = exact_target_user_id
          AND duty_code = exact_duty_code
          AND revoked_at IS NULL
          AND expires_at IS NOT NULL
          AND expires_at <= transaction_timestamp()
          AND aggregate_version = expired_grant.aggregate_version;
        GET DIAGNOSTICS changed_count = ROW_COUNT;
        IF changed_count <> 1 THEN
            RETURN jsonb_build_object('decision_code', 'PRECONDITION_FAILED');
        END IF;
    END IF;
    RETURN plan;
END
$function$;

ALTER FUNCTION iam_api.lock_internal_sandbox_platform_duty_admin_v2(
    uuid, uuid, uuid, text, bigint, text, boolean
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.lock_internal_sandbox_platform_duty_admin_v2(
    uuid, uuid, uuid, text, bigint, text, boolean
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.lock_internal_sandbox_platform_duty_admin_v2(
    uuid, uuid, uuid, text, bigint, text, boolean
) TO iam_app;
REVOKE EXECUTE ON FUNCTION
    iam_api.lock_internal_sandbox_platform_duty_admin_v1(
        uuid, uuid, uuid, text, bigint, text, boolean
    )
FROM iam_app;

DO $assertions$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.validate_internal_sandbox_platform_user_admin_target_v2(uuid,uuid,uuid,text)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.lock_internal_sandbox_platform_user_admin_v2(uuid,uuid,uuid,text,bigint,boolean)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.lock_internal_sandbox_platform_duty_admin_v2(uuid,uuid,uuid,text,bigint,text,boolean)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.probe_platform_user_admin_command_receipt_v1(uuid,uuid,uuid,text,text,bytea)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.lock_platform_user_admin_v1(uuid,uuid,uuid,text,bigint,boolean)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.lock_internal_sandbox_platform_duty_admin_v1(uuid,uuid,uuid,text,bigint,text,boolean)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam_api.probe_platform_user_admin_command_receipt_v1(uuid,uuid,uuid,text,text,bytea)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sandbox account administration hardening assertion failed';
    END IF;
END
$assertions$;
