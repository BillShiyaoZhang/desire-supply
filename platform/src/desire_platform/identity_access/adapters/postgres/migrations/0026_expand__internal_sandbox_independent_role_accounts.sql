-- IAM 0026: four fixed INTERNAL_SANDBOX accounts with isolated effective roles.
--
-- IAM 0023 remains byte-frozen and is retained as the reviewed graph/session
-- lifecycle engine.  This migration closes its deployment surface behind v2:
-- the three non-CREATOR accounts keep their invitation-backed bootstrap grant
-- only as revoked evidence, so no committed state exposes mixed authorities.

CREATE OR REPLACE FUNCTION iam.enforce_role_grant_binding_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF TG_TABLE_NAME = 'user_role_grants' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.role_code IS DISTINCT FROM OLD.role_code
           OR NEW.source_invitation_id IS DISTINCT FROM OLD.source_invitation_id
           OR NEW.policy_selector_digest IS DISTINCT FROM OLD.policy_selector_digest
           OR NEW.granted_by_kind IS DISTINCT FROM OLD.granted_by_kind
           OR NEW.granted_by_id IS DISTINCT FROM OLD.granted_by_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_role_grant_binding_immutable',
                MESSAGE = 'role grant binding is immutable';
        END IF;
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.membership_id IS DISTINCT FROM OLD.membership_id
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.role_code IS DISTINCT FROM OLD.role_code
           OR NEW.source_invitation_id IS DISTINCT FROM OLD.source_invitation_id
           OR NEW.policy_selector_digest IS DISTINCT FROM OLD.policy_selector_digest
           OR NEW.granted_by_kind IS DISTINCT FROM OLD.granted_by_kind
           OR NEW.granted_by_id IS DISTINCT FROM OLD.granted_by_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_role_grant_binding_immutable',
                MESSAGE = 'role grant binding is immutable';
        END IF;
    END IF;

    -- A v2 SECURITY DEFINER call may restore only its three exact isolation
    -- edges, within the same transaction, so frozen v1 can verify/rotate/revoke
    -- the graph.  The online role has neither table DML nor v1 EXECUTE.
    IF TG_TABLE_NAME = 'user_role_grants'
       AND iam.internal_sandbox_bootstrap_context_v1()
       AND NULLIF(current_setting(
            'app.bootstrap_role_isolation_transition',
            true
       ), '') = 'RESTORE'
       AND OLD.revoked_at IS NOT NULL
       AND OLD.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
       AND NEW.revoked_at IS NULL
       AND NEW.revocation_reason_code IS NULL
       AND NEW.aggregate_version = OLD.aggregate_version + 1 THEN
        RETURN NEW;
    END IF;

    IF OLD.revoked_at IS NOT NULL
       OR NEW.revoked_at IS NULL
       OR NEW.revocation_reason_code IS NULL
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_role_grant_revocation',
            MESSAGE = 'invalid role grant revocation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION iam.internal_sandbox_independent_role_graph_v2(
    exact_manifest jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, iam, infra
AS $function$
WITH accounts AS (
    SELECT
        item.value->>'account_code' AS account_code,
        (item.value->>'user_id')::uuid AS user_id,
        (item.value#>>'{creator_grant,grant_id}')::uuid AS creator_grant_id,
        CASE
            WHEN pg_catalog.jsonb_typeof(
                item.value->'demand_owner_grant'
            ) = 'object'
            THEN (item.value#>>'{demand_owner_grant,grant_id}')::uuid
            ELSE NULL
        END AS demand_owner_grant_id,
        CASE
            WHEN pg_catalog.jsonb_typeof(
                item.value->'demand_owner_grant'
            ) = 'object'
            THEN (item.value#>>'{demand_owner_grant,membership_id}')::uuid
            ELSE NULL
        END AS membership_id,
        CASE
            WHEN pg_catalog.jsonb_typeof(
                item.value->'demand_owner_grant'
            ) = 'object'
            THEN (item.value#>>'{demand_owner_grant,organization_id}')::uuid
            ELSE NULL
        END AS organization_id,
        CASE
            WHEN pg_catalog.jsonb_array_length(
                item.value->'platform_duty_grants'
            ) = 1
            THEN item.value#>>'{platform_duty_grants,0,duty_code}'
            ELSE NULL
        END AS duty_code,
        CASE
            WHEN pg_catalog.jsonb_array_length(
                item.value->'platform_duty_grants'
            ) = 1
            THEN (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
            ELSE NULL
        END AS duty_grant_id
    FROM pg_catalog.jsonb_array_elements(
        exact_manifest->'accounts'
    ) AS item(value)
),
bootstrap_accounts AS (
    SELECT account.*
    FROM accounts AS account
    JOIN infra.iam_sandbox_bootstrap_accounts AS state
      ON state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
     AND state.account_code = account.account_code
     AND state.user_id = account.user_id
),
active_user_roles AS (
    SELECT grant_row.id, grant_row.user_id, grant_row.role_code
    FROM iam.user_role_grants AS grant_row
    JOIN accounts AS account ON account.user_id = grant_row.user_id
    WHERE grant_row.revoked_at IS NULL
),
isolated_creator_roles AS (
    SELECT grant_row.id, grant_row.user_id
    FROM iam.user_role_grants AS grant_row
    JOIN accounts AS account
      ON account.user_id = grant_row.user_id
     AND account.creator_grant_id = grant_row.id
    WHERE account.account_code <> 'creator_01'
      AND grant_row.role_code = 'CREATOR'
      AND grant_row.revoked_at IS NOT NULL
      AND grant_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
),
active_membership_roles AS (
    SELECT grant_row.id, grant_row.user_id, grant_row.membership_id,
        grant_row.organization_id, grant_row.role_code
    FROM iam.membership_role_grants AS grant_row
    JOIN accounts AS account ON account.user_id = grant_row.user_id
    WHERE grant_row.revoked_at IS NULL
),
active_duties AS (
    SELECT grant_row.id, grant_row.user_id, grant_row.duty_code
    FROM iam.platform_duty_grants AS grant_row
    JOIN accounts AS account ON account.user_id = grant_row.user_id
    WHERE grant_row.revoked_at IS NULL
)
SELECT
    (SELECT count(*) FROM accounts) = 4
    AND (SELECT count(*) FROM bootstrap_accounts) = 4
    AND (
        SELECT count(*)
        FROM infra.iam_sandbox_bootstrap_accounts AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 4
    AND (
        SELECT count(*)
        FROM active_user_roles AS role_row
        JOIN accounts AS account
          ON account.user_id = role_row.user_id
         AND account.creator_grant_id = role_row.id
        WHERE account.account_code = 'creator_01'
          AND role_row.role_code = 'CREATOR'
    ) = 1
    AND (SELECT count(*) FROM active_user_roles) = 1
    AND (SELECT count(*) FROM isolated_creator_roles) = 3
    AND (
        SELECT count(*)
        FROM active_membership_roles AS role_row
        JOIN accounts AS account
          ON account.user_id = role_row.user_id
         AND account.demand_owner_grant_id = role_row.id
         AND account.membership_id = role_row.membership_id
         AND account.organization_id = role_row.organization_id
        JOIN iam.memberships AS membership
          ON membership.id = role_row.membership_id
         AND membership.organization_id = role_row.organization_id
         AND membership.user_id = role_row.user_id
         AND membership.status = 'ACTIVE'
        WHERE account.account_code = 'demand_owner_01'
          AND role_row.role_code = 'DEMAND_OWNER'
    ) = 1
    AND (SELECT count(*) FROM active_membership_roles) = 1
    AND (
        SELECT count(*)
        FROM active_duties AS duty
        JOIN accounts AS account
          ON account.user_id = duty.user_id
         AND account.duty_grant_id = duty.id
         AND account.duty_code = duty.duty_code
        WHERE (
            account.account_code = 'access_admin_01'
            AND duty.duty_code = 'ACCESS_ADMIN'
        ) OR (
            account.account_code = 'operations_reviewer_01'
            AND duty.duty_code = 'OPERATIONS_REVIEWER'
        )
    ) = 2
    AND (SELECT count(*) FROM active_duties) = 2
$function$;

ALTER FUNCTION iam.internal_sandbox_independent_role_graph_v2(jsonb)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam.internal_sandbox_independent_role_graph_v2(jsonb)
FROM PUBLIC;

CREATE FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v2(
    exact_action text,
    exact_canonical_manifest bytea,
    exact_manifest_sha256 bytea,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_system_actor_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_bootstrap_id uuid
)
RETURNS TABLE(outcome text, revision integer, account_count integer)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    manifest_document jsonb;
    accounts_document jsonb;
    state_row infra.iam_sandbox_bootstrap_state%ROWTYPE;
    manifest_revision integer;
    manifest_account_count integer;
    manifest_issuer text;
    base_outcome text;
    base_revision integer;
    base_account_count integer;
    affected integer;
    state_found boolean := false;
    exact_active_state boolean := false;
    restore_for_persistent_call boolean := false;
BEGIN
    IF exact_action NOT IN ('APPLY', 'VERIFY', 'REVOKE_ACCESS')
       OR exact_canonical_manifest IS NULL
       OR pg_catalog.octet_length(exact_canonical_manifest)
            NOT BETWEEN 1 AND 131072
       OR exact_manifest_sha256 IS NULL
       OR pg_catalog.octet_length(exact_manifest_sha256) <> 32
       OR pg_catalog.sha256(exact_canonical_manifest)
            <> exact_manifest_sha256
       OR exact_command_id IS NULL OR exact_command_id = zero_uuid
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_audit_event_id IS NULL OR exact_audit_event_id = zero_uuid
       OR exact_system_actor_id IS NULL OR exact_system_actor_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_bootstrap_id IS NULL OR exact_bootstrap_id = zero_uuid
       OR session_user IS DISTINCT FROM 'iam_sandbox_bootstrap'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.internal_sandbox_bootstrap_context_v1()
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_action
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.manifest_sha256', true), '')
            IS DISTINCT FROM pg_catalog.encode(
                exact_manifest_sha256,
                'hex'
            )
       OR NULLIF(current_setting(
            'app.bootstrap_role_isolation_transition',
            true
       ), '') IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_internal_sandbox_role_split_invocation',
            MESSAGE = 'internal sandbox role split invocation is invalid';
    END IF;

    BEGIN
        manifest_document := pg_catalog.convert_from(
            exact_canonical_manifest,
            'UTF8'
        )::jsonb;
        accounts_document := manifest_document->'accounts';
        manifest_revision := (manifest_document->>'revision')::integer;
        manifest_account_count := pg_catalog.jsonb_array_length(
            accounts_document
        );
        manifest_issuer := manifest_document->>'issuer';
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_role_split_manifest',
            MESSAGE = 'internal sandbox role split manifest is invalid';
    END;

    IF manifest_document->>'schema_name'
            <> 'desire-internal-sandbox-identity-bootstrap-v1'
       OR manifest_document->>'environment_id' <> 'internal-sandbox'
       OR manifest_document->>'bootstrap_id' <> exact_bootstrap_id::text
       OR manifest_account_count <> 4
       OR (
            SELECT count(DISTINCT item.value->>'account_code')
            FROM pg_catalog.jsonb_array_elements(
                accounts_document
            ) AS item(value)
       ) <> 4
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_array_elements(
                accounts_document
            ) AS item(value)
            WHERE CASE item.value->>'account_code'
                WHEN 'access_admin_01' THEN NOT (
                    pg_catalog.jsonb_typeof(
                        item.value->'demand_owner_grant'
                    ) = 'null'
                    AND pg_catalog.jsonb_typeof(
                        item.value->'creator_grant'
                    ) = 'object'
                    AND pg_catalog.jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 1
                    AND item.value#>>'{platform_duty_grants,0,duty_code}'
                        = 'ACCESS_ADMIN'
                )
                WHEN 'creator_01' THEN NOT (
                    pg_catalog.jsonb_typeof(
                        item.value->'demand_owner_grant'
                    ) = 'null'
                    AND pg_catalog.jsonb_typeof(
                        item.value->'creator_grant'
                    ) = 'object'
                    AND pg_catalog.jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 0
                )
                WHEN 'demand_owner_01' THEN NOT (
                    pg_catalog.jsonb_typeof(
                        item.value->'demand_owner_grant'
                    ) = 'object'
                    AND pg_catalog.jsonb_typeof(
                        item.value->'creator_grant'
                    ) = 'object'
                    AND pg_catalog.jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 0
                )
                WHEN 'operations_reviewer_01' THEN NOT (
                    pg_catalog.jsonb_typeof(
                        item.value->'demand_owner_grant'
                    ) = 'null'
                    AND pg_catalog.jsonb_typeof(
                        item.value->'creator_grant'
                    ) = 'object'
                    AND pg_catalog.jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 1
                    AND item.value#>>'{platform_duty_grants,0,duty_code}'
                        = 'OPERATIONS_REVIEWER'
                )
                ELSE true
            END
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_role_split_manifest',
            MESSAGE = 'internal sandbox role split manifest is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(1229016369, 23);
    SELECT * INTO state_row
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.bootstrap_id = exact_bootstrap_id
    FOR UPDATE;

    state_found := FOUND;
    exact_active_state := state_found
        AND state_row.status = 'ACTIVE'
        AND state_row.manifest_sha256 = exact_manifest_sha256
        AND state_row.revision = manifest_revision
        AND state_row.issuer = manifest_issuer
        AND state_row.account_count = manifest_account_count;

    IF exact_active_state OR (
        state_found
        AND state_row.status = 'ACTIVE'
        AND exact_action = 'APPLY'
    ) THEN
        IF NOT iam.internal_sandbox_independent_role_graph_v2(
            manifest_document
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_role_split_graph',
                MESSAGE = 'internal sandbox role split graph drifted';
        END IF;

        IF exact_active_state
           AND exact_action IN ('APPLY', 'VERIFY') THEN
            -- v1 performs the complete policy/identity/authority verification.
            -- The exception subtransaction rolls back the temporary restore
            -- and any v1 effects while PL/pgSQL retains the returned facts.
            BEGIN
                PERFORM set_config(
                    'app.bootstrap_role_isolation_transition',
                    'RESTORE',
                    true
                );
                UPDATE iam.user_role_grants AS grant_row
                SET revoked_at = NULL,
                    revocation_reason_code = NULL,
                    aggregate_version = grant_row.aggregate_version + 1
                FROM pg_catalog.jsonb_array_elements(
                    accounts_document
                ) AS item(value)
                WHERE item.value->>'account_code' <> 'creator_01'
                  AND grant_row.id = (
                        item.value#>>'{creator_grant,grant_id}'
                  )::uuid
                  AND grant_row.user_id = (item.value->>'user_id')::uuid
                  AND grant_row.role_code = 'CREATOR'
                  AND grant_row.revoked_at IS NOT NULL
                  AND grant_row.revocation_reason_code
                        = 'BOOTSTRAP_ROLE_ISOLATION';
                GET DIAGNOSTICS affected = ROW_COUNT;
                IF affected <> 3 THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '55000',
                        CONSTRAINT = 'ck_internal_sandbox_role_split_restore',
                        MESSAGE = 'internal sandbox role split restore failed';
                END IF;
                PERFORM set_config(
                    'app.bootstrap_role_isolation_transition',
                    '',
                    true
                );

                SELECT base.outcome, base.revision, base.account_count
                INTO base_outcome, base_revision, base_account_count
                FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1(
                    exact_action,
                    exact_canonical_manifest,
                    exact_manifest_sha256,
                    exact_command_id,
                    exact_receipt_id,
                    exact_audit_event_id,
                    exact_system_actor_id,
                    exact_correlation_id,
                    exact_trace_id,
                    exact_bootstrap_id
                ) AS base;
                RAISE EXCEPTION USING
                    ERRCODE = 'Z2601',
                    MESSAGE = 'rollback role verification restore';
            EXCEPTION WHEN SQLSTATE 'Z2601' THEN
                NULL;
            END;
        ELSE
            restore_for_persistent_call := true;
        END IF;
    END IF;

    IF NOT exact_active_state
       OR exact_action = 'REVOKE_ACCESS' THEN
        IF restore_for_persistent_call THEN
            PERFORM set_config(
                'app.bootstrap_role_isolation_transition',
                'RESTORE',
                true
            );
            UPDATE iam.user_role_grants AS grant_row
            SET revoked_at = NULL,
                revocation_reason_code = NULL,
                aggregate_version = grant_row.aggregate_version + 1
            FROM pg_catalog.jsonb_array_elements(
                accounts_document
            ) AS item(value)
            WHERE item.value->>'account_code' <> 'creator_01'
              AND grant_row.id = (
                    item.value#>>'{creator_grant,grant_id}'
              )::uuid
              AND grant_row.user_id = (item.value->>'user_id')::uuid
              AND grant_row.role_code = 'CREATOR'
              AND grant_row.revoked_at IS NOT NULL
              AND grant_row.revocation_reason_code
                    = 'BOOTSTRAP_ROLE_ISOLATION';
            GET DIAGNOSTICS affected = ROW_COUNT;
            IF affected <> 3 THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_role_split_restore',
                    MESSAGE = 'internal sandbox role split restore failed';
            END IF;
            PERFORM set_config(
                'app.bootstrap_role_isolation_transition',
                '',
                true
            );
        END IF;

        SELECT base.outcome, base.revision, base.account_count
        INTO base_outcome, base_revision, base_account_count
        FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1(
            exact_action,
            exact_canonical_manifest,
            exact_manifest_sha256,
            exact_command_id,
            exact_receipt_id,
            exact_audit_event_id,
            exact_system_actor_id,
            exact_correlation_id,
            exact_trace_id,
            exact_bootstrap_id
        ) AS base;
    END IF;

    IF base_outcome IN ('APPLIED', 'ROTATED') THEN
        UPDATE iam.user_role_grants AS grant_row
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION',
            aggregate_version = grant_row.aggregate_version + 1
        FROM pg_catalog.jsonb_array_elements(
            accounts_document
        ) AS item(value)
        WHERE item.value->>'account_code' <> 'creator_01'
          AND grant_row.id = (
                item.value#>>'{creator_grant,grant_id}'
          )::uuid
          AND grant_row.user_id = (item.value->>'user_id')::uuid
          AND grant_row.role_code = 'CREATOR'
          AND grant_row.revoked_at IS NULL;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 3
           OR NOT iam.internal_sandbox_independent_role_graph_v2(
                manifest_document
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_role_split_isolation',
                MESSAGE = 'internal sandbox role split isolation failed';
        END IF;
    ELSIF base_outcome IN ('REPLAYED', 'VERIFIED') THEN
        IF NOT iam.internal_sandbox_independent_role_graph_v2(
            manifest_document
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_role_split_graph',
                MESSAGE = 'internal sandbox role split graph drifted';
        END IF;
    ELSIF base_outcome NOT IN ('REVOKED', 'ALREADY_REVOKED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_role_split_outcome',
            MESSAGE = 'internal sandbox role split outcome is invalid';
    END IF;

    RETURN QUERY SELECT base_outcome, base_revision, base_account_count;
END
$function$;

ALTER FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v2(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v2(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v1(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
FROM iam_sandbox_bootstrap;
GRANT EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v2(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
TO iam_sandbox_bootstrap;

DO $assertions$
BEGIN
    IF pg_catalog.has_function_privilege(
        'iam_sandbox_bootstrap',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v1(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'iam_sandbox_bootstrap',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v2(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v2(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_onboarding',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v2(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_system',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v2(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v2(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sandbox independent-role bootstrap EXECUTE assertion failed';
    END IF;
END
$assertions$;
