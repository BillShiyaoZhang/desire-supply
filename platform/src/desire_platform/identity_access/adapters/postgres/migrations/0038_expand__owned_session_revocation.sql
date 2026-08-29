ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_owned_session_revocation CHECK (
    command_name <> 'RevokeSession'
    OR (
        command_version = 1
        AND principal_kind = 'USER'
        AND target_kind = 'Session'
        AND http_method = 'DELETE'
        AND canonical_path = '/v1/me/sessions/' || target_id::text
        AND if_match_version IS NULL
        AND reconstruction_metadata IS NULL
        AND (
            (
                status = 'IN_PROGRESS'
                AND response_schema_version IS NULL
                AND safe_response_body IS NULL
                AND response_http_status IS NULL
                AND response_schema_name IS NULL
                AND response_entity_tag IS NULL
                AND current_user_entity_tag IS NULL
            ) OR (
                status = 'COMPLETED'
                AND response_schema_version = 1
                AND response_http_status = 204
                AND response_schema_name = 'Empty204'
                AND response_entity_tag IS NULL
                AND current_user_entity_tag IS NULL
                AND safe_response_body IS NOT NULL
                AND safe_response_body->>'current_session_id'
                    ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                AND safe_response_body->>'session_id' = target_id::text
                AND safe_response_body->>'session_family_id'
                    ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                AND safe_response_body->>'session_status' IN (
                    'REVOKED', 'EXPIRED'
                )
                AND safe_response_body->>'session_version' ~ '^[1-9][0-9]*$'
                AND safe_response_body->>'outcome' IN (
                    'REVOKED', 'EXPIRED', 'ALREADY_TERMINAL'
                )
                AND safe_response_body->'replayed' = 'false'::jsonb
                AND safe_response_body->'clear_current_session_cookie'
                    = to_jsonb(
                        safe_response_body->>'current_session_id'
                            = target_id::text
                    )
                AND safe_response_body ?& ARRAY[
                    'outcome', 'current_session_id', 'session_id',
                    'session_family_id', 'session_status', 'session_version',
                    'replayed', 'clear_current_session_cookie'
                ]
                AND safe_response_body - ARRAY[
                    'outcome', 'current_session_id', 'session_id',
                    'session_family_id', 'session_status', 'session_version',
                    'replayed', 'clear_current_session_cookie'
                ] = '{}'::jsonb
            )
        )
    )
);

CREATE FUNCTION iam.owned_session_revocation_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT session_user = 'iam_app'
   AND current_user = 'schema_owner'
   AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
   AND NULLIF(current_setting('app.operation', true), '') = 'REVOKE_SESSION'
   AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
   AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
   AND NULLIF(current_setting('app.target_session_id', true), '') IS NOT NULL
   AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
$function$;

ALTER FUNCTION iam.owned_session_revocation_context_v1() OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.owned_session_revocation_context_v1() FROM PUBLIC;

CREATE POLICY rls_owned_session_revocation_user_v1 ON iam.users
FOR ALL TO schema_owner
USING (
    iam.owned_session_revocation_context_v1()
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_owned_session_revocation_family_v1
ON iam.session_families
FOR ALL TO schema_owner
USING (
    iam.owned_session_revocation_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.family_id = session_families.id
          AND exact_session.user_id = session_families.user_id
          AND exact_session.id::text IN (
                NULLIF(current_setting('app.session_id', true), ''),
                NULLIF(current_setting('app.target_session_id', true), '')
          )
    )
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_owned_session_revocation_session_select_v1
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    iam.owned_session_revocation_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND id::text IN (
        NULLIF(current_setting('app.session_id', true), ''),
        NULLIF(current_setting('app.target_session_id', true), '')
    )
);

CREATE POLICY rls_owned_session_revocation_session_update_v1
ON iam.sessions
FOR UPDATE TO schema_owner
USING (
    iam.owned_session_revocation_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND id::text IN (
        NULLIF(current_setting('app.session_id', true), ''),
        NULLIF(current_setting('app.target_session_id', true), '')
    )
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.target_session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND status IN ('REVOKED', 'EXPIRED')
);

CREATE POLICY rls_owned_session_revocation_key_policy_select_v1
ON infra.iam_receipt_key_policy
FOR SELECT TO schema_owner
USING (iam.owned_session_revocation_context_v1() AND singleton_key);

CREATE POLICY rls_owned_session_revocation_key_policy_lock_v1
ON infra.iam_receipt_key_policy
FOR UPDATE TO schema_owner
USING (iam.owned_session_revocation_context_v1() AND singleton_key)
WITH CHECK (singleton_key);

CREATE POLICY rls_owned_session_revocation_audit_v1
ON audit.audit_events
FOR INSERT TO schema_owner
WITH CHECK (
    iam.owned_session_revocation_context_v1()
    AND actor_kind = 'USER'
    AND actor_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND original_actor_id IS NULL
    AND action_code = 'RevokeSession'
    AND target_kind = 'Session'
    AND target_id::text = NULLIF(
        current_setting('app.target_session_id', true), ''
    )
    AND organization_id IS NULL
    AND command_id::text = NULLIF(current_setting('app.command_id', true), '')
    AND causation_id = command_id
);

CREATE POLICY rls_owned_session_revocation_outbox_v1
ON infra.outbox_events
FOR INSERT TO schema_owner
WITH CHECK (
    iam.owned_session_revocation_context_v1()
    AND event_type = 'SessionRevoked'
    AND aggregate_type = 'Session'
    AND aggregate_id::text = NULLIF(
        current_setting('app.target_session_id', true), ''
    )
    AND actor_kind = 'USER'
    AND actor_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND original_actor_id IS NULL
    AND causation_id::text = NULLIF(
        current_setting('app.command_id', true), ''
    )
    AND organization_id IS NULL
);

CREATE FUNCTION iam_api.revoke_owned_session_v1(
    exact_actor_user_id uuid,
    exact_current_session_id uuid,
    exact_target_session_id uuid,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_idempotency_key_digest bytea,
    exact_idempotency_key_digest_key_id text,
    exact_payload_hash bytea,
    exact_payload_hash_key_id text,
    exact_canonicalization_version text,
    exact_retain_until timestamptz,
    new_audit_event_id uuid,
    new_outbox_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    server_now timestamptz := transaction_timestamp();
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
    actor_row iam.users%ROWTYPE;
    current_family_row iam.session_families%ROWTYPE;
    target_family_row iam.session_families%ROWTYPE;
    current_row iam.sessions%ROWTYPE;
    target_row iam.sessions%ROWTYPE;
    existing infra.command_receipts%ROWTYPE;
    resolved_current_family_id uuid;
    resolved_target_family_id uuid;
    claimed_count integer := 0;
    result_outcome text;
    result_status text;
    before_status text;
    before_version bigint;
    result_version bigint;
    safe_result jsonb;
    clear_cookie boolean;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.owned_session_revocation_context_v1()
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_current_session_id IS NULL
       OR exact_current_session_id = zero_uuid
       OR exact_target_session_id IS NULL
       OR exact_target_session_id = zero_uuid
       OR exact_command_id IS NULL OR exact_command_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS DISTINCT FROM exact_command_id
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR new_audit_event_id IS NULL OR new_audit_event_id = zero_uuid
       OR new_outbox_event_id IS NULL OR new_outbox_event_id = zero_uuid
       OR cardinality(ARRAY[
            exact_command_id, new_audit_event_id, new_outbox_event_id
       ]) <> cardinality(ARRAY(
            SELECT DISTINCT identifier
            FROM unnest(ARRAY[
                exact_command_id, new_audit_event_id, new_outbox_event_id
            ]) AS identifier
       ))
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_current_session_id::text
       OR NULLIF(current_setting('app.target_session_id', true), '')
            IS DISTINCT FROM exact_target_session_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_owned_session_revocation_context',
            MESSAGE = 'owned Session revocation context is invalid';
    END IF;

    IF exact_retain_until IS NULL OR exact_retain_until <= server_now THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_owned_session_revocation_expired',
            MESSAGE = 'owned Session revocation receipt retention expired';
    END IF;

    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key
    FOR UPDATE;
    IF NOT FOUND
       OR exact_idempotency_key_digest_key_id
            <> 'iam-receipt-idempotency-hmac-2026-01'
       OR exact_payload_hash_key_id
            <> 'iam-receipt-payload-hmac-2026-01'
       OR exact_canonicalization_version <> 'restricted-canonical-json-v1'
       OR key_policy.active_idempotency_key_id
            <> exact_idempotency_key_digest_key_id
       OR key_policy.active_payload_hash_key_id <> exact_payload_hash_key_id
       OR key_policy.active_canonicalization_version
            <> exact_canonicalization_version
       OR NOT exact_idempotency_key_digest_key_id
            = ANY(key_policy.retained_idempotency_key_ids)
       OR NOT exact_payload_hash_key_id
            = ANY(key_policy.retained_payload_hash_key_ids)
       OR NOT exact_canonicalization_version
            = ANY(key_policy.retained_canonicalization_versions) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_owned_session_revocation_key_policy',
            MESSAGE = 'owned Session revocation key policy is unavailable';
    END IF;

    SELECT receipt.* INTO existing
    FROM infra.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.idempotency_key_digest_key_id
            = exact_idempotency_key_digest_key_id
      AND receipt.idempotency_key_digest = exact_idempotency_key_digest
    ORDER BY receipt.id
    LIMIT 1
    FOR UPDATE;

    IF existing.id IS NULL THEN
        IF EXISTS (
            SELECT 1 FROM infra.command_receipts
            WHERE id = exact_command_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'ck_owned_session_revocation_idempotency_reused',
                MESSAGE = 'owned Session revocation command identifier was reused';
        END IF;

        INSERT INTO infra.command_receipts (
            id, principal_kind, principal_id, command_name, command_version,
            idempotency_key_digest, idempotency_key_digest_key_id,
            payload_hash, payload_hash_key_id, canonicalization_version,
            target_kind, target_id, http_method, canonical_path,
            if_match_version, status, response_schema_version,
            safe_response_body, reconstruction_metadata, created_at,
            retain_until, completed_at, response_http_status,
            response_schema_name, response_entity_tag, current_user_entity_tag
        ) VALUES (
            exact_command_id, 'USER', exact_actor_user_id, 'RevokeSession', 1,
            exact_idempotency_key_digest,
            exact_idempotency_key_digest_key_id, exact_payload_hash,
            exact_payload_hash_key_id, exact_canonicalization_version,
            'Session', exact_target_session_id, 'DELETE',
            '/v1/me/sessions/' || exact_target_session_id::text, NULL,
            'IN_PROGRESS', NULL, NULL, NULL, server_now,
            exact_retain_until, NULL, NULL, NULL, NULL, NULL
        ) ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS claimed_count = ROW_COUNT;
        IF claimed_count <> 1 THEN
            SELECT receipt.* INTO existing
            FROM infra.command_receipts AS receipt
            WHERE receipt.principal_kind = 'USER'
              AND receipt.principal_id = exact_actor_user_id
              AND receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_id
              AND receipt.idempotency_key_digest = exact_idempotency_key_digest
            ORDER BY receipt.id
            LIMIT 1
            FOR UPDATE;
            IF existing.id IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505',
                    CONSTRAINT = 'ck_owned_session_revocation_idempotency_reused',
                    MESSAGE = 'owned Session revocation idempotency claim conflicted';
            END IF;
        END IF;
    END IF;

    SELECT family_id INTO resolved_current_family_id
    FROM iam.sessions
    WHERE id = exact_current_session_id
      AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_owned_session_revocation_authentication',
            MESSAGE = 'owned Session revocation authentication is unavailable';
    END IF;

    SELECT family_id INTO resolved_target_family_id
    FROM iam.sessions
    WHERE id = exact_target_session_id
      AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002',
            CONSTRAINT = 'ck_owned_session_revocation_target_unavailable',
            MESSAGE = 'owned Session revocation target is unavailable';
    END IF;

    SELECT * INTO actor_row
    FROM iam.users
    WHERE id = exact_actor_user_id
    FOR UPDATE;

    PERFORM family.id
    FROM iam.session_families AS family
    WHERE family.id IN (
        resolved_current_family_id, resolved_target_family_id
    )
      AND family.user_id = exact_actor_user_id
    ORDER BY family.id
    FOR UPDATE;

    SELECT * INTO current_family_row
    FROM iam.session_families
    WHERE id = resolved_current_family_id
      AND user_id = exact_actor_user_id;
    SELECT * INTO target_family_row
    FROM iam.session_families
    WHERE id = resolved_target_family_id
      AND user_id = exact_actor_user_id;

    PERFORM session_row.id
    FROM iam.sessions AS session_row
    WHERE session_row.id IN (
        exact_current_session_id, exact_target_session_id
    )
      AND session_row.user_id = exact_actor_user_id
    ORDER BY session_row.id
    FOR UPDATE;

    SELECT * INTO current_row
    FROM iam.sessions
    WHERE id = exact_current_session_id
      AND user_id = exact_actor_user_id
      AND family_id = resolved_current_family_id;
    SELECT * INTO target_row
    FROM iam.sessions AS target
    WHERE target.id = exact_target_session_id
      AND target.user_id = exact_actor_user_id
      AND target.family_id = resolved_target_family_id;

    IF actor_row.id IS NULL OR actor_row.status <> 'ACTIVE'
       OR current_family_row.id IS NULL OR current_row.id IS NULL
       OR target_family_row.id IS NULL OR target_row.id IS NULL
       OR current_row.status NOT IN ('ACTIVE', 'REVOKED', 'EXPIRED')
       OR target_row.status NOT IN ('ACTIVE', 'REVOKED', 'EXPIRED')
       OR (
            current_row.status = 'ACTIVE'
            AND (
                current_family_row.status <> 'ACTIVE'
                OR current_family_row.current_generation
                    <> current_row.generation
            )
       )
       OR (
            target_row.status = 'ACTIVE'
            AND (
                target_family_row.status <> 'ACTIVE'
                OR target_family_row.current_generation <> target_row.generation
            )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_owned_session_revocation_context',
            MESSAGE = 'owned Session revocation facts are inconsistent';
    END IF;

    IF exact_target_session_id <> exact_current_session_id
       AND current_row.status <> 'ACTIVE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_owned_session_revocation_authentication',
            MESSAGE = 'owned Session revocation authentication is unavailable';
    END IF;
    IF exact_target_session_id <> exact_current_session_id
       AND (
            server_now >= current_row.idle_expires_at
            OR server_now >= current_row.absolute_expires_at
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_owned_session_revocation_expired',
            MESSAGE = 'owned Session revocation current Session expired';
    END IF;

    IF existing.id IS NOT NULL THEN
        IF existing.command_name = 'RevokeCurrentSession' THEN
            IF exact_target_session_id <> exact_current_session_id
               OR existing.command_version <> 1
               OR existing.payload_hash_key_id <> exact_payload_hash_key_id
               OR existing.payload_hash <> exact_payload_hash
               OR existing.canonicalization_version
                    <> exact_canonicalization_version
               OR existing.target_kind <> 'Session'
               OR existing.target_id <> exact_current_session_id
               OR existing.http_method <> 'DELETE'
               OR existing.canonical_path
                    <> '/v1/me/sessions/' || exact_current_session_id::text
               OR existing.if_match_version IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505',
                    CONSTRAINT = 'ck_owned_session_revocation_idempotency_reused',
                    MESSAGE = 'owned Session revocation idempotency key was reused';
            ELSIF existing.status = 'IN_PROGRESS' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_owned_session_revocation_in_progress',
                    MESSAGE = 'owned Session revocation is in progress';
            ELSIF existing.status <> 'COMPLETED'
               OR existing.response_schema_version <> 1
               OR existing.response_http_status <> 204
               OR existing.response_schema_name <> 'Empty204'
               OR existing.response_entity_tag IS NOT NULL
               OR existing.current_user_entity_tag IS NOT NULL
               OR existing.reconstruction_metadata IS NOT NULL
               OR existing.safe_response_body IS NULL
               OR existing.retain_until <= server_now
               OR existing.safe_response_body->>'session_id'
                    <> exact_current_session_id::text
               OR existing.safe_response_body->>'session_family_id'
                    <> resolved_target_family_id::text
               OR existing.safe_response_body->>'session_status'
                    <> target_row.status
               OR existing.safe_response_body->>'session_version'
                    <> target_row.aggregate_version::text
               OR existing.safe_response_body->>'outcome' NOT IN (
                    'REVOKED', 'EXPIRED', 'ALREADY_TERMINAL'
               )
               OR existing.safe_response_body->'replayed' <> 'false'::jsonb
               OR existing.safe_response_body->'clear_current_session_cookie'
                    <> 'true'::jsonb
               OR (
                    SELECT count(*)
                    FROM jsonb_object_keys(existing.safe_response_body)
                  ) <> 7 THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_owned_session_revocation_context',
                    MESSAGE = 'legacy current Session receipt is inconsistent';
            END IF;
            RETURN existing.safe_response_body || jsonb_build_object(
                'outcome', 'REPLAYED',
                'current_session_id', exact_current_session_id::text,
                'replayed', true
            );
        END IF;

        IF existing.command_name <> 'RevokeSession'
           OR existing.command_version <> 1
           OR existing.payload_hash_key_id <> exact_payload_hash_key_id
           OR existing.payload_hash <> exact_payload_hash
           OR existing.canonicalization_version
                <> exact_canonicalization_version
           OR existing.target_kind <> 'Session'
           OR existing.target_id <> exact_target_session_id
           OR existing.http_method <> 'DELETE'
           OR existing.canonical_path
                <> '/v1/me/sessions/' || exact_target_session_id::text
           OR existing.if_match_version IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'ck_owned_session_revocation_idempotency_reused',
                MESSAGE = 'owned Session revocation idempotency key was reused';
        ELSIF existing.status = 'IN_PROGRESS' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_owned_session_revocation_in_progress',
                MESSAGE = 'owned Session revocation is in progress';
        ELSIF existing.status <> 'COMPLETED'
           OR existing.response_schema_version <> 1
           OR existing.response_http_status <> 204
           OR existing.response_schema_name <> 'Empty204'
           OR existing.response_entity_tag IS NOT NULL
           OR existing.current_user_entity_tag IS NOT NULL
           OR existing.reconstruction_metadata IS NOT NULL
           OR existing.safe_response_body IS NULL
           OR existing.retain_until <= server_now
           OR existing.safe_response_body->>'current_session_id'
                <> exact_current_session_id::text
           OR existing.safe_response_body->>'session_id'
                <> exact_target_session_id::text
           OR existing.safe_response_body->>'session_family_id'
                <> resolved_target_family_id::text
           OR existing.safe_response_body->>'session_status'
                <> target_row.status
           OR existing.safe_response_body->>'session_version'
                <> target_row.aggregate_version::text
           OR existing.safe_response_body->>'outcome' NOT IN (
                'REVOKED', 'EXPIRED', 'ALREADY_TERMINAL'
           )
           OR existing.safe_response_body->'replayed' <> 'false'::jsonb
           OR existing.safe_response_body->'clear_current_session_cookie'
                <> to_jsonb(
                    exact_target_session_id = exact_current_session_id
                )
           OR (
                SELECT count(*)
                FROM jsonb_object_keys(existing.safe_response_body)
              ) <> 8 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_owned_session_revocation_context',
                MESSAGE = 'owned Session revocation receipt is inconsistent';
        END IF;
        RETURN jsonb_set(
            jsonb_set(
                existing.safe_response_body,
                '{outcome}', to_jsonb('REPLAYED'::text), false
            ),
            '{replayed}', 'true'::jsonb, false
        );
    END IF;

    before_status := target_row.status;
    before_version := target_row.aggregate_version;
    clear_cookie := exact_target_session_id = exact_current_session_id;

    IF target_row.status = 'ACTIVE'
       AND server_now < target_row.idle_expires_at
       AND server_now < target_row.absolute_expires_at THEN
        UPDATE iam.sessions AS target
        SET status = 'REVOKED',
            revoked_at = server_now,
            revocation_reason_code = CASE
                WHEN exact_target_session_id = exact_current_session_id
                THEN 'USER_LOGOUT_CURRENT_SESSION'
                ELSE 'USER_REVOKED_SESSION'
            END,
            aggregate_version = target.aggregate_version + 1,
            updated_at = server_now
        WHERE target.id = exact_target_session_id
          AND target.user_id = exact_actor_user_id
          AND target.family_id = resolved_target_family_id
          AND target.status = 'ACTIVE'
          AND target.aggregate_version = before_version
        RETURNING target.status, target.aggregate_version
        INTO result_status, result_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                CONSTRAINT = 'ck_owned_session_revocation_context',
                MESSAGE = 'owned Session revocation write conflicted';
        END IF;
        result_outcome := 'REVOKED';
    ELSIF target_row.status = 'ACTIVE' THEN
        UPDATE iam.sessions AS target
        SET status = 'EXPIRED',
            revoked_at = server_now,
            revocation_reason_code = 'SESSION_EXPIRED',
            aggregate_version = target.aggregate_version + 1,
            updated_at = server_now
        WHERE target.id = exact_target_session_id
          AND target.user_id = exact_actor_user_id
          AND target.family_id = resolved_target_family_id
          AND target.status = 'ACTIVE'
          AND target.aggregate_version = before_version
        RETURNING target.status, target.aggregate_version
        INTO result_status, result_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                CONSTRAINT = 'ck_owned_session_revocation_context',
                MESSAGE = 'owned Session expiry write conflicted';
        END IF;
        result_outcome := 'EXPIRED';
    ELSE
        result_outcome := 'ALREADY_TERMINAL';
        result_status := target_row.status;
        result_version := target_row.aggregate_version;
    END IF;

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id, before_status,
        after_status, before_version, after_version, role_code, purpose_code,
        reason_code, auth_strength_code, result_code, command_id,
        correlation_id, causation_id, trace_id, safe_attributes
    ) VALUES (
        new_audit_event_id, server_now, 'USER', exact_actor_user_id, NULL,
        'RevokeSession', 'Session', exact_target_session_id, NULL,
        before_status, result_status, before_version, result_version, NULL,
        'SELF_SESSION', CASE result_outcome
            WHEN 'REVOKED' THEN CASE
                WHEN clear_cookie THEN 'USER_LOGOUT_CURRENT_SESSION'
                ELSE 'USER_REVOKED_SESSION'
            END
            WHEN 'EXPIRED' THEN 'SESSION_EXPIRED'
            ELSE 'ALREADY_TERMINAL'
        END, current_row.acr_code, 'SUCCEEDED', exact_command_id,
        exact_correlation_id, exact_causation_id, exact_trace_id, '{}'::jsonb
    );

    IF result_outcome = 'REVOKED' THEN
        INSERT INTO infra.outbox_events (
            event_id, event_type, schema_version, occurred_at, aggregate_type,
            aggregate_id, aggregate_version, actor_kind, actor_id,
            original_actor_id, correlation_id, causation_id, trace_id,
            organization_id, payload, delivery_status, attempt_count,
            available_at, lease_owner, lease_until, published_at,
            last_error_code, created_at
        ) VALUES (
            new_outbox_event_id, 'SessionRevoked', 1, server_now, 'Session',
            exact_target_session_id, result_version, 'USER',
            exact_actor_user_id, NULL, exact_correlation_id,
            exact_causation_id, exact_trace_id, NULL,
            jsonb_build_object(
                'session_id', exact_target_session_id::text,
                'session_family_id', resolved_target_family_id::text,
                'user_id', exact_actor_user_id::text,
                'status', 'REVOKED'
            ), 'PENDING', 0, server_now, NULL, NULL, NULL, NULL, server_now
        );
    END IF;

    safe_result := jsonb_build_object(
        'outcome', result_outcome,
        'current_session_id', exact_current_session_id::text,
        'session_id', exact_target_session_id::text,
        'session_family_id', resolved_target_family_id::text,
        'session_status', result_status,
        'session_version', result_version,
        'replayed', false,
        'clear_current_session_cookie', clear_cookie
    );
    UPDATE infra.command_receipts
    SET status = 'COMPLETED', response_schema_version = 1,
        safe_response_body = safe_result, reconstruction_metadata = NULL,
        completed_at = server_now, response_http_status = 204,
        response_schema_name = 'Empty204', response_entity_tag = NULL,
        current_user_entity_tag = NULL
    WHERE id = exact_command_id AND status = 'IN_PROGRESS';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            CONSTRAINT = 'ck_owned_session_revocation_context',
            MESSAGE = 'owned Session revocation receipt completion conflicted';
    END IF;
    RETURN safe_result;
END;
$function$;

ALTER FUNCTION iam_api.revoke_owned_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.revoke_owned_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) FROM PUBLIC, iam_session_authenticator;
GRANT EXECUTE ON FUNCTION iam_api.revoke_owned_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) TO iam_app;
