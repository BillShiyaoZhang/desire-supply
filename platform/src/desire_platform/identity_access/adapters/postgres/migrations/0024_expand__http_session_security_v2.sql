-- IAM 0024: authoritative HTTP Session resolution and replay convergence.

GRANT SELECT (id, status) ON iam.users TO iam_session_authenticator;
GRANT SELECT (revoked_at, revocation_reason_code)
    ON iam.session_families TO iam_session_authenticator;
GRANT SELECT (revoked_at, revocation_reason_code)
    ON iam.sessions TO iam_session_authenticator;

CREATE POLICY rls_user_session_authenticate_exact ON iam.users
FOR SELECT TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'RESOLVE_COOKIE'
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.user_id = users.id
          AND exact_session.handle_digest_key_id = NULLIF(
              current_setting('app.session_handle_digest_key_id', true),
              ''
          )
          AND exact_session.handle_digest = decode(
              NULLIF(current_setting('app.session_handle_digest', true), ''),
              'hex'
          )
    )
);

CREATE VIEW iam_api.resolve_cookie_session_v2
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    session.id AS session_id,
    session.user_id,
    session.family_id,
    session.generation,
    session.status AS session_status,
    session.handle_digest_key_id,
    session.handle_digest,
    session.csrf_salt,
    session.csrf_key_id,
    session.csrf_digest,
    session.auth_time,
    session.acr_code,
    session.amr_codes,
    session.idle_expires_at,
    session.absolute_expires_at,
    session.verified_contact_point_id,
    session.verified_at,
    session.verified_for_invitation_id,
    session.auth_transaction_id,
    session.device_label,
    session.aggregate_version AS session_aggregate_version,
    family.status AS family_status,
    family.current_generation,
    family.aggregate_version AS family_aggregate_version,
    actor.status AS user_status
FROM iam.sessions AS session
JOIN iam.session_families AS family ON family.id = session.family_id
JOIN iam.users AS actor ON actor.id = session.user_id;

REVOKE ALL ON iam_api.resolve_cookie_session_v2 FROM PUBLIC;
GRANT SELECT ON iam_api.resolve_cookie_session_v2 TO iam_session_authenticator;

CREATE TABLE iam.session_security_events (
    security_event_id uuid NOT NULL,
    event_type varchar(64) NOT NULL,
    session_family_id uuid NOT NULL,
    replayed_session_id uuid NOT NULL,
    user_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT pk_session_security_events PRIMARY KEY (security_event_id),
    CONSTRAINT uq_session_security_event_replayed_session
        UNIQUE (replayed_session_id),
    CONSTRAINT fk_session_security_event_replayed_family FOREIGN KEY (
        replayed_session_id,
        session_family_id
    ) REFERENCES iam.sessions (id, family_id) ON DELETE RESTRICT,
    CONSTRAINT fk_session_security_event_family_user FOREIGN KEY (
        session_family_id,
        user_id
    ) REFERENCES iam.session_families (id, user_id) ON DELETE RESTRICT,
    CONSTRAINT ck_session_security_event_type CHECK (
        event_type = 'REPLAYED_SESSION_HANDLE'
    )
);

CREATE FUNCTION iam.reject_session_security_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'trg_session_security_event_append_only',
        MESSAGE = 'session security events are append only';
END
$function$;

REVOKE ALL ON FUNCTION iam.reject_session_security_event_mutation()
    FROM PUBLIC;

CREATE TRIGGER trg_session_security_event_append_only
BEFORE UPDATE OR DELETE ON iam.session_security_events
FOR EACH ROW EXECUTE FUNCTION iam.reject_session_security_event_mutation();

ALTER TABLE iam.session_security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.session_security_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON iam.session_security_events FROM PUBLIC;
GRANT SELECT, INSERT ON iam.session_security_events
    TO iam_session_authenticator;

CREATE POLICY rls_session_security_event_replay_select
ON iam.session_security_events
FOR SELECT TO iam_session_authenticator
USING (
    session_user = 'iam_session_authenticator'
    AND current_user = 'iam_session_authenticator'
    AND NULLIF(current_setting('app.scope_kind', true), '') =
        'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') =
        'REVOKE_REPLAYED_FAMILY'
    AND replayed_session_id =
        NULLIF(current_setting('app.session_id', true), '')::uuid
    AND session_family_id =
        NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND iam.replayed_session_matches_family(session_family_id)
);

CREATE POLICY rls_session_security_event_replay_insert
ON iam.session_security_events
FOR INSERT TO iam_session_authenticator
WITH CHECK (
    session_user = 'iam_session_authenticator'
    AND current_user = 'iam_session_authenticator'
    AND NULLIF(current_setting('app.scope_kind', true), '') =
        'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') =
        'REVOKE_REPLAYED_FAMILY'
    AND security_event_id =
        NULLIF(current_setting('app.command_id', true), '')::uuid
    AND event_type = 'REPLAYED_SESSION_HANDLE'
    AND replayed_session_id =
        NULLIF(current_setting('app.session_id', true), '')::uuid
    AND session_family_id =
        NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND occurred_at = transaction_timestamp()
    AND iam.replayed_session_matches_family(session_family_id)
    AND EXISTS (
        SELECT 1
        FROM iam.session_families AS replay_family
        JOIN iam.sessions AS current_session
          ON current_session.family_id = replay_family.id
         AND current_session.user_id = replay_family.user_id
         AND current_session.generation = replay_family.current_generation
        WHERE replay_family.id = session_family_id
          AND replay_family.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
          AND replay_family.status = 'REVOKED'
          AND replay_family.revocation_reason_code =
              'REPLAYED_SESSION_HANDLE'
          AND current_session.status = 'REVOKED'
          AND current_session.revocation_reason_code =
              'REPLAYED_SESSION_HANDLE'
    )
);

GRANT INSERT ON infra.outbox_events TO iam_session_authenticator;

CREATE POLICY rls_session_replay_audit_insert_system
ON audit.audit_events
FOR INSERT TO iam_session_authenticator
WITH CHECK (
    session_user = 'iam_session_authenticator'
    AND current_user = 'iam_session_authenticator'
    AND NULLIF(current_setting('app.scope_kind', true), '') =
        'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') =
        'REVOKE_REPLAYED_FAMILY'
    AND actor_kind = 'SYSTEM'
    AND actor_id = '00000000-0000-5000-8000-000000000017'::uuid
    AND original_actor_id IS NULL
    AND action_code = 'RevokeReplayedSessionFamily'
    AND target_kind = 'SessionFamily'
    AND target_id = NULLIF(
        current_setting('app.session_family_id', true),
        ''
    )::uuid
    AND organization_id IS NULL
    AND occurred_at = transaction_timestamp()
    AND before_status = 'ACTIVE'
    AND after_status = 'REVOKED'
    AND before_version IS NOT NULL
    AND after_version = before_version + 1
    AND role_code IS NULL
    AND purpose_code IS NULL
    AND reason_code = 'REPLAYED_SESSION_HANDLE'
    AND auth_strength_code IS NULL
    AND result_code = 'SUCCEEDED'
    AND event_id = NULLIF(
        current_setting('app.audit_event_id', true),
        ''
    )::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND correlation_id = NULLIF(
        current_setting('app.correlation_id', true),
        ''
    )::uuid
    AND causation_id = command_id
    AND trace_id = NULLIF(current_setting('app.trace_id', true), '')::uuid
    AND safe_attributes = '{}'::jsonb
    AND (target_id, after_version) = (
        SELECT replay_family.id, replay_family.aggregate_version
        FROM iam.session_families AS replay_family
        WHERE replay_family.id = target_id
          AND replay_family.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
          AND replay_family.status = 'REVOKED'
          AND replay_family.revocation_reason_code =
              'REPLAYED_SESSION_HANDLE'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.session_security_events AS marker
        WHERE marker.security_event_id = command_id
    )
);

CREATE POLICY rls_session_replay_outbox_insert_system
ON infra.outbox_events
FOR INSERT TO iam_session_authenticator
WITH CHECK (
    session_user = 'iam_session_authenticator'
    AND current_user = 'iam_session_authenticator'
    AND NULLIF(current_setting('app.scope_kind', true), '') =
        'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') =
        'REVOKE_REPLAYED_FAMILY'
    AND event_type = 'SessionRevoked'
    AND event_id = NULLIF(
        current_setting('app.outbox_event_id', true),
        ''
    )::uuid
    AND schema_version = 1
    AND aggregate_type = 'Session'
    AND aggregate_id <> NULLIF(current_setting('app.session_id', true), '')::uuid
    AND aggregate_version >= 2
    AND actor_kind = 'SYSTEM'
    AND actor_id = '00000000-0000-5000-8000-000000000017'::uuid
    AND original_actor_id IS NULL
    AND correlation_id = NULLIF(
        current_setting('app.correlation_id', true),
        ''
    )::uuid
    AND causation_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND trace_id = NULLIF(current_setting('app.trace_id', true), '')::uuid
    AND organization_id IS NULL
    AND occurred_at = transaction_timestamp()
    AND payload = pg_catalog.jsonb_build_object(
        'session_id', aggregate_id::text,
        'session_family_id', NULLIF(
            current_setting('app.session_family_id', true),
            ''
        ),
        'user_id', NULLIF(current_setting('app.actor_user_id', true), ''),
        'status', 'REVOKED'
    )
    AND delivery_status = 'PENDING'
    AND attempt_count = 0
    AND available_at = occurred_at
    AND created_at = occurred_at
    AND lease_owner IS NULL
    AND lease_until IS NULL
    AND published_at IS NULL
    AND last_error_code IS NULL
    AND (aggregate_id, aggregate_version) = (
        SELECT current_session.id, current_session.aggregate_version
        FROM iam.session_families AS replay_family
        JOIN iam.sessions AS current_session
          ON current_session.family_id = replay_family.id
         AND current_session.user_id = replay_family.user_id
         AND current_session.generation = replay_family.current_generation
        WHERE replay_family.id = NULLIF(
                  current_setting('app.session_family_id', true),
                  ''
              )::uuid
          AND replay_family.user_id = NULLIF(
                  current_setting('app.actor_user_id', true),
                  ''
              )::uuid
          AND replay_family.status = 'REVOKED'
          AND replay_family.revocation_reason_code =
              'REPLAYED_SESSION_HANDLE'
          AND current_session.status = 'REVOKED'
          AND current_session.revocation_reason_code =
              'REPLAYED_SESSION_HANDLE'
    )
    AND EXISTS (
        SELECT 1
        FROM iam.session_security_events AS marker
        WHERE marker.security_event_id = causation_id
    )
);

CREATE FUNCTION iam_api.revoke_replayed_session_family_v1(
    exact_security_event_id uuid,
    exact_audit_event_id uuid,
    exact_outbox_event_id uuid,
    exact_system_actor_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE(
    outcome text,
    revoked_session_id uuid,
    family_version bigint,
    session_version bigint
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, audit, infra, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    system_actor constant uuid := '00000000-0000-5000-8000-000000000017';
    exact_user_id uuid;
    exact_family_id uuid;
    exact_replayed_session_id uuid;
    family_status text;
    family_reason text;
    family_current_generation bigint;
    family_version_value bigint;
    current_session_id uuid;
    current_session_version bigint;
BEGIN
    IF session_user <> 'iam_session_authenticator'
       OR current_user <> 'iam_session_authenticator'
       OR NULLIF(current_setting('app.scope_kind', true), '') <>
            'SESSION_AUTHENTICATE'
       OR NULLIF(current_setting('app.operation', true), '') <>
            'REVOKE_REPLAYED_FAMILY' THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'session replay capability is unavailable';
    END IF;

    exact_user_id := NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid;
    exact_family_id := NULLIF(
        current_setting('app.session_family_id', true),
        ''
    )::uuid;
    exact_replayed_session_id := NULLIF(
        current_setting('app.session_id', true),
        ''
    )::uuid;

    IF exact_user_id IS NULL
       OR exact_family_id IS NULL
       OR exact_replayed_session_id IS NULL
       OR exact_security_event_id IS NULL
       OR exact_audit_event_id IS NULL
       OR exact_outbox_event_id IS NULL
       OR exact_system_actor_id IS NULL
       OR exact_correlation_id IS NULL
       OR exact_trace_id IS NULL
       OR exact_user_id = zero_uuid
       OR exact_family_id = zero_uuid
       OR exact_replayed_session_id = zero_uuid
       OR exact_security_event_id = zero_uuid
       OR exact_audit_event_id = zero_uuid
       OR exact_outbox_event_id = zero_uuid
       OR exact_correlation_id = zero_uuid
       OR exact_trace_id = zero_uuid
       OR exact_system_actor_id <> system_actor
       OR exact_security_event_id = exact_audit_event_id
       OR exact_security_event_id = exact_outbox_event_id
       OR exact_audit_event_id = exact_outbox_event_id
       OR exact_security_event_id <>
            NULLIF(current_setting('app.command_id', true), '')::uuid
       OR exact_audit_event_id <>
            NULLIF(current_setting('app.audit_event_id', true), '')::uuid
       OR exact_outbox_event_id <>
            NULLIF(current_setting('app.outbox_event_id', true), '')::uuid
       OR exact_correlation_id <>
            NULLIF(current_setting('app.correlation_id', true), '')::uuid
       OR exact_trace_id <>
            NULLIF(current_setting('app.trace_id', true), '')::uuid THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'session replay request is invalid';
    END IF;

    SELECT
        family.status,
        family.revocation_reason_code,
        family.current_generation,
        family.aggregate_version
    INTO
        family_status,
        family_reason,
        family_current_generation,
        family_version_value
    FROM iam.session_families AS family
    WHERE family.id = exact_family_id
      AND family.user_id = exact_user_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'session replay family is unavailable';
    END IF;

    PERFORM 1
    FROM iam.session_security_events AS marker
    WHERE marker.replayed_session_id = exact_replayed_session_id;

    IF FOUND THEN
        IF family_status <> 'REVOKED'
           OR family_reason <> 'REPLAYED_SESSION_HANDLE' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'session replay marker is inconsistent';
        END IF;
        SELECT
            session.id,
            session.aggregate_version
        INTO
            current_session_id,
            current_session_version
        FROM iam.sessions AS session
        WHERE session.family_id = exact_family_id
          AND session.user_id = exact_user_id
          AND session.generation = family_current_generation
          AND session.status = 'REVOKED'
          AND session.revocation_reason_code = 'REPLAYED_SESSION_HANDLE';
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'session replay result is inconsistent';
        END IF;
        RETURN QUERY SELECT
            'ALREADY_REVOKED'::text,
            current_session_id,
            family_version_value,
            current_session_version;
        RETURN;
    END IF;

    IF family_status = 'REVOKED' THEN
        SELECT
            session.id,
            session.aggregate_version
        INTO
            current_session_id,
            current_session_version
        FROM iam.sessions AS session
        WHERE session.family_id = exact_family_id
          AND session.user_id = exact_user_id
          AND session.generation = family_current_generation;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'terminal session family is inconsistent';
        END IF;
        RETURN QUERY SELECT
            'ALREADY_TERMINAL'::text,
            current_session_id,
            family_version_value,
            current_session_version;
        RETURN;
    END IF;

    SELECT
        session.id,
        session.aggregate_version
    INTO
        current_session_id,
        current_session_version
    FROM iam.sessions AS session
    WHERE session.family_id = exact_family_id
      AND session.user_id = exact_user_id
      AND session.generation = family_current_generation
      AND session.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'active session family is inconsistent';
    END IF;

    UPDATE iam.sessions AS session
    SET status = 'REVOKED',
        revoked_at = transaction_timestamp(),
        revocation_reason_code = 'REPLAYED_SESSION_HANDLE',
        aggregate_version = session.aggregate_version + 1,
        updated_at = transaction_timestamp()
    WHERE session.id = current_session_id
      AND session.aggregate_version = current_session_version
      AND session.status = 'ACTIVE'
    RETURNING session.aggregate_version INTO current_session_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'session replay write conflicted';
    END IF;

    UPDATE iam.session_families AS family
    SET status = 'REVOKED',
        revoked_at = transaction_timestamp(),
        revocation_reason_code = 'REPLAYED_SESSION_HANDLE',
        aggregate_version = family.aggregate_version + 1,
        updated_at = transaction_timestamp()
    WHERE family.id = exact_family_id
      AND family.aggregate_version = family_version_value
      AND family.status = 'ACTIVE'
    RETURNING family.aggregate_version INTO family_version_value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'session replay family write conflicted';
    END IF;

    INSERT INTO iam.session_security_events (
        security_event_id,
        event_type,
        session_family_id,
        replayed_session_id,
        user_id,
        occurred_at
    ) VALUES (
        exact_security_event_id,
        'REPLAYED_SESSION_HANDLE',
        exact_family_id,
        exact_replayed_session_id,
        exact_user_id,
        transaction_timestamp()
    );

    INSERT INTO audit.audit_events (
        event_id,
        occurred_at,
        actor_kind,
        actor_id,
        original_actor_id,
        action_code,
        target_kind,
        target_id,
        organization_id,
        before_status,
        after_status,
        before_version,
        after_version,
        role_code,
        purpose_code,
        reason_code,
        auth_strength_code,
        result_code,
        command_id,
        correlation_id,
        causation_id,
        trace_id,
        safe_attributes
    ) VALUES (
        exact_audit_event_id,
        transaction_timestamp(),
        'SYSTEM',
        system_actor,
        NULL,
        'RevokeReplayedSessionFamily',
        'SessionFamily',
        exact_family_id,
        NULL,
        'ACTIVE',
        'REVOKED',
        family_version_value - 1,
        family_version_value,
        NULL,
        NULL,
        'REPLAYED_SESSION_HANDLE',
        NULL,
        'SUCCEEDED',
        exact_security_event_id,
        exact_correlation_id,
        exact_security_event_id,
        exact_trace_id,
        '{}'::jsonb
    );

    INSERT INTO infra.outbox_events (
        event_id,
        event_type,
        schema_version,
        occurred_at,
        aggregate_type,
        aggregate_id,
        aggregate_version,
        actor_kind,
        actor_id,
        original_actor_id,
        correlation_id,
        causation_id,
        trace_id,
        organization_id,
        payload,
        delivery_status,
        attempt_count,
        available_at,
        lease_owner,
        lease_until,
        published_at,
        last_error_code,
        created_at
    ) VALUES (
        exact_outbox_event_id,
        'SessionRevoked',
        1,
        transaction_timestamp(),
        'Session',
        current_session_id,
        current_session_version,
        'SYSTEM',
        system_actor,
        NULL,
        exact_correlation_id,
        exact_security_event_id,
        exact_trace_id,
        NULL,
        pg_catalog.jsonb_build_object(
            'session_id', current_session_id::text,
            'session_family_id', exact_family_id::text,
            'user_id', exact_user_id::text,
            'status', 'REVOKED'
        ),
        'PENDING',
        0,
        transaction_timestamp(),
        NULL,
        NULL,
        NULL,
        NULL,
        transaction_timestamp()
    );

    RETURN QUERY SELECT
        'REVOKED'::text,
        current_session_id,
        family_version_value,
        current_session_version;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.revoke_replayed_session_family_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.revoke_replayed_session_family_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid
) TO iam_session_authenticator;
