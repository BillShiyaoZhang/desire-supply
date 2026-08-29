-- IAM 0028: keep policy/consent authentication evidence compatible with OIDC.
--
-- OIDC NumericDate auth_time is second-precision, while PostgreSQL records the
-- successful exchange at transaction_timestamp() precision.  The completed
-- authorization protocol deadline is not the lifetime of the active Session.
-- The principal lock therefore proves ordered provenance while retaining the
-- exact User, SessionFamily, Session, AuthTransaction, generation, and status
-- locks established by IAM 0014.

CREATE OR REPLACE FUNCTION iam.lock_policy_consent_principal_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_session_family_id uuid,
    exact_auth_transaction_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    locked_family iam.session_families%ROWTYPE;
    locked_session iam.sessions%ROWTYPE;
    locked_user iam.users%ROWTYPE;
    locked_auth iam.auth_transactions%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'SELF'
       OR NULLIF(current_setting('app.operation', true), '') NOT IN (
            'ACCEPT_CURRENT_POLICIES',
            'GRANT_CONSENT'
       )
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.target_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.session_family_id', true), '')
            IS DISTINCT FROM exact_session_family_id::text
       OR NULLIF(current_setting('app.auth_transaction_id', true), '')
            IS DISTINCT FROM exact_auth_transaction_id::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_policy_consent_principal_scope',
            MESSAGE = 'policy consent principal scope is invalid';
    END IF;

    SELECT family.*
    INTO locked_family
    FROM iam.session_families AS family
    WHERE family.id = exact_session_family_id
      AND family.user_id = exact_actor_user_id
    FOR UPDATE;

    SELECT session.*
    INTO locked_session
    FROM iam.sessions AS session
    WHERE session.id = exact_session_id
      AND session.user_id = exact_actor_user_id
      AND session.family_id = exact_session_family_id
    FOR UPDATE;

    SELECT actor.*
    INTO locked_user
    FROM iam.users AS actor
    WHERE actor.id = exact_actor_user_id
    FOR UPDATE;

    SELECT auth.*
    INTO locked_auth
    FROM iam.auth_transactions AS auth
    WHERE auth.id = exact_auth_transaction_id
    FOR UPDATE;

    IF locked_family.id IS NULL
       OR locked_session.id IS NULL
       OR locked_user.id IS NULL
       OR locked_auth.id IS NULL
       OR locked_family.status <> 'ACTIVE'
       OR locked_session.status <> 'ACTIVE'
       OR locked_user.status <> 'ACTIVE'
       OR locked_family.current_generation <> locked_session.generation
       OR locked_session.auth_transaction_id <> exact_auth_transaction_id
       OR locked_session.auth_time IS NULL
       OR locked_session.auth_time > transaction_timestamp()
       OR locked_session.idle_expires_at <= transaction_timestamp()
       OR locked_session.absolute_expires_at <= transaction_timestamp()
       OR locked_auth.status <> 'SUCCEEDED'
       OR locked_auth.purpose NOT IN ('LOGIN', 'STEP_UP')
       OR locked_auth.expected_user_id NOT IN (exact_actor_user_id)
          AND locked_auth.expected_user_id IS NOT NULL
       OR locked_auth.succeeded_at IS NULL
       OR locked_auth.created_at > locked_auth.succeeded_at
       OR locked_auth.succeeded_at > locked_auth.deadline
       OR locked_auth.succeeded_at > transaction_timestamp()
       OR locked_auth.succeeded_at > locked_session.created_at
       OR locked_session.auth_time > locked_auth.succeeded_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_policy_consent_principal_active',
            MESSAGE = 'policy consent principal is unavailable';
    END IF;

    RETURN jsonb_build_object(
        'user_id', locked_user.id::text,
        'user_status', locked_user.status,
        'user_version', locked_user.aggregate_version,
        'session_id', locked_session.id::text,
        'session_family_id', locked_family.id::text,
        'auth_transaction_id', locked_session.auth_transaction_id::text,
        'auth_time', locked_session.auth_time,
        'acr_code', locked_session.acr_code,
        'amr_codes', to_jsonb(iam.canonical_text_array(locked_session.amr_codes))
    );
END
$function$;

ALTER FUNCTION iam.lock_policy_consent_principal_v1(
    uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.lock_policy_consent_principal_v1(
    uuid, uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.lock_policy_consent_principal_v1(
    uuid, uuid, uuid, uuid
) TO iam_app;

DO $assertions$
BEGIN
    IF NOT pg_catalog.has_function_privilege(
        'iam_app',
        'iam.lock_policy_consent_principal_v1(uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_onboarding',
        'iam.lock_policy_consent_principal_v1(uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam.lock_policy_consent_principal_v1(uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy consent principal EXECUTE assertion failed';
    END IF;
END
$assertions$;
