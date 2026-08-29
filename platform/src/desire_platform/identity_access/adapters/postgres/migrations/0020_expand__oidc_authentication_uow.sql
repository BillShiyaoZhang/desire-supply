-- Complete the v2 OIDC protocol evidence required by the production adapter.
-- Existing protocol_version=1 fixtures remain readable and unchanged.

ALTER TABLE iam.auth_transactions
    ADD COLUMN expected_contact_type text NULL,
    ADD COLUMN expected_contact_binding_digest bytea NULL,
    ADD COLUMN expected_contact_binding_key_id varchar(64) NULL,
    ADD COLUMN nonce_ciphertext bytea NULL,
    ADD COLUMN nonce_encryption_key_id varchar(64) NULL,
    ADD COLUMN nonce_encryption_algorithm text NULL,
    ADD COLUMN pkce_code_challenge varchar(128) NULL,
    ADD COLUMN pkce_code_challenge_method text NULL,
    ADD COLUMN provider_issuer varchar(2048) NULL,
    ADD COLUMN provider_audience varchar(512) NULL,
    ADD COLUMN return_to varchar(2048) NULL,
    ADD COLUMN security_policy_version varchar(64) NULL,
    ADD COLUMN exchange_owner_id uuid NULL,
    ADD COLUMN exchange_claimed_at timestamptz NULL,
    ADD COLUMN aggregate_version bigint NULL;

ALTER TABLE iam.auth_transactions
    ADD CONSTRAINT ck_auth_transaction_v2_contact CHECK (
        protocol_version <> 2
        OR (
            (
                invitation_id IS NULL
                AND expected_contact_type IS NULL
                AND expected_contact_binding_digest IS NULL
                AND expected_contact_binding_key_id IS NULL
            )
            OR (
                invitation_id IS NOT NULL
                AND expected_contact_type IN ('EMAIL', 'PHONE')
                AND octet_length(expected_contact_binding_digest) = 32
                AND length(expected_contact_binding_key_id) > 0
            )
        )
    ),
    ADD CONSTRAINT ck_auth_transaction_v2_protocol CHECK (
        protocol_version <> 2
        OR (
            octet_length(nonce_ciphertext) > 0
            AND length(nonce_encryption_key_id) > 0
            AND nonce_encryption_algorithm = 'AES_256_GCM_V1'
            AND pkce_code_challenge ~ '^[A-Za-z0-9_-]{43,128}$'
            AND pkce_code_challenge_method = 'S256'
            AND provider_issuer ~ '^https://'
            AND length(provider_audience) > 0
            AND return_to ~ '^/[^/]'
            AND length(security_policy_version) > 0
            AND aggregate_version >= 1
        )
    ),
    ADD CONSTRAINT ck_auth_transaction_v2_exchange CHECK (
        protocol_version <> 2
        OR (
            (
                status = 'PENDING'
                AND attempt = 0
                AND exchange_owner_id IS NULL
                AND exchange_claimed_at IS NULL
                AND aggregate_version = 1
            )
            OR (
                status = 'EXCHANGING'
                AND attempt = 1
                AND exchange_owner_id IS NOT NULL
                AND exchange_claimed_at IS NOT NULL
                AND provider_error_class IS NULL
                AND aggregate_version = 2
            )
            OR (
                status = 'FAILED'
                AND attempt = 0
                AND exchange_owner_id IS NULL
                AND exchange_claimed_at IS NULL
                AND provider_error_class IN ('REJECTED', 'MISCONFIGURED')
                AND aggregate_version = 2
            )
            OR (
                status IN ('SUCCEEDED', 'FAILED', 'RESULT_UNKNOWN')
                AND attempt = 1
                AND exchange_owner_id IS NOT NULL
                AND exchange_claimed_at IS NOT NULL
                AND aggregate_version = 3
                AND (
                    (status = 'SUCCEEDED' AND provider_error_class IS NULL)
                    OR (
                        status = 'FAILED'
                        AND provider_error_class IN ('REJECTED', 'MISCONFIGURED')
                    )
                    OR (
                        status = 'RESULT_UNKNOWN'
                        AND provider_error_class = 'RESULT_UNKNOWN'
                    )
                )
            )
        )
    );

CREATE OR REPLACE FUNCTION iam.enforce_auth_transaction_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.protocol_version IS DISTINCT FROM OLD.protocol_version
       OR NEW.browser_binding_digest IS DISTINCT FROM OLD.browser_binding_digest
       OR NEW.browser_binding_key_id IS DISTINCT FROM OLD.browser_binding_key_id
       OR NEW.initiating_session_id IS DISTINCT FROM OLD.initiating_session_id
       OR NEW.initiating_user_id IS DISTINCT FROM OLD.initiating_user_id
       OR NEW.expected_user_id IS DISTINCT FROM OLD.expected_user_id
       OR NEW.invitation_id IS DISTINCT FROM OLD.invitation_id
       OR NEW.invitation_version IS DISTINCT FROM OLD.invitation_version
       OR NEW.expected_contact_point_id IS DISTINCT FROM OLD.expected_contact_point_id
       OR NEW.expected_contact_type IS DISTINCT FROM OLD.expected_contact_type
       OR NEW.expected_contact_binding_digest
            IS DISTINCT FROM OLD.expected_contact_binding_digest
       OR NEW.expected_contact_binding_key_id
            IS DISTINCT FROM OLD.expected_contact_binding_key_id
       OR NEW.state_digest IS DISTINCT FROM OLD.state_digest
       OR NEW.state_digest_key_id IS DISTINCT FROM OLD.state_digest_key_id
       OR NEW.nonce_digest IS DISTINCT FROM OLD.nonce_digest
       OR NEW.nonce_digest_key_id IS DISTINCT FROM OLD.nonce_digest_key_id
       OR NEW.nonce_ciphertext IS DISTINCT FROM OLD.nonce_ciphertext
       OR NEW.nonce_encryption_key_id IS DISTINCT FROM OLD.nonce_encryption_key_id
       OR NEW.nonce_encryption_algorithm
            IS DISTINCT FROM OLD.nonce_encryption_algorithm
       OR NEW.pkce_verifier_ciphertext
            IS DISTINCT FROM OLD.pkce_verifier_ciphertext
       OR NEW.pkce_encryption_key_id IS DISTINCT FROM OLD.pkce_encryption_key_id
       OR NEW.pkce_encryption_algorithm
            IS DISTINCT FROM OLD.pkce_encryption_algorithm
       OR NEW.pkce_code_challenge IS DISTINCT FROM OLD.pkce_code_challenge
       OR NEW.pkce_code_challenge_method
            IS DISTINCT FROM OLD.pkce_code_challenge_method
       OR NEW.provider_issuer IS DISTINCT FROM OLD.provider_issuer
       OR NEW.provider_audience IS DISTINCT FROM OLD.provider_audience
       OR NEW.redirect_uri IS DISTINCT FROM OLD.redirect_uri
       OR NEW.return_to IS DISTINCT FROM OLD.return_to
       OR NEW.security_policy_version IS DISTINCT FROM OLD.security_policy_version
       OR NEW.deadline IS DISTINCT FROM OLD.deadline
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.attempt < OLD.attempt
       OR (OLD.status = 'PENDING' AND NEW.status NOT IN ('EXCHANGING', 'FAILED'))
       OR (
           OLD.status = 'EXCHANGING'
           AND NEW.status NOT IN ('SUCCEEDED', 'RESULT_UNKNOWN', 'FAILED')
       )
       OR (
           OLD.status IN ('SUCCEEDED', 'RESULT_UNKNOWN', 'FAILED')
           AND NEW.status <> OLD.status
       )
       OR (
           OLD.protocol_version = 2
           AND NEW.aggregate_version <> OLD.aggregate_version + 1
       )
       OR (
           OLD.protocol_version = 2
           AND OLD.status <> 'PENDING'
           AND NEW.exchange_owner_id IS DISTINCT FROM OLD.exchange_owner_id
       )
       OR (
           OLD.protocol_version = 2
           AND OLD.status <> 'PENDING'
           AND NEW.exchange_claimed_at IS DISTINCT FROM OLD.exchange_claimed_at
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_auth_transaction_state',
            MESSAGE = 'invalid auth transaction mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE POLICY rls_oidc_callback_transaction_definer
ON iam.auth_transactions
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND state_digest_key_id = NULLIF(
        current_setting('app.oidc_state_digest_key_id', true),
        ''
    )
    AND state_digest = decode(
        NULLIF(current_setting('app.oidc_state_digest', true), ''),
        'hex'
    )
    AND browser_binding_key_id = NULLIF(
        current_setting('app.oidc_browser_digest_key_id', true),
        ''
    )
    AND browser_binding_digest = decode(
        NULLIF(current_setting('app.oidc_browser_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_oidc_external_identity_definer
ON iam.external_identities
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND issuer = NULLIF(current_setting('app.oidc_subject_issuer', true), '')
    AND subject_digest_key_id = NULLIF(
        current_setting('app.oidc_subject_digest_key_id', true),
        ''
    )
    AND subject_digest = decode(
        NULLIF(current_setting('app.oidc_subject_digest', true), ''),
        'hex'
    )
);

-- ``SELECT .. FOR UPDATE`` also requires an UPDATE policy.  Keep that
-- authority separate from the read policy so the callback program can lock
-- only the one externally identified row; it still cannot insert or delete.
CREATE POLICY rls_oidc_external_identity_lock_definer
ON iam.external_identities
FOR UPDATE TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND issuer = NULLIF(current_setting('app.oidc_subject_issuer', true), '')
    AND subject_digest_key_id = NULLIF(
        current_setting('app.oidc_subject_digest_key_id', true),
        ''
    )
    AND subject_digest = decode(
        NULLIF(current_setting('app.oidc_subject_digest', true), ''),
        'hex'
    )
)
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND issuer = NULLIF(current_setting('app.oidc_subject_issuer', true), '')
    AND subject_digest_key_id = NULLIF(
        current_setting('app.oidc_subject_digest_key_id', true),
        ''
    )
    AND subject_digest = decode(
        NULLIF(current_setting('app.oidc_subject_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_oidc_user_definer
ON iam.users
FOR SELECT TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND EXISTS (
        SELECT 1
        FROM iam.external_identities AS exact_identity
        WHERE exact_identity.user_id = users.id
          AND exact_identity.issuer = NULLIF(
              current_setting('app.oidc_subject_issuer', true),
              ''
          )
          AND exact_identity.subject_digest_key_id = NULLIF(
              current_setting('app.oidc_subject_digest_key_id', true),
              ''
          )
          AND exact_identity.subject_digest = decode(
              NULLIF(current_setting('app.oidc_subject_digest', true), ''),
              'hex'
          )
    )
);

CREATE POLICY rls_oidc_user_lock_definer
ON iam.users
FOR UPDATE TO schema_owner
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND EXISTS (
        SELECT 1
        FROM iam.external_identities AS exact_identity
        WHERE exact_identity.user_id = users.id
          AND exact_identity.issuer = NULLIF(
              current_setting('app.oidc_subject_issuer', true),
              ''
          )
          AND exact_identity.subject_digest_key_id = NULLIF(
              current_setting('app.oidc_subject_digest_key_id', true),
              ''
          )
          AND exact_identity.subject_digest = decode(
              NULLIF(current_setting('app.oidc_subject_digest', true), ''),
              'hex'
          )
    )
)
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
    AND EXISTS (
        SELECT 1
        FROM iam.external_identities AS exact_identity
        WHERE exact_identity.user_id = users.id
          AND exact_identity.issuer = NULLIF(
              current_setting('app.oidc_subject_issuer', true),
              ''
          )
          AND exact_identity.subject_digest_key_id = NULLIF(
              current_setting('app.oidc_subject_digest_key_id', true),
              ''
          )
          AND exact_identity.subject_digest = decode(
              NULLIF(current_setting('app.oidc_subject_digest', true), ''),
              'hex'
          )
    )
);

CREATE POLICY rls_oidc_audit_insert_system
ON audit.audit_events
FOR INSERT TO iam_onboarding
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') IN ('BEGIN', 'COMPLETE')
    AND actor_kind = 'SYSTEM'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND target_kind = 'AuthTransaction'
    AND target_id = NULLIF(
        current_setting('app.auth_transaction_id', true),
        ''
    )::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND causation_id = command_id
    AND organization_id IS NULL
);

CREATE FUNCTION iam_api.read_oidc_callback_v2(
    exact_state_digest_key_id text,
    exact_state_digest bytea,
    exact_browser_binding_key_id text,
    exact_browser_binding_digest bytea
)
RETURNS TABLE (
    auth_transaction_id uuid,
    status text,
    purpose text,
    attempt smallint,
    browser_binding_digest bytea,
    browser_binding_key_id text,
    initiating_session_id uuid,
    initiating_user_id uuid,
    expected_user_id uuid,
    invitation_id uuid,
    invitation_version bigint,
    expected_contact_point_id uuid,
    expected_contact_type text,
    expected_contact_binding_digest bytea,
    expected_contact_binding_key_id text,
    state_digest bytea,
    state_digest_key_id text,
    nonce_digest bytea,
    nonce_digest_key_id text,
    nonce_ciphertext bytea,
    nonce_encryption_key_id text,
    pkce_verifier_ciphertext bytea,
    pkce_encryption_key_id text,
    pkce_code_challenge text,
    provider_issuer text,
    provider_audience text,
    redirect_uri text,
    return_to text,
    security_policy_version text,
    deadline timestamptz,
    exchange_owner_id uuid,
    exchange_claimed_at timestamptz,
    provider_error_class text,
    aggregate_version bigint,
    created_at timestamptz,
    updated_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
SELECT
    candidate.id,
    candidate.status,
    candidate.purpose,
    candidate.attempt,
    candidate.browser_binding_digest,
    candidate.browser_binding_key_id,
    candidate.initiating_session_id,
    candidate.initiating_user_id,
    candidate.expected_user_id,
    candidate.invitation_id,
    candidate.invitation_version,
    candidate.expected_contact_point_id,
    candidate.expected_contact_type,
    candidate.expected_contact_binding_digest,
    candidate.expected_contact_binding_key_id,
    candidate.state_digest,
    candidate.state_digest_key_id,
    candidate.nonce_digest,
    candidate.nonce_digest_key_id,
    candidate.nonce_ciphertext,
    candidate.nonce_encryption_key_id,
    candidate.pkce_verifier_ciphertext,
    candidate.pkce_encryption_key_id,
    candidate.pkce_code_challenge,
    candidate.provider_issuer,
    candidate.provider_audience,
    candidate.redirect_uri,
    candidate.return_to,
    candidate.security_policy_version,
    candidate.deadline,
    candidate.exchange_owner_id,
    candidate.exchange_claimed_at,
    candidate.provider_error_class,
    candidate.aggregate_version,
    candidate.created_at,
    candidate.updated_at
FROM iam.auth_transactions AS candidate
WHERE session_user = 'iam_onboarding'
  AND current_user = 'schema_owner'
  AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
  AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE'
  AND NULLIF(current_setting('app.oidc_state_digest_key_id', true), '')
        = exact_state_digest_key_id
  AND decode(NULLIF(current_setting('app.oidc_state_digest', true), ''), 'hex')
        = exact_state_digest
  AND NULLIF(current_setting('app.oidc_browser_digest_key_id', true), '')
        = exact_browser_binding_key_id
  AND decode(NULLIF(current_setting('app.oidc_browser_digest', true), ''), 'hex')
        = exact_browser_binding_digest
  AND candidate.protocol_version = 2
  AND candidate.status = 'PENDING'
  AND candidate.aggregate_version = 1
  AND candidate.state_digest_key_id = exact_state_digest_key_id
  AND candidate.state_digest = exact_state_digest
  AND candidate.browser_binding_key_id = exact_browser_binding_key_id
  AND candidate.browser_binding_digest = exact_browser_binding_digest
  AND transaction_timestamp() < candidate.deadline
$function$;

CREATE FUNCTION iam_api.lock_oidc_identity_v2(
    exact_issuer text,
    exact_subject_digest bytea,
    exact_subject_digest_key_id text
)
RETURNS TABLE (
    external_identity_id uuid,
    user_id uuid,
    user_status text,
    user_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    locked_identity_id uuid;
    locked_user_id uuid;
    locked_user_status text;
    locked_user_version bigint;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE'
       OR NULLIF(current_setting('app.oidc_subject_issuer', true), '')
            IS DISTINCT FROM exact_issuer
       OR decode(
            NULLIF(current_setting('app.oidc_subject_digest', true), ''),
            'hex'
       ) IS DISTINCT FROM exact_subject_digest
       OR NULLIF(current_setting('app.oidc_subject_digest_key_id', true), '')
            IS DISTINCT FROM exact_subject_digest_key_id
       OR octet_length(exact_subject_digest) <> 32 THEN
        RETURN;
    END IF;

    SELECT identity.id, identity.user_id
    INTO locked_identity_id, locked_user_id
    FROM iam.external_identities AS identity
    WHERE identity.issuer = exact_issuer
      AND identity.subject_digest = exact_subject_digest
      AND identity.subject_digest_key_id = exact_subject_digest_key_id
      AND identity.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT candidate.status, candidate.aggregate_version
    INTO locked_user_status, locked_user_version
    FROM iam.users AS candidate
    WHERE candidate.id = locked_user_id
      AND candidate.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    external_identity_id := locked_identity_id;
    user_id := locked_user_id;
    user_status := locked_user_status;
    user_version := locked_user_version;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.read_oidc_callback_v2(text, bytea, text, bytea)
FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.lock_oidc_identity_v2(text, bytea, text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION iam_api.read_oidc_callback_v2(
    text, bytea, text, bytea
) TO iam_onboarding;
GRANT EXECUTE ON FUNCTION iam_api.lock_oidc_identity_v2(text, bytea, text)
TO iam_onboarding;
