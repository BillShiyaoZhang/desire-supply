CREATE FUNCTION iam.text_array_is_unique_nonnull(input_values text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT count(*) > 0
       AND count(*) = count(value)
       AND count(*) = count(DISTINCT value)
    FROM unnest(input_values) AS item(value)
$function$;

CREATE FUNCTION iam.canonical_text_array(input_values text[])
RETURNS text[]
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT array_agg(DISTINCT value ORDER BY value)
    FROM unnest(input_values) AS item(value)
$function$;

CREATE TABLE iam.auth_transactions (
    id uuid NOT NULL,
    status text NOT NULL,
    purpose text NOT NULL,
    attempt smallint NOT NULL,
    protocol_version bigint NOT NULL,
    browser_binding_digest bytea NOT NULL,
    browser_binding_key_id varchar(64) NOT NULL,
    initiating_session_id uuid NULL,
    initiating_user_id uuid NULL,
    expected_user_id uuid NULL,
    invitation_id uuid NULL,
    invitation_version bigint NULL,
    expected_contact_point_id uuid NULL,
    state_digest bytea NOT NULL,
    state_digest_key_id varchar(64) NOT NULL,
    nonce_digest bytea NOT NULL,
    nonce_digest_key_id varchar(64) NOT NULL,
    pkce_verifier_ciphertext bytea NOT NULL,
    pkce_encryption_key_id varchar(64) NOT NULL,
    pkce_encryption_algorithm text NOT NULL,
    redirect_uri varchar(2048) NOT NULL,
    provider_error_class text NULL,
    deadline timestamptz NOT NULL,
    succeeded_at timestamptz NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_auth_transactions PRIMARY KEY (id),
    CONSTRAINT uq_auth_transaction_state UNIQUE (state_digest),
    CONSTRAINT uq_auth_transaction_invitation_contact UNIQUE (
        id,
        invitation_id,
        expected_contact_point_id
    ),
    CONSTRAINT fk_auth_transaction_initiating_user FOREIGN KEY (initiating_user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_auth_transaction_expected_user FOREIGN KEY (expected_user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_auth_transaction_invitation_contact FOREIGN KEY (
        invitation_id,
        expected_contact_point_id
    ) REFERENCES iam.access_invitations (id, recipient_contact_id) ON DELETE RESTRICT,
    CONSTRAINT ck_auth_transaction_status CHECK (
        status IN ('PENDING', 'EXCHANGING', 'SUCCEEDED', 'RESULT_UNKNOWN', 'FAILED')
    ),
    CONSTRAINT ck_auth_transaction_purpose CHECK (
        purpose IN ('LOGIN', 'ENROLLMENT', 'STEP_UP')
    ),
    CONSTRAINT ck_auth_transaction_attempt CHECK (attempt >= 0),
    CONSTRAINT ck_auth_transaction_protocol_version CHECK (protocol_version >= 1),
    CONSTRAINT ck_auth_transaction_digest_shape CHECK (
        octet_length(browser_binding_digest) = 32
        AND octet_length(state_digest) = 32
        AND octet_length(nonce_digest) = 32
    ),
    CONSTRAINT ck_auth_transaction_pkce CHECK (
        octet_length(pkce_verifier_ciphertext) > 0
        AND pkce_encryption_algorithm = 'AES_256_GCM_V1'
    ),
    CONSTRAINT ck_auth_transaction_purpose_shape CHECK (
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
                OR
                (
                    initiating_session_id IS NOT NULL
                    AND initiating_user_id IS NOT NULL
                    AND expected_user_id = initiating_user_id
                )
            )
        )
        OR
        (
            purpose = 'ENROLLMENT'
            AND initiating_session_id IS NULL
            AND initiating_user_id IS NULL
            AND expected_user_id IS NULL
            AND invitation_id IS NOT NULL
            AND invitation_version IS NOT NULL
            AND expected_contact_point_id IS NOT NULL
        )
        OR
        (
            purpose = 'STEP_UP'
            AND initiating_session_id IS NOT NULL
            AND initiating_user_id IS NOT NULL
            AND expected_user_id = initiating_user_id
            AND invitation_id IS NOT NULL
            AND invitation_version IS NOT NULL
            AND expected_contact_point_id IS NOT NULL
        )
    ),
    CONSTRAINT ck_auth_transaction_invitation_version CHECK (
        invitation_version IS NULL OR invitation_version >= 1
    ),
    CONSTRAINT ck_auth_transaction_result_shape CHECK (
        (
            status IN ('PENDING', 'EXCHANGING')
            AND succeeded_at IS NULL
            AND provider_error_class IS NULL
        )
        OR
        (
            status = 'SUCCEEDED'
            AND succeeded_at IS NOT NULL
            AND provider_error_class IS NULL
        )
        OR
        (
            status = 'RESULT_UNKNOWN'
            AND succeeded_at IS NULL
        )
        OR
        (
            status = 'FAILED'
            AND succeeded_at IS NULL
            AND provider_error_class IS NOT NULL
        )
    ),
    CONSTRAINT ck_auth_transaction_time CHECK (
        deadline > created_at
        AND updated_at >= created_at
        AND (succeeded_at IS NULL OR succeeded_at >= created_at)
    )
);

CREATE TABLE iam.session_families (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    current_generation bigint NOT NULL,
    revoked_at timestamptz NULL,
    revocation_reason_code varchar(64) NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_session_families PRIMARY KEY (id),
    CONSTRAINT uq_session_family_id_user UNIQUE (id, user_id),
    CONSTRAINT fk_session_family_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT ck_session_family_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT ck_session_family_revocation CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason_code IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_session_family_generation CHECK (current_generation >= 1),
    CONSTRAINT ck_session_family_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_session_family_time CHECK (
        updated_at >= created_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE TABLE iam.sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    family_id uuid NOT NULL,
    generation bigint NOT NULL,
    predecessor_session_id uuid NULL,
    handle_digest bytea NOT NULL,
    handle_digest_key_id varchar(64) NOT NULL,
    csrf_salt bytea NOT NULL,
    csrf_key_id varchar(64) NOT NULL,
    csrf_digest bytea NOT NULL,
    verified_contact_point_id uuid NULL,
    verified_at timestamptz NULL,
    verified_for_invitation_id uuid NULL,
    auth_transaction_id uuid NULL,
    auth_time timestamptz NOT NULL,
    acr_code varchar(128) NOT NULL,
    amr_codes text[] NOT NULL,
    created_at timestamptz NOT NULL,
    last_activity_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    device_label varchar(80) NOT NULL,
    status text NOT NULL,
    rotation_reason text NOT NULL,
    revoked_at timestamptz NULL,
    revocation_reason_code varchar(64) NULL,
    aggregate_version bigint NOT NULL,
    CONSTRAINT pk_sessions PRIMARY KEY (id),
    CONSTRAINT uq_session_id_user UNIQUE (id, user_id),
    CONSTRAINT uq_session_id_family UNIQUE (id, family_id),
    CONSTRAINT uq_session_id_auth_transaction UNIQUE (id, auth_transaction_id),
    CONSTRAINT uq_session_family_generation UNIQUE (family_id, generation),
    CONSTRAINT uq_session_predecessor UNIQUE (predecessor_session_id),
    CONSTRAINT uq_session_handle_digest UNIQUE (handle_digest_key_id, handle_digest),
    CONSTRAINT fk_session_family_user_pair FOREIGN KEY (family_id, user_id)
        REFERENCES iam.session_families (id, user_id) ON DELETE RESTRICT,
    CONSTRAINT fk_session_predecessor_family FOREIGN KEY (
        predecessor_session_id,
        family_id
    ) REFERENCES iam.sessions (id, family_id) ON DELETE RESTRICT,
    CONSTRAINT fk_session_contact FOREIGN KEY (verified_contact_point_id)
        REFERENCES iam.contact_points (id) ON DELETE RESTRICT,
    CONSTRAINT fk_session_invitation_contact FOREIGN KEY (
        verified_for_invitation_id,
        verified_contact_point_id
    ) REFERENCES iam.access_invitations (id, recipient_contact_id) ON DELETE RESTRICT,
    CONSTRAINT fk_session_auth_transaction FOREIGN KEY (auth_transaction_id)
        REFERENCES iam.auth_transactions (id) ON DELETE RESTRICT,
    CONSTRAINT fk_session_auth_invitation_contact FOREIGN KEY (
        auth_transaction_id,
        verified_for_invitation_id,
        verified_contact_point_id
    ) REFERENCES iam.auth_transactions (
        id,
        invitation_id,
        expected_contact_point_id
    ) ON DELETE RESTRICT,
    CONSTRAINT ck_session_generation CHECK (generation >= 1),
    CONSTRAINT ck_session_predecessor CHECK (
        predecessor_session_id IS NULL OR predecessor_session_id <> id
    ),
    CONSTRAINT ck_session_handle_digest CHECK (octet_length(handle_digest) = 32),
    CONSTRAINT ck_session_csrf CHECK (
        octet_length(csrf_salt) = 32 AND octet_length(csrf_digest) = 32
    ),
    CONSTRAINT ck_session_invitation_binding CHECK (
        (
            verified_contact_point_id IS NULL
            AND verified_at IS NULL
            AND verified_for_invitation_id IS NULL
        )
        OR
        (
            verified_contact_point_id IS NOT NULL
            AND verified_at IS NOT NULL
            AND verified_for_invitation_id IS NOT NULL
            AND auth_transaction_id IS NOT NULL
        )
    ),
    CONSTRAINT ck_session_auth_context CHECK (
        length(acr_code) > 0
        AND cardinality(amr_codes) BETWEEN 1 AND 16
        AND iam.text_array_is_unique_nonnull(amr_codes)
    ),
    CONSTRAINT ck_session_device_label CHECK (
        device_label IN ('Browser', 'Mobile browser')
    ),
    CONSTRAINT ck_session_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_session_rotation_reason CHECK (
        rotation_reason IN ('LOGIN', 'ENROLLMENT', 'STEP_UP', 'INVITATION_ACCEPT')
    ),
    CONSTRAINT ck_session_revocation CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason_code IS NULL)
        OR (
            status IN ('REVOKED', 'EXPIRED')
            AND revoked_at IS NOT NULL
            AND revocation_reason_code IS NOT NULL
        )
    ),
    CONSTRAINT ck_session_accept_successor CHECK (
        NOT (status = 'ACTIVE' AND rotation_reason = 'INVITATION_ACCEPT')
        OR (
            verified_contact_point_id IS NULL
            AND verified_at IS NULL
            AND verified_for_invitation_id IS NULL
            AND auth_transaction_id IS NULL
        )
    ),
    CONSTRAINT ck_session_lifetime CHECK (
        auth_time <= created_at
        AND created_at <= last_activity_at
        AND last_activity_at < idle_expires_at
        AND idle_expires_at <= absolute_expires_at
        AND updated_at >= created_at
        AND (verified_at IS NULL OR verified_at <= created_at)
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    ),
    CONSTRAINT ck_session_version CHECK (aggregate_version >= 1)
);

CREATE UNIQUE INDEX ux_session_one_active_family
    ON iam.sessions (family_id)
    WHERE status = 'ACTIVE';

ALTER TABLE iam.auth_transactions
    ADD CONSTRAINT fk_auth_transaction_initiating_session
    FOREIGN KEY (initiating_session_id, initiating_user_id)
    REFERENCES iam.sessions (id, user_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION iam.enforce_auth_transaction_transition()
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
       OR NEW.state_digest IS DISTINCT FROM OLD.state_digest
       OR NEW.state_digest_key_id IS DISTINCT FROM OLD.state_digest_key_id
       OR NEW.nonce_digest IS DISTINCT FROM OLD.nonce_digest
       OR NEW.nonce_digest_key_id IS DISTINCT FROM OLD.nonce_digest_key_id
       OR NEW.pkce_verifier_ciphertext IS DISTINCT FROM OLD.pkce_verifier_ciphertext
       OR NEW.pkce_encryption_key_id IS DISTINCT FROM OLD.pkce_encryption_key_id
       OR NEW.pkce_encryption_algorithm IS DISTINCT FROM OLD.pkce_encryption_algorithm
       OR NEW.redirect_uri IS DISTINCT FROM OLD.redirect_uri
       OR NEW.deadline IS DISTINCT FROM OLD.deadline
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.attempt < OLD.attempt
       OR (OLD.status = 'PENDING' AND NEW.status NOT IN ('EXCHANGING', 'FAILED'))
       OR (OLD.status = 'EXCHANGING' AND NEW.status NOT IN ('SUCCEEDED', 'RESULT_UNKNOWN', 'FAILED'))
       OR (OLD.status IN ('SUCCEEDED', 'RESULT_UNKNOWN', 'FAILED') AND NEW.status <> OLD.status) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_auth_transaction_state',
            MESSAGE = 'invalid auth transaction mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_auth_transaction_state
BEFORE UPDATE ON iam.auth_transactions
FOR EACH ROW EXECUTE FUNCTION iam.enforce_auth_transaction_transition();

CREATE FUNCTION iam.enforce_session_family_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.current_generation < OLD.current_generation
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'REVOKED'))
       OR (OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_session_family_state',
            MESSAGE = 'invalid session family mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_session_family_state
BEFORE UPDATE ON iam.session_families
FOR EACH ROW EXECUTE FUNCTION iam.enforce_session_family_transition();

CREATE FUNCTION iam.enforce_session_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.family_id IS DISTINCT FROM OLD.family_id
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.predecessor_session_id IS DISTINCT FROM OLD.predecessor_session_id
       OR NEW.handle_digest IS DISTINCT FROM OLD.handle_digest
       OR NEW.handle_digest_key_id IS DISTINCT FROM OLD.handle_digest_key_id
       OR NEW.csrf_salt IS DISTINCT FROM OLD.csrf_salt
       OR NEW.csrf_key_id IS DISTINCT FROM OLD.csrf_key_id
       OR NEW.csrf_digest IS DISTINCT FROM OLD.csrf_digest
       OR NEW.verified_contact_point_id IS DISTINCT FROM OLD.verified_contact_point_id
       OR NEW.verified_at IS DISTINCT FROM OLD.verified_at
       OR NEW.verified_for_invitation_id IS DISTINCT FROM OLD.verified_for_invitation_id
       OR NEW.auth_transaction_id IS DISTINCT FROM OLD.auth_transaction_id
       OR NEW.auth_time IS DISTINCT FROM OLD.auth_time
       OR NEW.acr_code IS DISTINCT FROM OLD.acr_code
       OR NEW.amr_codes IS DISTINCT FROM OLD.amr_codes
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at
       OR NEW.device_label IS DISTINCT FROM OLD.device_label
       OR NEW.rotation_reason IS DISTINCT FROM OLD.rotation_reason
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
       OR (OLD.status IN ('REVOKED', 'EXPIRED') AND NEW.status <> OLD.status) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_session_state',
            MESSAGE = 'invalid session mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_session_state
BEFORE UPDATE ON iam.sessions
FOR EACH ROW EXECUTE FUNCTION iam.enforce_session_transition();

CREATE TABLE iam.policy_acceptances (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    document_id uuid NOT NULL,
    content_sha256 bytea NOT NULL,
    bundle_id uuid NOT NULL,
    accepted_at timestamptz NOT NULL,
    session_id uuid NOT NULL,
    auth_transaction_id uuid NOT NULL,
    auth_time timestamptz NOT NULL,
    acr_code varchar(128) NOT NULL,
    amr_codes text[] NOT NULL,
    source_action text NOT NULL,
    command_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_policy_acceptances PRIMARY KEY (id),
    CONSTRAINT fk_policy_acceptance_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_acceptance_document_hash FOREIGN KEY (
        document_id,
        content_sha256
    ) REFERENCES iam.policy_documents (id, content_sha256) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_acceptance_bundle_document FOREIGN KEY (
        bundle_id,
        document_id
    ) REFERENCES iam.policy_bundle_documents (bundle_id, document_id) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_acceptance_session FOREIGN KEY (session_id)
        REFERENCES iam.sessions (id) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_acceptance_auth_transaction FOREIGN KEY (auth_transaction_id)
        REFERENCES iam.auth_transactions (id) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_acceptance_session_auth FOREIGN KEY (
        session_id,
        auth_transaction_id
    ) REFERENCES iam.sessions (id, auth_transaction_id) ON DELETE RESTRICT,
    CONSTRAINT uq_policy_acceptance_user_document_hash UNIQUE (
        user_id,
        document_id,
        content_sha256
    ),
    CONSTRAINT ck_policy_acceptance_hash CHECK (octet_length(content_sha256) = 32),
    CONSTRAINT ck_policy_acceptance_auth CHECK (
        length(acr_code) > 0
        AND cardinality(amr_codes) BETWEEN 1 AND 16
        AND iam.text_array_is_unique_nonnull(amr_codes)
    ),
    CONSTRAINT ck_policy_acceptance_source CHECK (
        source_action IN ('ACCESS_INVITATION_ACCEPT', 'POLICY_ACCEPT')
    ),
    CONSTRAINT ck_policy_acceptance_version CHECK (aggregate_version = 1),
    CONSTRAINT ck_policy_acceptance_time CHECK (
        auth_time <= accepted_at AND accepted_at = created_at
    )
);

CREATE TABLE iam.consent_grants (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    consent_offer_id uuid NOT NULL,
    consent_offer_version bigint NOT NULL,
    policy_bundle_id uuid NOT NULL,
    purpose text NOT NULL,
    scope_type text NOT NULL,
    scope_id uuid NULL,
    recipient_ref varchar(128) NOT NULL,
    recipient_label varchar(160) NOT NULL,
    document_id uuid NOT NULL,
    document_content_sha256 bytea NOT NULL,
    granted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    session_id uuid NOT NULL,
    auth_transaction_id uuid NOT NULL,
    auth_time timestamptz NOT NULL,
    acr_code varchar(128) NOT NULL,
    amr_codes text[] NOT NULL,
    command_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    status text NOT NULL,
    withdrawn_at timestamptz NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_consent_grants PRIMARY KEY (id),
    CONSTRAINT uq_consent_grant_id_user UNIQUE (id, user_id),
    CONSTRAINT fk_consent_grant_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_grant_offer_version FOREIGN KEY (
        consent_offer_id,
        consent_offer_version
    ) REFERENCES iam.consent_offers (id, offer_version) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_grant_bundle_offer FOREIGN KEY (
        policy_bundle_id,
        consent_offer_id
    ) REFERENCES iam.consent_offers (bundle_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_grant_document_hash FOREIGN KEY (
        document_id,
        document_content_sha256
    ) REFERENCES iam.policy_documents (id, content_sha256) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_grant_session FOREIGN KEY (session_id)
        REFERENCES iam.sessions (id) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_grant_auth_transaction FOREIGN KEY (auth_transaction_id)
        REFERENCES iam.auth_transactions (id) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_grant_session_auth FOREIGN KEY (
        session_id,
        auth_transaction_id
    ) REFERENCES iam.sessions (id, auth_transaction_id) ON DELETE RESTRICT,
    CONSTRAINT ck_consent_grant_version CHECK (
        consent_offer_version >= 1 AND aggregate_version >= 1
    ),
    CONSTRAINT ck_consent_grant_purpose CHECK (
        purpose IN (
            'PILOT_RESEARCH',
            'AI_ASSISTED_PROCESSING',
            'DISCLOSE_PROFILE_FIELDS_TO_PARTY'
        )
    ),
    CONSTRAINT ck_consent_grant_scope CHECK (
        (
            scope_type = 'PLATFORM_PARTICIPATION'
            AND scope_id IS NULL
        )
        OR
        (
            scope_type IN ('ORGANIZATION', 'PROJECT', 'RECIPIENT_DISCLOSURE')
            AND scope_id IS NOT NULL
        )
    ),
    CONSTRAINT ck_consent_grant_document_hash CHECK (
        octet_length(document_content_sha256) = 32
    ),
    CONSTRAINT ck_consent_grant_auth CHECK (
        length(acr_code) > 0
        AND cardinality(amr_codes) BETWEEN 1 AND 16
        AND iam.text_array_is_unique_nonnull(amr_codes)
    ),
    CONSTRAINT ck_consent_grant_status CHECK (
        status IN ('ACTIVE', 'WITHDRAWN', 'EXPIRED')
    ),
    CONSTRAINT ck_consent_grant_lifecycle CHECK (
        (status IN ('ACTIVE', 'EXPIRED') AND withdrawn_at IS NULL)
        OR (status = 'WITHDRAWN' AND withdrawn_at IS NOT NULL)
    ),
    CONSTRAINT ck_consent_grant_time CHECK (
        auth_time <= granted_at
        AND expires_at > granted_at
        AND created_at = granted_at
        AND updated_at >= created_at
        AND (withdrawn_at IS NULL OR withdrawn_at >= granted_at)
    )
);

CREATE UNIQUE INDEX ux_consent_grant_active_authority
    ON iam.consent_grants (user_id, purpose, scope_type, scope_id) NULLS NOT DISTINCT
    WHERE status = 'ACTIVE';

CREATE TABLE iam.consent_grant_data_categories (
    grant_id uuid NOT NULL,
    category text NOT NULL,
    position smallint NOT NULL,
    CONSTRAINT pk_consent_grant_data_categories PRIMARY KEY (grant_id, category),
    CONSTRAINT uq_consent_grant_category_position UNIQUE (grant_id, position),
    CONSTRAINT fk_consent_grant_category_grant FOREIGN KEY (grant_id)
        REFERENCES iam.consent_grants (id) ON DELETE RESTRICT,
    CONSTRAINT ck_consent_grant_category CHECK (
        category IN ('PROFILE', 'MATCHING', 'RESEARCH', 'AI_INPUT', 'CONTACT', 'PROJECT')
    ),
    CONSTRAINT ck_consent_grant_category_position CHECK (position BETWEEN 1 AND 20)
);

CREATE TABLE iam.consent_withdrawals (
    id uuid NOT NULL,
    consent_grant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    withdrawn_at timestamptz NOT NULL,
    reason_code varchar(64) NOT NULL,
    command_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_consent_withdrawals PRIMARY KEY (id),
    CONSTRAINT uq_consent_withdrawal_grant UNIQUE (consent_grant_id),
    CONSTRAINT fk_consent_withdrawal_grant_user FOREIGN KEY (
        consent_grant_id,
        user_id
    ) REFERENCES iam.consent_grants (id, user_id) ON DELETE RESTRICT,
    CONSTRAINT ck_consent_withdrawal_reason CHECK (
        reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
    ),
    CONSTRAINT ck_consent_withdrawal_time CHECK (created_at = withdrawn_at)
);

CREATE FUNCTION iam.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = TG_ARGV[0],
        MESSAGE = 'append-only IAM evidence cannot be mutated';
END
$function$;

CREATE TRIGGER trg_policy_acceptance_append_only
BEFORE UPDATE OR DELETE ON iam.policy_acceptances
FOR EACH ROW EXECUTE FUNCTION iam.reject_append_only_mutation(
    'trg_policy_acceptance_append_only'
);

CREATE TRIGGER trg_consent_withdrawal_append_only
BEFORE UPDATE OR DELETE ON iam.consent_withdrawals
FOR EACH ROW EXECUTE FUNCTION iam.reject_append_only_mutation(
    'trg_consent_withdrawal_append_only'
);

CREATE TRIGGER trg_consent_grant_category_immutable
BEFORE UPDATE OR DELETE ON iam.consent_grant_data_categories
FOR EACH ROW EXECUTE FUNCTION iam.reject_append_only_mutation(
    'trg_consent_grant_category_immutable'
);

CREATE FUNCTION iam.enforce_consent_grant_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.consent_offer_id IS DISTINCT FROM OLD.consent_offer_id
       OR NEW.consent_offer_version IS DISTINCT FROM OLD.consent_offer_version
       OR NEW.policy_bundle_id IS DISTINCT FROM OLD.policy_bundle_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
       OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
       OR NEW.recipient_ref IS DISTINCT FROM OLD.recipient_ref
       OR NEW.recipient_label IS DISTINCT FROM OLD.recipient_label
       OR NEW.document_id IS DISTINCT FROM OLD.document_id
       OR NEW.document_content_sha256 IS DISTINCT FROM OLD.document_content_sha256
       OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.session_id IS DISTINCT FROM OLD.session_id
       OR NEW.auth_transaction_id IS DISTINCT FROM OLD.auth_transaction_id
       OR NEW.auth_time IS DISTINCT FROM OLD.auth_time
       OR NEW.acr_code IS DISTINCT FROM OLD.acr_code
       OR NEW.amr_codes IS DISTINCT FROM OLD.amr_codes
       OR NEW.command_id IS DISTINCT FROM OLD.command_id
       OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.status <> 'ACTIVE'
       OR NEW.status NOT IN ('WITHDRAWN', 'EXPIRED')
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_grant_state',
            MESSAGE = 'invalid consent grant mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_consent_grant_state
BEFORE UPDATE ON iam.consent_grants
FOR EACH ROW EXECUTE FUNCTION iam.enforce_consent_grant_transition();

CREATE FUNCTION iam.enforce_evidence_matches_session_auth()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM iam.sessions AS session
        WHERE session.id = NEW.session_id
          AND session.user_id = NEW.user_id
          AND session.auth_transaction_id = NEW.auth_transaction_id
          AND session.auth_time = NEW.auth_time
          AND session.acr_code = NEW.acr_code
          AND iam.canonical_text_array(session.amr_codes)
              = iam.canonical_text_array(NEW.amr_codes)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_evidence_matches_session_auth',
            MESSAGE = 'authentication evidence does not match session';
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER trg_evidence_matches_session_auth
AFTER INSERT OR UPDATE ON iam.policy_acceptances
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_evidence_matches_session_auth();

CREATE CONSTRAINT TRIGGER trg_evidence_matches_session_auth
AFTER INSERT OR UPDATE ON iam.consent_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_evidence_matches_session_auth();

CREATE FUNCTION iam.assert_consent_grant_matches_offer(checked_grant_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    grant_row iam.consent_grants%ROWTYPE;
    offer_row iam.consent_offers%ROWTYPE;
    expected_expiry timestamptz;
BEGIN
    SELECT * INTO grant_row FROM iam.consent_grants WHERE id = checked_grant_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT * INTO offer_row FROM iam.consent_offers WHERE id = grant_row.consent_offer_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_grant_matches_offer',
            MESSAGE = 'consent offer is unavailable';
    END IF;

    expected_expiry := CASE offer_row.expiry_rule
        WHEN 'FIXED_NOT_AFTER' THEN offer_row.not_after
        ELSE least(
            grant_row.granted_at + (offer_row.expiry_days * interval '1 day'),
            offer_row.not_after
        )
    END;

    IF grant_row.consent_offer_version <> offer_row.offer_version
       OR grant_row.policy_bundle_id <> offer_row.bundle_id
       OR grant_row.purpose <> offer_row.purpose
       OR grant_row.scope_type <> offer_row.scope_type
       OR grant_row.scope_id IS NOT NULL
       OR grant_row.recipient_ref <> offer_row.recipient_ref
       OR grant_row.recipient_label <> offer_row.recipient_label
       OR grant_row.document_id <> offer_row.document_id
       OR grant_row.document_content_sha256 <> offer_row.document_content_sha256
       OR grant_row.expires_at <> expected_expiry
       OR EXISTS (
            SELECT category, position
            FROM iam.consent_offer_data_categories
            WHERE offer_id = offer_row.id
            EXCEPT
            SELECT category, position
            FROM iam.consent_grant_data_categories
            WHERE grant_id = grant_row.id
       )
       OR EXISTS (
            SELECT category, position
            FROM iam.consent_grant_data_categories
            WHERE grant_id = grant_row.id
            EXCEPT
            SELECT category, position
            FROM iam.consent_offer_data_categories
            WHERE offer_id = offer_row.id
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_grant_matches_offer',
            MESSAGE = 'consent grant does not match immutable offer';
    END IF;
END
$function$;

CREATE FUNCTION iam.enforce_consent_grant_matches_offer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    checked_grant_id uuid;
BEGIN
    checked_grant_id := CASE
        WHEN TG_TABLE_NAME = 'consent_grants' THEN NEW.id
        ELSE NEW.grant_id
    END;
    PERFORM iam.assert_consent_grant_matches_offer(checked_grant_id);
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER trg_consent_grant_matches_offer
AFTER INSERT OR UPDATE ON iam.consent_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_consent_grant_matches_offer();

CREATE CONSTRAINT TRIGGER trg_consent_grant_matches_offer
AFTER INSERT ON iam.consent_grant_data_categories
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_consent_grant_matches_offer();

CREATE FUNCTION iam.enforce_session_family_consistent()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    checked_family_id uuid;
    family_status text;
    family_user_id uuid;
    family_current_generation bigint;
BEGIN
    IF TG_TABLE_NAME = 'session_families' THEN
        checked_family_id := NEW.id;
    ELSE
        checked_family_id := NEW.family_id;
    END IF;

    SELECT status, user_id, current_generation
    INTO family_status, family_user_id, family_current_generation
    FROM iam.session_families
    WHERE id = checked_family_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF family_status = 'ACTIVE' THEN
        IF (
            SELECT count(*)
            FROM iam.sessions
            WHERE family_id = checked_family_id AND status = 'ACTIVE'
        ) <> 1 OR NOT EXISTS (
            SELECT 1
            FROM iam.sessions
            WHERE family_id = checked_family_id
              AND status = 'ACTIVE'
              AND generation = family_current_generation
              AND user_id = family_user_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_session_family_consistent',
                MESSAGE = 'active session family has no exact current session';
        END IF;
    ELSIF EXISTS (
        SELECT 1 FROM iam.sessions
        WHERE family_id = checked_family_id AND status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_session_family_consistent',
            MESSAGE = 'revoked session family has an active session';
    END IF;

    IF TG_TABLE_NAME = 'sessions' THEN
        IF (
            (NEW.generation = 1 AND NEW.predecessor_session_id IS NOT NULL)
            OR (NEW.generation > 1 AND NOT EXISTS (
                SELECT 1
                FROM iam.sessions AS predecessor
                WHERE predecessor.id = NEW.predecessor_session_id
                  AND predecessor.family_id = NEW.family_id
                  AND predecessor.generation = NEW.generation - 1
            ))
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_session_family_consistent',
                MESSAGE = 'session predecessor generation is inconsistent';
        END IF;
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER trg_session_family_consistent
AFTER INSERT OR UPDATE ON iam.session_families
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_session_family_consistent();

CREATE CONSTRAINT TRIGGER trg_session_family_consistent
AFTER INSERT OR UPDATE ON iam.sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_session_family_consistent();

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM PUBLIC;
