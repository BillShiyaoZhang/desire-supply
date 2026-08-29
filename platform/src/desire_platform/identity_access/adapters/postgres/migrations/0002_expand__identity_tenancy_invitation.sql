CREATE TABLE iam.users (
    id uuid NOT NULL,
    status text NOT NULL,
    display_handle varchar(80) NOT NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_id_version UNIQUE (id, aggregate_version),
    CONSTRAINT ck_user_status CHECK (
        status IN ('PENDING_ENROLLMENT', 'ACTIVE', 'SUSPENDED', 'CLOSED')
    ),
    CONSTRAINT ck_user_display_handle CHECK (
        display_handle ~ '^[A-Za-z0-9][A-Za-z0-9_-]{1,79}$'
    ),
    CONSTRAINT ck_user_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_user_time CHECK (updated_at >= created_at)
);

CREATE TABLE iam.external_identities (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    issuer varchar(2048) NOT NULL,
    subject_digest bytea NOT NULL,
    subject_digest_key_id varchar(64) NOT NULL,
    verified_at timestamptz NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_external_identities PRIMARY KEY (id),
    CONSTRAINT fk_external_identity_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT uq_external_identity_issuer_subject UNIQUE (issuer, subject_digest),
    CONSTRAINT ck_external_identity_digest CHECK (
        octet_length(subject_digest) = 32
    ),
    CONSTRAINT ck_external_identity_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT ck_external_identity_time CHECK (verified_at >= created_at)
);

CREATE UNIQUE INDEX ux_external_identity_active_user
    ON iam.external_identities (user_id)
    WHERE status = 'ACTIVE';

CREATE TABLE iam.contact_points (
    id uuid NOT NULL,
    user_id uuid NULL,
    contact_type text NOT NULL,
    locator_ciphertext bytea NULL,
    locator_encryption_key_id varchar(64) NULL,
    locator_encryption_algorithm text NULL,
    binding_digest bytea NOT NULL,
    binding_digest_key_id varchar(64) NOT NULL,
    verified_at timestamptz NULL,
    retention_until timestamptz NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_contact_points PRIMARY KEY (id),
    CONSTRAINT fk_contact_point_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT ck_contact_point_type CHECK (contact_type IN ('EMAIL', 'PHONE')),
    CONSTRAINT ck_contact_point_locator_shape CHECK (
        (
            locator_ciphertext IS NULL
            AND locator_encryption_key_id IS NULL
            AND locator_encryption_algorithm IS NULL
        )
        OR
        (
            locator_ciphertext IS NOT NULL
            AND octet_length(locator_ciphertext) > 0
            AND locator_encryption_key_id IS NOT NULL
            AND locator_encryption_algorithm = 'AES_256_GCM_V1'
        )
    ),
    CONSTRAINT ck_contact_point_binding_digest CHECK (
        octet_length(binding_digest) = 32
    ),
    CONSTRAINT ck_contact_point_time CHECK (
        updated_at >= created_at
        AND (verified_at IS NULL OR verified_at >= created_at)
        AND (retention_until IS NULL OR retention_until >= created_at)
    )
);

CREATE INDEX ix_contact_binding_lookup
    ON iam.contact_points (
        contact_type,
        binding_digest_key_id,
        binding_digest
    );

CREATE TABLE iam.organizations (
    id uuid NOT NULL,
    organization_type text NOT NULL,
    public_name varchar(160) NOT NULL,
    jurisdiction varchar(32) NOT NULL,
    status text NOT NULL,
    client_reference_namespace varchar(64) NOT NULL,
    client_reference varchar(128) NOT NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_organizations PRIMARY KEY (id),
    CONSTRAINT uq_organization_client_ref UNIQUE (
        client_reference_namespace,
        client_reference
    ),
    CONSTRAINT uq_organizations_id_version UNIQUE (id, aggregate_version),
    CONSTRAINT ck_organization_type CHECK (
        organization_type IN ('BUSINESS', 'NONPROFIT', 'COMMUNITY', 'CREATOR_TEAM')
    ),
    CONSTRAINT ck_organization_public_name CHECK (length(public_name) > 0),
    CONSTRAINT ck_organization_jurisdiction CHECK (
        jurisdiction ~ '^[A-Z0-9_-]{2,32}$'
    ),
    CONSTRAINT ck_organization_status CHECK (
        status IN ('PENDING_ADMIN', 'ACTIVE', 'SUSPENDED', 'CLOSED')
    ),
    CONSTRAINT ck_organization_client_ref CHECK (
        length(client_reference_namespace) > 0
        AND length(client_reference) > 0
    ),
    CONSTRAINT ck_organization_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_organization_time CHECK (updated_at >= created_at)
);

CREATE TABLE iam.access_invitations (
    id uuid NOT NULL,
    purpose text NOT NULL,
    organization_id uuid NULL,
    target_scope text NOT NULL,
    target_role text NOT NULL,
    is_initial_admin boolean NOT NULL DEFAULT false,
    recipient_contact_id uuid NOT NULL,
    masked_recipient_label varchar(80) NOT NULL,
    policy_selector_digest bytea NOT NULL,
    issued_policy_bundle_id uuid NOT NULL,
    status text NOT NULL,
    expires_at timestamptz NOT NULL,
    issuer_kind text NOT NULL,
    issuer_user_id uuid NULL,
    token_nonce bytea NOT NULL,
    token_key_id varchar(64) NOT NULL,
    accepted_by_user_id uuid NULL,
    terminal_at timestamptz NULL,
    terminal_reason_code varchar(64) NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_access_invitations PRIMARY KEY (id),
    CONSTRAINT fk_invitation_organization FOREIGN KEY (organization_id)
        REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT fk_invitation_contact FOREIGN KEY (recipient_contact_id)
        REFERENCES iam.contact_points (id) ON DELETE RESTRICT,
    CONSTRAINT fk_invitation_selector FOREIGN KEY (policy_selector_digest)
        REFERENCES iam.policy_selectors (selector_digest) ON DELETE RESTRICT,
    CONSTRAINT fk_invitation_issued_bundle_selector FOREIGN KEY (
        issued_policy_bundle_id,
        policy_selector_digest
    ) REFERENCES iam.policy_bundles (id, selector_digest) ON DELETE RESTRICT,
    CONSTRAINT fk_invitation_issuer_user FOREIGN KEY (issuer_user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_invitation_accepted_user FOREIGN KEY (accepted_by_user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT uq_invitation_id_nonce UNIQUE (id, token_nonce),
    CONSTRAINT uq_invitation_id_contact UNIQUE (id, recipient_contact_id),
    CONSTRAINT uq_invitation_id_selector UNIQUE (id, policy_selector_digest),
    CONSTRAINT uq_invitation_id_target_role UNIQUE (id, target_role),
    CONSTRAINT uq_invitation_id_org UNIQUE (id, organization_id),
    CONSTRAINT uq_invitation_id_org_role UNIQUE (id, organization_id, target_role),
    CONSTRAINT uq_invitation_id_selector_role UNIQUE (
        id,
        policy_selector_digest,
        target_role
    ),
    CONSTRAINT uq_invitation_id_selector_org_role UNIQUE (
        id,
        policy_selector_digest,
        organization_id,
        target_role
    ),
    CONSTRAINT ck_invitation_target_shape CHECK (
        (
            purpose = 'CREATOR_ENROLLMENT'
            AND organization_id IS NULL
            AND target_scope = 'USER'
            AND target_role = 'CREATOR'
            AND NOT is_initial_admin
        )
        OR
        (
            purpose = 'ORGANIZATION_MEMBERSHIP'
            AND organization_id IS NOT NULL
            AND target_scope = 'ORGANIZATION'
            AND target_role IN ('ORG_ADMIN', 'DEMAND_OWNER')
        )
    ),
    CONSTRAINT ck_invitation_initial_admin CHECK (
        NOT is_initial_admin
        OR (
            purpose = 'ORGANIZATION_MEMBERSHIP'
            AND target_role = 'ORG_ADMIN'
            AND issuer_kind = 'SYSTEM'
        )
    ),
    CONSTRAINT ck_invitation_issuer_shape CHECK (
        (issuer_kind = 'SYSTEM' AND issuer_user_id IS NULL)
        OR (issuer_kind = 'USER' AND issuer_user_id IS NOT NULL)
    ),
    CONSTRAINT ck_invitation_terminal_shape CHECK (
        (
            status = 'ISSUED'
            AND accepted_by_user_id IS NULL
            AND terminal_at IS NULL
            AND terminal_reason_code IS NULL
        )
        OR
        (
            status = 'ACCEPTED'
            AND accepted_by_user_id IS NOT NULL
            AND terminal_at IS NOT NULL
            AND terminal_reason_code IS NULL
        )
        OR
        (
            status IN ('REVOKED', 'EXPIRED')
            AND accepted_by_user_id IS NULL
            AND terminal_at IS NOT NULL
        )
    ),
    CONSTRAINT ck_invitation_mask CHECK (length(masked_recipient_label) > 0),
    CONSTRAINT ck_invitation_selector_digest CHECK (
        octet_length(policy_selector_digest) = 32
    ),
    CONSTRAINT ck_invitation_token_nonce CHECK (octet_length(token_nonce) = 32),
    CONSTRAINT ck_invitation_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_invitation_time CHECK (
        expires_at > created_at
        AND updated_at >= created_at
        AND (terminal_at IS NULL OR terminal_at >= created_at)
    )
);

CREATE UNIQUE INDEX ux_invitation_open_initial_admin
    ON iam.access_invitations (organization_id)
    WHERE is_initial_admin AND status = 'ISSUED';

CREATE INDEX ix_invitation_expiry
    ON iam.access_invitations (status, expires_at);

CREATE TABLE iam.memberships (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    source_invitation_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_memberships PRIMARY KEY (id),
    CONSTRAINT fk_membership_organization FOREIGN KEY (organization_id)
        REFERENCES iam.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT fk_membership_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_membership_source_invitation FOREIGN KEY (
        source_invitation_id,
        organization_id
    ) REFERENCES iam.access_invitations (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT uq_membership_org_user UNIQUE (organization_id, user_id),
    CONSTRAINT uq_membership_org_id UNIQUE (organization_id, id),
    CONSTRAINT uq_membership_org_id_user UNIQUE (organization_id, id, user_id),
    CONSTRAINT uq_membership_source_invitation UNIQUE (source_invitation_id),
    CONSTRAINT ck_membership_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    CONSTRAINT ck_membership_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_membership_time CHECK (updated_at >= created_at)
);

CREATE TABLE iam.user_role_grants (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_code text NOT NULL,
    source_invitation_id uuid NOT NULL,
    policy_selector_digest bytea NOT NULL,
    granted_by_kind text NOT NULL,
    granted_by_id uuid NOT NULL,
    granted_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    revocation_reason_code varchar(64) NULL,
    aggregate_version bigint NOT NULL,
    CONSTRAINT pk_user_role_grants PRIMARY KEY (id),
    CONSTRAINT fk_user_role_grant_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_user_role_grant_selector FOREIGN KEY (policy_selector_digest)
        REFERENCES iam.policy_selectors (selector_digest) ON DELETE RESTRICT,
    CONSTRAINT fk_user_role_grant_source FOREIGN KEY (
        source_invitation_id,
        policy_selector_digest,
        role_code
    ) REFERENCES iam.access_invitations (
        id,
        policy_selector_digest,
        target_role
    ) ON DELETE RESTRICT,
    CONSTRAINT uq_user_role_source_invitation UNIQUE (source_invitation_id),
    CONSTRAINT ck_user_role_code CHECK (role_code = 'CREATOR'),
    CONSTRAINT ck_user_role_selector_digest CHECK (
        octet_length(policy_selector_digest) = 32
    ),
    CONSTRAINT ck_user_role_grantor CHECK (granted_by_kind IN ('USER', 'SYSTEM')),
    CONSTRAINT ck_user_role_revocation CHECK (
        (revoked_at IS NULL AND revocation_reason_code IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_user_role_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_user_role_time CHECK (
        revoked_at IS NULL OR revoked_at >= granted_at
    )
);

CREATE UNIQUE INDEX ux_user_role_active
    ON iam.user_role_grants (user_id, role_code)
    WHERE revoked_at IS NULL;

CREATE TABLE iam.membership_role_grants (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_code text NOT NULL,
    source_invitation_id uuid NOT NULL,
    policy_selector_digest bytea NOT NULL,
    granted_by_kind text NOT NULL,
    granted_by_id uuid NOT NULL,
    granted_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    revocation_reason_code varchar(64) NULL,
    aggregate_version bigint NOT NULL,
    CONSTRAINT pk_membership_role_grants PRIMARY KEY (id),
    CONSTRAINT uq_membership_role_org_id UNIQUE (organization_id, id),
    CONSTRAINT fk_membership_role_membership FOREIGN KEY (
        organization_id,
        membership_id,
        user_id
    ) REFERENCES iam.memberships (organization_id, id, user_id) ON DELETE RESTRICT,
    CONSTRAINT fk_membership_role_selector FOREIGN KEY (policy_selector_digest)
        REFERENCES iam.policy_selectors (selector_digest) ON DELETE RESTRICT,
    CONSTRAINT fk_membership_role_source FOREIGN KEY (
        source_invitation_id,
        policy_selector_digest,
        organization_id,
        role_code
    ) REFERENCES iam.access_invitations (
        id,
        policy_selector_digest,
        organization_id,
        target_role
    ) ON DELETE RESTRICT,
    CONSTRAINT uq_membership_role_source_invitation UNIQUE (source_invitation_id),
    CONSTRAINT ck_membership_role_code CHECK (
        role_code IN ('ORG_ADMIN', 'DEMAND_OWNER')
    ),
    CONSTRAINT ck_membership_role_selector_digest CHECK (
        octet_length(policy_selector_digest) = 32
    ),
    CONSTRAINT ck_membership_role_grantor CHECK (
        granted_by_kind IN ('USER', 'SYSTEM')
    ),
    CONSTRAINT ck_membership_role_revocation CHECK (
        (revoked_at IS NULL AND revocation_reason_code IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_membership_role_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_membership_role_time CHECK (
        revoked_at IS NULL OR revoked_at >= granted_at
    )
);

CREATE UNIQUE INDEX ux_membership_role_active
    ON iam.membership_role_grants (membership_id, role_code)
    WHERE revoked_at IS NULL;

CREATE FUNCTION iam.enforce_contact_binding_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.contact_type IS DISTINCT FROM OLD.contact_type
       OR NEW.binding_digest IS DISTINCT FROM OLD.binding_digest
       OR NEW.binding_digest_key_id IS DISTINCT FROM OLD.binding_digest_key_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_contact_binding_immutable',
            MESSAGE = 'contact binding is immutable';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_contact_binding_immutable
BEFORE UPDATE ON iam.contact_points
FOR EACH ROW EXECUTE FUNCTION iam.enforce_contact_binding_immutable();

CREATE FUNCTION iam.enforce_invitation_binding_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.target_scope IS DISTINCT FROM OLD.target_scope
       OR NEW.target_role IS DISTINCT FROM OLD.target_role
       OR NEW.is_initial_admin IS DISTINCT FROM OLD.is_initial_admin
       OR NEW.recipient_contact_id IS DISTINCT FROM OLD.recipient_contact_id
       OR NEW.masked_recipient_label IS DISTINCT FROM OLD.masked_recipient_label
       OR NEW.policy_selector_digest IS DISTINCT FROM OLD.policy_selector_digest
       OR NEW.issued_policy_bundle_id IS DISTINCT FROM OLD.issued_policy_bundle_id
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.issuer_kind IS DISTINCT FROM OLD.issuer_kind
       OR NEW.issuer_user_id IS DISTINCT FROM OLD.issuer_user_id
       OR NEW.token_nonce IS DISTINCT FROM OLD.token_nonce
       OR NEW.token_key_id IS DISTINCT FROM OLD.token_key_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.status <> 'ISSUED'
       OR NEW.status NOT IN ('ACCEPTED', 'REVOKED', 'EXPIRED')
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_invitation_binding_immutable',
            MESSAGE = 'invalid invitation mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_invitation_binding_immutable
BEFORE UPDATE ON iam.access_invitations
FOR EACH ROW EXECUTE FUNCTION iam.enforce_invitation_binding_immutable();

CREATE FUNCTION iam.enforce_user_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'PENDING_ENROLLMENT' AND NEW.status NOT IN ('ACTIVE', 'CLOSED'))
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
       OR (OLD.status = 'SUSPENDED' AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
       OR (OLD.status = 'CLOSED' AND NEW.status <> 'CLOSED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_user_state_transition',
            MESSAGE = 'invalid user state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_user_state_transition
BEFORE UPDATE ON iam.users
FOR EACH ROW EXECUTE FUNCTION iam.enforce_user_transition();

CREATE FUNCTION iam.enforce_organization_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'PENDING_ADMIN' AND NEW.status NOT IN ('ACTIVE', 'CLOSED'))
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
       OR (OLD.status = 'SUSPENDED' AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
       OR (OLD.status = 'CLOSED' AND NEW.status <> 'CLOSED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_organization_state_transition',
            MESSAGE = 'invalid organization state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_organization_state_transition
BEFORE UPDATE ON iam.organizations
FOR EACH ROW EXECUTE FUNCTION iam.enforce_organization_transition();

CREATE FUNCTION iam.enforce_membership_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.source_invitation_id IS DISTINCT FROM OLD.source_invitation_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
       OR (OLD.status = 'SUSPENDED' AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
       OR (OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_membership_state_transition',
            MESSAGE = 'invalid membership mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_membership_state_transition
BEFORE UPDATE ON iam.memberships
FOR EACH ROW EXECUTE FUNCTION iam.enforce_membership_transition();

CREATE FUNCTION iam.enforce_role_grant_binding_immutable()
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

CREATE TRIGGER trg_role_grant_binding_immutable
BEFORE UPDATE ON iam.user_role_grants
FOR EACH ROW EXECUTE FUNCTION iam.enforce_role_grant_binding_immutable();

CREATE TRIGGER trg_role_grant_binding_immutable
BEFORE UPDATE ON iam.membership_role_grants
FOR EACH ROW EXECUTE FUNCTION iam.enforce_role_grant_binding_immutable();

CREATE FUNCTION iam.enforce_activation_matches_invitation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF TG_TABLE_NAME = 'memberships' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM iam.access_invitations AS invitation
            WHERE invitation.id = NEW.source_invitation_id
              AND invitation.status = 'ACCEPTED'
              AND invitation.accepted_by_user_id = NEW.user_id
              AND invitation.organization_id = NEW.organization_id
              AND invitation.purpose = 'ORGANIZATION_MEMBERSHIP'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_activation_matches_accepted_invitation',
                MESSAGE = 'membership activation source is inconsistent';
        END IF;
    ELSIF TG_TABLE_NAME = 'user_role_grants' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM iam.access_invitations AS invitation
            WHERE invitation.id = NEW.source_invitation_id
              AND invitation.status = 'ACCEPTED'
              AND invitation.accepted_by_user_id = NEW.user_id
              AND invitation.organization_id IS NULL
              AND invitation.policy_selector_digest = NEW.policy_selector_digest
              AND invitation.target_role = NEW.role_code
              AND invitation.purpose = 'CREATOR_ENROLLMENT'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_activation_matches_accepted_invitation',
                MESSAGE = 'user role activation source is inconsistent';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1
            FROM iam.access_invitations AS invitation
            WHERE invitation.id = NEW.source_invitation_id
              AND invitation.status = 'ACCEPTED'
              AND invitation.accepted_by_user_id = NEW.user_id
              AND invitation.organization_id = NEW.organization_id
              AND invitation.policy_selector_digest = NEW.policy_selector_digest
              AND invitation.target_role = NEW.role_code
              AND invitation.purpose = 'ORGANIZATION_MEMBERSHIP'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_activation_matches_accepted_invitation',
                MESSAGE = 'membership role activation source is inconsistent';
        END IF;
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER trg_activation_matches_accepted_invitation
AFTER INSERT OR UPDATE ON iam.memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_activation_matches_invitation();

CREATE CONSTRAINT TRIGGER trg_activation_matches_accepted_invitation
AFTER INSERT OR UPDATE ON iam.user_role_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_activation_matches_invitation();

CREATE CONSTRAINT TRIGGER trg_activation_matches_accepted_invitation
AFTER INSERT OR UPDATE ON iam.membership_role_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_activation_matches_invitation();

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM PUBLIC;
