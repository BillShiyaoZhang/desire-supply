-- Creator Profile independent PostgreSQL schema v1.

CREATE SCHEMA profile AUTHORIZATION profile_schema_owner;
CREATE SCHEMA profile_api AUTHORIZATION profile_schema_owner;
REVOKE ALL ON SCHEMA profile, profile_api FROM PUBLIC;

CREATE TABLE profile.schema_migrations (
    component text NOT NULL,
    version integer NOT NULL,
    phase text NOT NULL,
    name text NOT NULL,
    checksum_sha256 bytea NOT NULL,
    manifest_sha256 bytea NOT NULL,
    runner_version varchar(96) NOT NULL,
    applied_at timestamptz NOT NULL,
    CONSTRAINT pk_profile_schema_migrations PRIMARY KEY (component, version),
    CONSTRAINT ck_profile_schema_migration_component CHECK (component = 'profile'),
    CONSTRAINT ck_profile_schema_migration_version CHECK (version >= 1),
    CONSTRAINT ck_profile_schema_migration_phase CHECK (
        phase IN ('expand', 'migrate', 'contract')
    ),
    CONSTRAINT ck_profile_schema_migration_hashes CHECK (
        octet_length(checksum_sha256) = 32
        AND octet_length(manifest_sha256) = 32
    )
);

CREATE TABLE profile.schema_contracts (
    singleton_key boolean NOT NULL,
    schema_head_version integer NOT NULL,
    min_app_compatible_version integer NOT NULL,
    max_app_compatible_version integer NOT NULL,
    api_contract_sha256 bytea NOT NULL,
    event_contract_sha256 bytea NOT NULL,
    domain_contract_sha256 bytea NOT NULL,
    migration_manifest_sha256 bytea NOT NULL,
    generated_at timestamptz NOT NULL,
    CONSTRAINT pk_profile_schema_contracts PRIMARY KEY (singleton_key),
    CONSTRAINT ck_profile_schema_contract_singleton CHECK (singleton_key),
    CONSTRAINT ck_profile_schema_contract_version CHECK (
        schema_head_version = 1
        AND min_app_compatible_version = 1
        AND max_app_compatible_version = 1
    ),
    CONSTRAINT ck_profile_schema_contract_hashes CHECK (
        octet_length(api_contract_sha256) = 32
        AND octet_length(event_contract_sha256) = 32
        AND octet_length(domain_contract_sha256) = 32
        AND octet_length(migration_manifest_sha256) = 32
    )
);

CREATE VIEW profile.schema_compatibility
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    'profile'::text AS component,
    COALESCE(
        (SELECT max(version) FROM profile.schema_migrations
         WHERE component = 'profile'),
        0
    )::integer AS current_schema_version,
    contract.schema_head_version,
    contract.min_app_compatible_version,
    contract.max_app_compatible_version,
    contract.migration_manifest_sha256
FROM profile.schema_contracts AS contract
WHERE contract.singleton_key;

CREATE TABLE profile.creator_profiles (
    id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    status text NOT NULL,
    aggregate_version bigint NOT NULL,
    current_draft_version_id uuid NULL,
    current_published_version_id uuid NULL,
    paused_at timestamptz NULL,
    pause_reason_code varchar(64) NULL,
    archived_at timestamptz NULL,
    archive_reason_code varchar(64) NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_creator_profiles PRIMARY KEY (id),
    CONSTRAINT uq_creator_profile_owner UNIQUE (owner_user_id),
    CONSTRAINT uq_creator_profile_id_owner UNIQUE (id, owner_user_id),
    CONSTRAINT ck_creator_profile_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_creator_profile_time CHECK (updated_at >= created_at),
    CONSTRAINT ck_creator_profile_status CHECK (
        status IN ('DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED')
    ),
    CONSTRAINT ck_creator_profile_shape CHECK (
        (
            status = 'DRAFT'
            AND current_published_version_id IS NULL
            AND paused_at IS NULL AND pause_reason_code IS NULL
            AND archived_at IS NULL AND archive_reason_code IS NULL
        )
        OR
        (
            status = 'ACTIVE'
            AND current_published_version_id IS NOT NULL
            AND paused_at IS NULL AND pause_reason_code IS NULL
            AND archived_at IS NULL AND archive_reason_code IS NULL
        )
        OR
        (
            status = 'PAUSED'
            AND current_published_version_id IS NOT NULL
            AND paused_at IS NOT NULL AND pause_reason_code IS NOT NULL
            AND archived_at IS NULL AND archive_reason_code IS NULL
        )
        OR
        (
            status = 'ARCHIVED'
            AND current_draft_version_id IS NULL
            AND current_published_version_id IS NULL
            AND paused_at IS NULL AND pause_reason_code IS NULL
            AND archived_at IS NOT NULL AND archive_reason_code IS NOT NULL
        )
    )
);

CREATE TABLE profile.profile_versions (
    id uuid NOT NULL,
    profile_id uuid NOT NULL,
    version_no bigint NOT NULL,
    status text NOT NULL,
    based_on_profile_version_id uuid NULL,
    schema_version integer NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    canonical_content bytea NOT NULL,
    content jsonb NOT NULL,
    content_sha256 bytea NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    published_at timestamptz NULL,
    confirmed boolean NOT NULL DEFAULT false,
    CONSTRAINT pk_profile_versions PRIMARY KEY (id),
    CONSTRAINT uq_profile_version_number UNIQUE (profile_id, version_no),
    CONSTRAINT uq_profile_version_id_profile UNIQUE (profile_id, id),
    CONSTRAINT fk_profile_version_root FOREIGN KEY (profile_id)
        REFERENCES profile.creator_profiles (id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_profile_version_based_on FOREIGN KEY (
        profile_id,
        based_on_profile_version_id
    ) REFERENCES profile.profile_versions (profile_id, id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_profile_version_number CHECK (version_no >= 1),
    CONSTRAINT ck_profile_version_status CHECK (
        status IN ('DRAFT', 'PUBLISHED', 'DISCARDED', 'SUPERSEDED', 'RETIRED')
    ),
    CONSTRAINT ck_profile_version_contract CHECK (
        schema_version = 1
        AND canonicalization_version = 'profile-version-json-v1'
        AND jsonb_typeof(content) = 'object'
        AND octet_length(canonical_content) BETWEEN 1 AND 524288
        AND octet_length(content_sha256) = 32
    ),
    CONSTRAINT ck_profile_version_publish_shape CHECK (
        (
            status = 'DRAFT'
            AND published_at IS NULL
            AND NOT confirmed
        )
        OR
        (
            status IN ('DISCARDED')
            AND published_at IS NULL
        )
        OR
        (
            status IN ('PUBLISHED', 'SUPERSEDED', 'RETIRED')
            AND published_at IS NOT NULL
            AND confirmed
        )
    )
);

CREATE UNIQUE INDEX ux_profile_version_single_draft
ON profile.profile_versions (profile_id)
WHERE status = 'DRAFT';

CREATE UNIQUE INDEX ux_profile_version_single_published
ON profile.profile_versions (profile_id)
WHERE status = 'PUBLISHED';

ALTER TABLE profile.creator_profiles
ADD CONSTRAINT fk_creator_profile_current_draft FOREIGN KEY (
    id,
    current_draft_version_id
) REFERENCES profile.profile_versions (profile_id, id)
  ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE profile.creator_profiles
ADD CONSTRAINT fk_creator_profile_current_published FOREIGN KEY (
    id,
    current_published_version_id
) REFERENCES profile.profile_versions (profile_id, id)
  ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE profile.taxonomy_bundle_markers (
    id uuid NOT NULL,
    status text NOT NULL,
    bundle_sha256 bytea NOT NULL,
    aggregate_version bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_profile_taxonomy_bundle_markers PRIMARY KEY (id),
    CONSTRAINT ck_profile_taxonomy_marker_status CHECK (status = 'ACTIVE'),
    CONSTRAINT ck_profile_taxonomy_marker_hash CHECK (
        octet_length(bundle_sha256) = 32
    ),
    CONSTRAINT ck_profile_taxonomy_marker_version CHECK (aggregate_version >= 1)
);

CREATE TABLE profile.capability_evidence (
    id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    status text NOT NULL,
    aggregate_version bigint NOT NULL,
    safe_object_reference varchar(256) NOT NULL,
    evidence_sha256 bytea NOT NULL,
    verified_at timestamptz NULL,
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_profile_capability_evidence PRIMARY KEY (id),
    CONSTRAINT ck_profile_evidence_status CHECK (
        status IN ('PENDING', 'VERIFIED', 'REJECTED', 'EXPIRED', 'REVOKED')
    ),
    CONSTRAINT ck_profile_evidence_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_profile_evidence_hash CHECK (octet_length(evidence_sha256) = 32),
    CONSTRAINT ck_profile_evidence_time CHECK (
        (verified_at IS NULL OR verified_at >= created_at)
        AND (expires_at IS NULL OR expires_at > created_at)
    )
);

CREATE TABLE profile.profile_version_evidence (
    profile_id uuid NOT NULL,
    profile_version_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    evidence_version bigint NOT NULL,
    safe_status text NOT NULL,
    evidence_sha256 bytea NOT NULL,
    CONSTRAINT pk_profile_version_evidence PRIMARY KEY (
        profile_version_id,
        evidence_id
    ),
    CONSTRAINT fk_profile_version_evidence_version FOREIGN KEY (
        profile_id,
        profile_version_id
    ) REFERENCES profile.profile_versions (profile_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_profile_version_evidence_evidence FOREIGN KEY (evidence_id)
        REFERENCES profile.capability_evidence (id) ON DELETE RESTRICT,
    CONSTRAINT ck_profile_version_evidence_version CHECK (evidence_version >= 1),
    CONSTRAINT ck_profile_version_evidence_hash CHECK (
        octet_length(evidence_sha256) = 32
    )
);

CREATE TABLE profile.command_receipts (
    id uuid NOT NULL,
    principal_kind text NOT NULL,
    principal_id uuid NOT NULL,
    command_name varchar(96) NOT NULL,
    command_version integer NOT NULL,
    idempotency_key_digest_key_id varchar(64) NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    payload_hash_key_id varchar(64) NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    payload_hash bytea NOT NULL,
    target_profile_id uuid NOT NULL,
    expected_aggregate_version bigint NULL,
    status text NOT NULL,
    safe_response_body jsonb NULL,
    response_schema_version integer NULL,
    completed_aggregate_version bigint NULL,
    created_at timestamptz NOT NULL,
    retain_until timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT pk_profile_command_receipts PRIMARY KEY (id),
    CONSTRAINT uq_profile_command_receipt_identity UNIQUE (
        principal_kind,
        principal_id,
        command_name,
        command_version,
        idempotency_key_digest_key_id,
        idempotency_key_digest
    ),
    CONSTRAINT ck_profile_receipt_principal CHECK (principal_kind = 'USER'),
    CONSTRAINT ck_profile_receipt_version CHECK (command_version = 1),
    CONSTRAINT ck_profile_receipt_hashes CHECK (
        octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
    ),
    CONSTRAINT ck_profile_receipt_canonicalizer CHECK (
        canonicalization_version = 'profile-command-json-v1'
    ),
    CONSTRAINT ck_profile_receipt_status CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
    ),
    CONSTRAINT ck_profile_receipt_shape CHECK (
        (
            status = 'IN_PROGRESS'
            AND safe_response_body IS NULL
            AND response_schema_version IS NULL
            AND completed_aggregate_version IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            status = 'COMPLETED'
            AND jsonb_typeof(safe_response_body) = 'object'
            AND response_schema_version = 1
            AND completed_aggregate_version >= 1
            AND completed_at IS NOT NULL
        )
    ),
    CONSTRAINT ck_profile_receipt_time CHECK (
        retain_until > created_at
        AND (completed_at IS NULL OR completed_at < retain_until)
    )
);

CREATE TABLE profile.match_capture_authorizations (
    match_run_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    candidate_profile_id uuid NOT NULL,
    authorization_digest bytea NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_profile_match_capture_authorizations PRIMARY KEY (
        match_run_id,
        workload_id,
        candidate_profile_id
    ),
    CONSTRAINT fk_profile_match_candidate FOREIGN KEY (candidate_profile_id)
        REFERENCES profile.creator_profiles (id) ON DELETE RESTRICT,
    CONSTRAINT ck_profile_match_authorization_hash CHECK (
        octet_length(authorization_digest) = 32
    ),
    CONSTRAINT ck_profile_match_authorization_time CHECK (
        valid_from <= created_at AND valid_until > created_at
    )
);

CREATE FUNCTION profile.enforce_creator_profile_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, profile
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.updated_at < OLD.updated_at
       OR (OLD.status = 'ARCHIVED' AND NEW.status <> 'ARCHIVED')
       OR (OLD.status = 'PAUSED' AND NEW.status NOT IN ('ACTIVE', 'ARCHIVED'))
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'PAUSED', 'ARCHIVED'))
       OR (OLD.status = 'DRAFT' AND NEW.status NOT IN ('DRAFT', 'ACTIVE', 'ARCHIVED')) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'trg_creator_profile_transition',
            MESSAGE = 'invalid Creator Profile transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_creator_profile_transition
BEFORE UPDATE ON profile.creator_profiles
FOR EACH ROW EXECUTE FUNCTION profile.enforce_creator_profile_transition();

CREATE FUNCTION profile.enforce_profile_version_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, profile
AS $function$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.profile_id IS DISTINCT FROM OLD.profile_id
       OR NEW.version_no IS DISTINCT FROM OLD.version_no
       OR NEW.based_on_profile_version_id IS DISTINCT FROM OLD.based_on_profile_version_id
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
       OR NEW.canonicalization_version IS DISTINCT FROM OLD.canonicalization_version
       OR NEW.taxonomy_bundle_id IS DISTINCT FROM OLD.taxonomy_bundle_id
       OR NEW.canonical_content IS DISTINCT FROM OLD.canonical_content
       OR NEW.content IS DISTINCT FROM OLD.content
       OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NOT (
            (OLD.status = 'DRAFT' AND NEW.status IN ('PUBLISHED', 'DISCARDED'))
            OR (OLD.status = 'PUBLISHED' AND NEW.status IN ('SUPERSEDED', 'RETIRED'))
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'trg_profile_version_immutable',
            MESSAGE = 'ProfileVersion is immutable';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_profile_version_immutable
BEFORE UPDATE OR DELETE ON profile.profile_versions
FOR EACH ROW EXECUTE FUNCTION profile.enforce_profile_version_immutable();

CREATE FUNCTION profile.enforce_profile_receipt_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, profile
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.command_name IS DISTINCT FROM OLD.command_name
       OR NEW.command_version IS DISTINCT FROM OLD.command_version
       OR NEW.idempotency_key_digest_key_id IS DISTINCT FROM OLD.idempotency_key_digest_key_id
       OR NEW.idempotency_key_digest IS DISTINCT FROM OLD.idempotency_key_digest
       OR NEW.payload_hash_key_id IS DISTINCT FROM OLD.payload_hash_key_id
       OR NEW.canonicalization_version IS DISTINCT FROM OLD.canonicalization_version
       OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
       OR NEW.target_profile_id IS DISTINCT FROM OLD.target_profile_id
       OR NEW.expected_aggregate_version IS DISTINCT FROM OLD.expected_aggregate_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.retain_until IS DISTINCT FROM OLD.retain_until
       OR OLD.status <> 'IN_PROGRESS'
       OR NEW.status <> 'COMPLETED' THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'trg_profile_receipt_transition',
            MESSAGE = 'invalid Profile receipt transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_profile_receipt_transition
BEFORE UPDATE ON profile.command_receipts
FOR EACH ROW EXECUTE FUNCTION profile.enforce_profile_receipt_transition();

ALTER TABLE profile.creator_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.creator_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.profile_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.profile_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.taxonomy_bundle_markers ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.taxonomy_bundle_markers FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.capability_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.capability_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.profile_version_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.profile_version_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.command_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.match_capture_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.match_capture_authorizations FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_creator_profile_self
ON profile.creator_profiles
FOR ALL TO profile_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND id = NULLIF(current_setting('app.profile_id', true), '')::uuid
    AND owner_user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
)
WITH CHECK (
    id = NULLIF(current_setting('app.profile_id', true), '')::uuid
    AND owner_user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_profile_version_self
ON profile.profile_versions
FOR ALL TO profile_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND profile_id = NULLIF(current_setting('app.profile_id', true), '')::uuid
    AND EXISTS (
        SELECT 1 FROM profile.creator_profiles AS root
        WHERE root.id = profile_versions.profile_id
          AND root.owner_user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
    )
)
WITH CHECK (
    profile_id = NULLIF(current_setting('app.profile_id', true), '')::uuid
    AND created_by_user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
);

CREATE POLICY rls_profile_taxonomy_self
ON profile.taxonomy_bundle_markers
FOR SELECT TO profile_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND status = 'ACTIVE'
);

CREATE POLICY rls_profile_evidence_self
ON profile.capability_evidence
FOR SELECT TO profile_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND owner_user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_profile_version_evidence_self
ON profile.profile_version_evidence
FOR SELECT TO profile_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND profile_id = NULLIF(current_setting('app.profile_id', true), '')::uuid
);

CREATE POLICY rls_profile_receipt_self
ON profile.command_receipts
FOR ALL TO profile_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_SELF'
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = NULLIF(current_setting('app.command_version', true), '')::integer
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true),
        ''
    )
    AND idempotency_key_digest = pg_catalog.decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''),
        'hex'
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND target_profile_id = NULLIF(current_setting('app.profile_id', true), '')::uuid
);

CREATE POLICY rls_profile_match_authorization
ON profile.match_capture_authorizations
FOR SELECT TO profile_matcher
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_MATCH_CAPTURE'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND authorization_digest = pg_catalog.decode(
        NULLIF(current_setting('app.match_authorization_digest', true), ''),
        'hex'
    )
    AND valid_from <= transaction_timestamp()
    AND valid_until > transaction_timestamp()
);

CREATE POLICY rls_profile_match_authorization_definer
ON profile.match_capture_authorizations
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND authorization_digest = pg_catalog.decode(
        NULLIF(current_setting('app.match_authorization_digest', true), ''),
        'hex'
    )
    AND valid_from <= transaction_timestamp()
    AND valid_until > transaction_timestamp()
);

CREATE POLICY rls_creator_profile_matcher
ON profile.creator_profiles
FOR SELECT TO profile_matcher
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PROFILE_MATCH_CAPTURE'
    AND EXISTS (
        SELECT 1 FROM profile.match_capture_authorizations AS match_authz
        WHERE match_authz.candidate_profile_id = creator_profiles.id
    )
);

CREATE POLICY rls_creator_profile_matcher_definer
ON profile.creator_profiles
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND EXISTS (
        SELECT 1 FROM profile.match_capture_authorizations AS match_authz
        WHERE match_authz.candidate_profile_id = creator_profiles.id
    )
);

CREATE POLICY rls_profile_version_matcher
ON profile.profile_versions
FOR SELECT TO profile_matcher
USING (
    status = 'PUBLISHED'
    AND EXISTS (
        SELECT 1 FROM profile.creator_profiles AS root
        WHERE root.id = profile_versions.profile_id
          AND root.current_published_version_id = profile_versions.id
    )
);

CREATE FUNCTION profile_api.is_capture_candidate_eligible_v1(
    bound_profile_id uuid,
    bound_user_id uuid,
    bound_match_run_id uuid,
    bound_workload_id uuid,
    bound_authorization_digest bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, profile, profile_api, iam_api
AS $function$
BEGIN
    IF session_user <> 'profile_matcher'
       OR octet_length(bound_authorization_digest) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            <> 'PROFILE_MATCH_CAPTURE'
       OR NULLIF(current_setting('app.match_run_id', true), '')::uuid
            IS DISTINCT FROM bound_match_run_id
       OR NULLIF(current_setting('app.workload_id', true), '')::uuid
            IS DISTINCT FROM bound_workload_id
       OR pg_catalog.decode(
            NULLIF(current_setting('app.match_authorization_digest', true), ''),
            'hex'
          ) IS DISTINCT FROM bound_authorization_digest
       OR NOT EXISTS (
            SELECT 1
            FROM profile.match_capture_authorizations AS authz
            JOIN profile.creator_profiles AS root
              ON root.id = authz.candidate_profile_id
             AND root.owner_user_id = bound_user_id
            WHERE authz.match_run_id = bound_match_run_id
              AND authz.workload_id = bound_workload_id
              AND authz.candidate_profile_id = bound_profile_id
              AND authz.authorization_digest
                  = bound_authorization_digest
              AND authz.valid_from <= transaction_timestamp()
              AND authz.valid_until > transaction_timestamp()
       ) THEN
        RETURN false;
    END IF;

    RETURN iam_api.is_creator_match_eligible_v1(bound_user_id);
END
$function$;

REVOKE ALL ON FUNCTION profile_api.is_capture_candidate_eligible_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION profile_api.is_capture_candidate_eligible_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    bytea
) TO profile_matcher;

REVOKE ALL ON ALL TABLES IN SCHEMA profile FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA profile FROM PUBLIC;
GRANT USAGE ON SCHEMA profile, profile_api TO profile_app, profile_matcher;
GRANT SELECT, INSERT, UPDATE ON profile.creator_profiles TO profile_app;
GRANT SELECT, INSERT, UPDATE ON profile.profile_versions TO profile_app;
GRANT SELECT ON profile.taxonomy_bundle_markers TO profile_app;
GRANT SELECT ON profile.capability_evidence, profile.profile_version_evidence
TO profile_app;
GRANT SELECT, INSERT, UPDATE ON profile.command_receipts TO profile_app;
GRANT SELECT ON profile.creator_profiles, profile.profile_versions,
    profile.profile_version_evidence, profile.match_capture_authorizations
TO profile_matcher;

DO $assert$
DECLARE
    invalid_roles integer;
    invalid_rls integer;
BEGIN
    SELECT count(*) INTO invalid_roles
    FROM pg_catalog.pg_roles
    WHERE rolname IN ('profile_app', 'profile_matcher')
      AND (rolsuper OR rolbypassrls OR rolinherit OR NOT rolcanlogin);
    IF invalid_roles <> 0
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'profile_app')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'profile_matcher') THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Creator Profile online role assertion failed';
    END IF;

    SELECT count(*) INTO invalid_rls
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'profile'
      AND relation.relname IN (
        'creator_profiles',
        'profile_versions',
        'taxonomy_bundle_markers',
        'capability_evidence',
        'profile_version_evidence',
        'command_receipts',
        'match_capture_authorizations'
      )
      AND (NOT relation.relrowsecurity OR NOT relation.relforcerowsecurity);
    IF invalid_rls <> 0 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Creator Profile FORCE RLS assertion failed';
    END IF;
END
$assert$;
