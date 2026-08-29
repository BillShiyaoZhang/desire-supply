-- Exact Profile marker projection for the reviewed INTERNAL_SANDBOX seed.

CREATE TABLE profile.taxonomy_projection_inbox (
    event_id varchar(128) NOT NULL,
    event_sha256 bytea NOT NULL,
    seed_manifest_sha256 bytea NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    release_manifest_sha256 bytea NOT NULL,
    aggregate_version bigint NOT NULL,
    status text NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT pk_profile_taxonomy_projection_inbox PRIMARY KEY (event_id),
    CONSTRAINT uq_profile_taxonomy_projection_seed UNIQUE (
        seed_manifest_sha256
    ),
    CONSTRAINT ck_profile_taxonomy_projection_hashes CHECK (
        octet_length(event_sha256) = 32
        AND octet_length(seed_manifest_sha256) = 32
        AND octet_length(release_manifest_sha256) = 32
    ),
    CONSTRAINT ck_profile_taxonomy_projection_version CHECK (
        aggregate_version >= 1
    ),
    CONSTRAINT ck_profile_taxonomy_projection_status CHECK (
        status = 'COMPLETED'
    )
);

ALTER TABLE profile.taxonomy_projection_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.taxonomy_projection_inbox FORCE ROW LEVEL SECURITY;

CREATE POLICY profile_internal_seed_marker_owner
ON profile.taxonomy_bundle_markers
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
)
WITH CHECK (
    session_user = 'profile_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
);

CREATE POLICY profile_internal_seed_projection_owner
ON profile.taxonomy_projection_inbox
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
)
WITH CHECK (
    session_user = 'profile_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
);

CREATE POLICY profile_internal_seed_schema_migrations
ON profile.schema_migrations
FOR SELECT TO profile_migration_runner
USING (
    session_user = 'profile_migration_runner'
    AND current_user = 'profile_migration_runner'
);

CREATE POLICY profile_internal_seed_schema_contracts
ON profile.schema_contracts
FOR SELECT TO profile_migration_runner
USING (
    session_user = 'profile_migration_runner'
    AND current_user = 'profile_migration_runner'
);

CREATE POLICY profile_internal_seed_readiness_marker_owner
ON profile.taxonomy_bundle_markers
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_app'
    AND id = '50000000-0000-4000-8000-000000000001'::uuid
);

CREATE POLICY profile_internal_seed_readiness_inbox_owner
ON profile.taxonomy_projection_inbox
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_app'
    AND seed_manifest_sha256 = decode(
        '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d',
        'hex'
    )
);

CREATE FUNCTION profile_api.project_internal_sandbox_taxonomy_marker_v1(
    p_deployment_mode text,
    p_seed_manifest_sha256 bytea,
    p_event_id text,
    p_event_sha256 bytea,
    p_taxonomy_bundle_id uuid,
    p_release_manifest_sha256 bytea,
    p_aggregate_version bigint,
    p_captured_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, profile
AS $function$
DECLARE
    existing_inbox record;
    existing_marker record;
BEGIN
    IF session_user IS DISTINCT FROM 'profile_migration_runner'
       OR p_deployment_mode IS DISTINCT FROM 'INTERNAL_SANDBOX'
       OR encode(p_seed_manifest_sha256, 'hex') IS DISTINCT FROM
            '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
       OR NULLIF(current_setting('app.deployment_mode', true), '')
            IS DISTINCT FROM p_deployment_mode
       OR NULLIF(current_setting('app.seed_manifest_sha256', true), '')
            IS DISTINCT FROM encode(p_seed_manifest_sha256, 'hex')
       OR NULLIF(current_setting('app.seed_operation', true), '')
            IS DISTINCT FROM 'PROJECT_PROFILE_TAXONOMY'
       OR p_event_id IS NULL
       OR length(p_event_id) NOT BETWEEN 16 AND 128
       OR p_event_id !~ '^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$'
       OR p_event_sha256 IS NULL
       OR octet_length(p_event_sha256) <> 32
       OR p_event_sha256 = decode(repeat('00', 32), 'hex')
       OR p_taxonomy_bundle_id IS DISTINCT FROM
            '50000000-0000-4000-8000-000000000001'::uuid
       OR encode(p_release_manifest_sha256, 'hex') IS DISTINCT FROM
            'edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af'
       OR p_aggregate_version IS DISTINCT FROM 1::bigint
       OR p_captured_at IS NULL
       OR p_captured_at < '2020-01-01 00:00:00+00'::timestamptz
       OR p_captured_at > transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'internal sandbox taxonomy projection denied';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(encode(p_seed_manifest_sha256, 'hex'), 0)
    );
    SELECT event_id, event_sha256, taxonomy_bundle_id,
           release_manifest_sha256, aggregate_version, status
    INTO existing_inbox
    FROM profile.taxonomy_projection_inbox
    WHERE seed_manifest_sha256 = p_seed_manifest_sha256
    FOR UPDATE;
    IF existing_inbox IS NOT NULL THEN
        IF existing_inbox.event_id IS DISTINCT FROM p_event_id
           OR existing_inbox.event_sha256 IS DISTINCT FROM p_event_sha256
           OR existing_inbox.taxonomy_bundle_id IS DISTINCT FROM
                p_taxonomy_bundle_id
           OR existing_inbox.release_manifest_sha256 IS DISTINCT FROM
                p_release_manifest_sha256
           OR existing_inbox.aggregate_version IS DISTINCT FROM
                p_aggregate_version
           OR existing_inbox.status IS DISTINCT FROM 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'internal sandbox taxonomy projection drift';
        END IF;
        SELECT status, bundle_sha256, aggregate_version
        INTO existing_marker
        FROM profile.taxonomy_bundle_markers
        WHERE id = p_taxonomy_bundle_id
        FOR UPDATE;
        IF existing_marker IS NULL
           OR existing_marker.status IS DISTINCT FROM 'ACTIVE'
           OR existing_marker.bundle_sha256 IS DISTINCT FROM
                p_release_manifest_sha256
           OR existing_marker.aggregate_version IS DISTINCT FROM
                p_aggregate_version THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'internal sandbox taxonomy marker drift';
        END IF;
        RETURN false;
    END IF;

    SELECT status, bundle_sha256, aggregate_version
    INTO existing_marker
    FROM profile.taxonomy_bundle_markers
    WHERE id = p_taxonomy_bundle_id
    FOR UPDATE;
    IF existing_marker IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox taxonomy marker provenance missing';
    END IF;

    INSERT INTO profile.taxonomy_bundle_markers(
        id, status, bundle_sha256, aggregate_version, updated_at
    ) VALUES (
        p_taxonomy_bundle_id,
        'ACTIVE',
        p_release_manifest_sha256,
        p_aggregate_version,
        transaction_timestamp()
    );
    INSERT INTO profile.taxonomy_projection_inbox(
        event_id,
        event_sha256,
        seed_manifest_sha256,
        taxonomy_bundle_id,
        release_manifest_sha256,
        aggregate_version,
        status,
        completed_at
    ) VALUES (
        p_event_id,
        p_event_sha256,
        p_seed_manifest_sha256,
        p_taxonomy_bundle_id,
        p_release_manifest_sha256,
        p_aggregate_version,
        'COMPLETED',
        transaction_timestamp()
    );
    RETURN true;
END
$function$;

CREATE FUNCTION profile_api.internal_sandbox_taxonomy_seed_ready_v1()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, profile
AS $function$
    SELECT session_user = 'profile_app'
       AND (
            SELECT count(*)
            FROM profile.taxonomy_projection_inbox
            WHERE seed_manifest_sha256 = decode(
                '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d',
                'hex'
            )
              AND taxonomy_bundle_id =
                '50000000-0000-4000-8000-000000000001'::uuid
              AND release_manifest_sha256 = decode(
                'edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af',
                'hex'
              )
              AND aggregate_version = 1
              AND status = 'COMPLETED'
       ) = 1
       AND (
            SELECT count(*)
            FROM profile.taxonomy_bundle_markers
            WHERE id = '50000000-0000-4000-8000-000000000001'::uuid
              AND status = 'ACTIVE'
              AND bundle_sha256 = decode(
                'edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af',
                'hex'
              )
              AND aggregate_version = 1
       ) = 1
$function$;

ALTER FUNCTION profile_api.project_internal_sandbox_taxonomy_marker_v1(
    text, bytea, text, bytea, uuid, bytea, bigint, timestamptz
) OWNER TO profile_schema_owner;
ALTER FUNCTION profile_api.internal_sandbox_taxonomy_seed_ready_v1()
OWNER TO profile_schema_owner;
REVOKE ALL ON FUNCTION profile_api.project_internal_sandbox_taxonomy_marker_v1(
    text, bytea, text, bytea, uuid, bytea, bigint, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION profile_api.internal_sandbox_taxonomy_seed_ready_v1()
FROM PUBLIC;
GRANT USAGE ON SCHEMA profile_api TO profile_migration_runner;
GRANT USAGE ON SCHEMA profile TO profile_migration_runner;
GRANT SELECT ON profile.schema_migrations,profile.schema_contracts
TO profile_migration_runner;
GRANT SELECT ON profile.schema_compatibility TO profile_migration_runner;
GRANT EXECUTE ON FUNCTION profile_api.project_internal_sandbox_taxonomy_marker_v1(
    text, bytea, text, bytea, uuid, bytea, bigint, timestamptz
) TO profile_migration_runner;
GRANT EXECUTE ON FUNCTION profile_api.internal_sandbox_taxonomy_seed_ready_v1()
TO profile_app;

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'profile_api'
      AND procedure.proname =
          'project_internal_sandbox_taxonomy_marker_v1'
      AND (
          owner_role.rolname <> 'profile_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 'v'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, profile']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'profile_migration_runner',
            'profile_api.project_internal_sandbox_taxonomy_marker_v1(text,bytea,text,bytea,uuid,bytea,bigint,timestamptz)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_app',
            'profile_api.project_internal_sandbox_taxonomy_marker_v1(text,bytea,text,bytea,uuid,bytea,bigint,timestamptz)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox taxonomy projection assertion failed';
    END IF;
END
$assert$;

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'profile_api'
      AND procedure.proname =
          'internal_sandbox_taxonomy_seed_ready_v1'
      AND (
          owner_role.rolname <> 'profile_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 's'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, profile']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'profile_app',
            'profile_api.internal_sandbox_taxonomy_seed_ready_v1()',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_matcher',
            'profile_api.internal_sandbox_taxonomy_seed_ready_v1()',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_migration_runner',
            'profile_api.internal_sandbox_taxonomy_seed_ready_v1()',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox taxonomy readiness assertion failed';
    END IF;
END
$assert$;
