-- Digest-pinned INTERNAL_SANDBOX authority provisioning for one synthetic seed.

ALTER TABLE taxonomy.schema_contracts
DROP CONSTRAINT schema_contracts_schema_head_version_check;
ALTER TABLE taxonomy.schema_contracts
DROP CONSTRAINT schema_contracts_min_app_compatible_version_check;
ALTER TABLE taxonomy.schema_contracts
DROP CONSTRAINT schema_contracts_max_app_compatible_version_check;
ALTER TABLE taxonomy.schema_contracts
ADD CONSTRAINT ck_taxonomy_schema_contract_versions CHECK (
    schema_head_version >= 1
    AND min_app_compatible_version >= 1
    AND max_app_compatible_version >= min_app_compatible_version
);

CREATE POLICY taxonomy_internal_seed_workload_owner
ON taxonomy.workload_authorizations
FOR ALL TO taxonomy_schema_owner
USING (
    session_user = 'taxonomy_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
)
WITH CHECK (
    session_user = 'taxonomy_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
);

CREATE POLICY taxonomy_internal_seed_consumer_owner
ON taxonomy.consumer_authorizations
FOR ALL TO taxonomy_schema_owner
USING (
    session_user = 'taxonomy_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
)
WITH CHECK (
    session_user = 'taxonomy_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
);

CREATE POLICY taxonomy_internal_seed_bundle_owner
ON taxonomy.bundles
FOR SELECT TO taxonomy_schema_owner
USING (
    session_user = 'taxonomy_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
    AND bundle_id = '50000000-0000-4000-8000-000000000001'
);

CREATE POLICY taxonomy_internal_seed_current_owner
ON taxonomy.current_bundles
FOR SELECT TO taxonomy_schema_owner
USING (
    session_user = 'taxonomy_migration_runner'
    AND NULLIF(current_setting('app.deployment_mode', true), '')
        = 'INTERNAL_SANDBOX'
    AND NULLIF(current_setting('app.seed_manifest_sha256', true), '')
        = '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
    AND bundle_id = '50000000-0000-4000-8000-000000000001'
);

CREATE POLICY taxonomy_internal_seed_schema_migrations
ON taxonomy.schema_migrations
FOR SELECT TO taxonomy_migration_runner
USING (
    session_user = 'taxonomy_migration_runner'
    AND current_user = 'taxonomy_migration_runner'
);

CREATE POLICY taxonomy_internal_seed_schema_contracts
ON taxonomy.schema_contracts
FOR SELECT TO taxonomy_migration_runner
USING (
    session_user = 'taxonomy_migration_runner'
    AND current_user = 'taxonomy_migration_runner'
);

CREATE FUNCTION taxonomy_api.provision_internal_sandbox_workload_v1(
    p_deployment_mode text,
    p_seed_manifest_sha256 bytea,
    p_workload_principal_id text,
    p_operation text,
    p_credential_sha256 bytea,
    p_attestation_sha256 bytea,
    p_valid_until timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, taxonomy
AS $function$
DECLARE
    inserted_count integer;
    existing record;
BEGIN
    IF session_user IS DISTINCT FROM 'taxonomy_migration_runner'
       OR p_deployment_mode IS DISTINCT FROM 'INTERNAL_SANDBOX'
       OR encode(p_seed_manifest_sha256, 'hex') IS DISTINCT FROM
            '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
       OR NULLIF(current_setting('app.deployment_mode', true), '')
            IS DISTINCT FROM p_deployment_mode
       OR NULLIF(current_setting('app.seed_manifest_sha256', true), '')
            IS DISTINCT FROM encode(p_seed_manifest_sha256, 'hex')
       OR NULLIF(current_setting('app.seed_operation', true), '')
            IS DISTINCT FROM 'PROVISION_WORKLOAD'
       OR p_workload_principal_id IS DISTINCT FROM
            'internal_sandbox_taxonomy_seed_v1'
       OR p_operation IS DISTINCT FROM 'PublishTaxonomyBundle'
       OR p_credential_sha256 IS NULL
       OR octet_length(p_credential_sha256) <> 32
       OR p_credential_sha256 = decode(repeat('00', 32), 'hex')
       OR encode(p_attestation_sha256, 'hex') IS DISTINCT FROM
            '997cd36982083be3fd8f38e0069c2c20b342b1e89ba8e1225ce402fdfd46e501'
       OR p_valid_until IS DISTINCT FROM
            '2100-01-01 00:00:00+00'::timestamptz
       OR transaction_timestamp() >= p_valid_until THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'internal sandbox seed authority denied';
    END IF;

    INSERT INTO taxonomy.workload_authorizations(
        workload_principal_id,
        operation,
        credential_sha256,
        attestation_sha256,
        status,
        valid_until
    ) VALUES (
        p_workload_principal_id,
        p_operation,
        p_credential_sha256,
        p_attestation_sha256,
        'ACTIVE',
        p_valid_until
    ) ON CONFLICT (workload_principal_id, operation) DO NOTHING;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;

    SELECT credential_sha256, attestation_sha256, status, valid_until
    INTO existing
    FROM taxonomy.workload_authorizations
    WHERE workload_principal_id = p_workload_principal_id
      AND operation = p_operation
    FOR UPDATE;
    IF existing IS NULL
       OR existing.credential_sha256 IS DISTINCT FROM p_credential_sha256
       OR existing.attestation_sha256 IS DISTINCT FROM p_attestation_sha256
       OR existing.status IS DISTINCT FROM 'ACTIVE'
       OR existing.valid_until IS DISTINCT FROM p_valid_until THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox seed authority drift';
    END IF;
    RETURN inserted_count = 1;
END
$function$;

CREATE FUNCTION taxonomy_api.provision_internal_sandbox_profile_consumer_v1(
    p_deployment_mode text,
    p_seed_manifest_sha256 bytea,
    p_authorization_digest bytea,
    p_consumer_code text,
    p_consumer_job_id text,
    p_workload_principal_id text,
    p_bundle_id text,
    p_release_manifest_sha256 bytea,
    p_credential_sha256 bytea,
    p_attestation_sha256 bytea,
    p_valid_until timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, taxonomy
AS $function$
DECLARE
    inserted_count integer;
    existing record;
    release_count integer;
BEGIN
    IF session_user IS DISTINCT FROM 'taxonomy_migration_runner'
       OR p_deployment_mode IS DISTINCT FROM 'INTERNAL_SANDBOX'
       OR encode(p_seed_manifest_sha256, 'hex') IS DISTINCT FROM
            '418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d'
       OR NULLIF(current_setting('app.deployment_mode', true), '')
            IS DISTINCT FROM p_deployment_mode
       OR NULLIF(current_setting('app.seed_manifest_sha256', true), '')
            IS DISTINCT FROM encode(p_seed_manifest_sha256, 'hex')
       OR NULLIF(current_setting('app.seed_operation', true), '')
            IS DISTINCT FROM 'PROVISION_PROFILE_CONSUMER'
       OR encode(p_authorization_digest, 'hex') IS DISTINCT FROM
            'b1fc57d727ca30377601e05afd5eccdb787b59f82072a027a203934696496d33'
       OR p_consumer_code IS DISTINCT FROM 'PROFILE'
       OR p_consumer_job_id IS DISTINCT FROM
            'internal_sandbox_profile_seed_job_v1'
       OR p_workload_principal_id IS DISTINCT FROM
            'internal_sandbox_taxonomy_seed_v1'
       OR p_bundle_id IS DISTINCT FROM
            '50000000-0000-4000-8000-000000000001'
       OR encode(p_release_manifest_sha256, 'hex') IS DISTINCT FROM
            'edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af'
       OR p_credential_sha256 IS NULL
       OR octet_length(p_credential_sha256) <> 32
       OR p_credential_sha256 = decode(repeat('00', 32), 'hex')
       OR encode(p_attestation_sha256, 'hex') IS DISTINCT FROM
            '997cd36982083be3fd8f38e0069c2c20b342b1e89ba8e1225ce402fdfd46e501'
       OR p_valid_until IS DISTINCT FROM
            '2100-01-01 00:00:00+00'::timestamptz
       OR transaction_timestamp() >= p_valid_until THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'internal sandbox seed consumer denied';
    END IF;

    SELECT count(*) INTO release_count
    FROM taxonomy.bundles AS bundle
    JOIN taxonomy.current_bundles AS current
      ON current.selector_digest = bundle.selector_digest
     AND current.bundle_id = bundle.bundle_id
    WHERE bundle.bundle_id = p_bundle_id
      AND bundle.release_manifest_sha256 = p_release_manifest_sha256
      AND bundle.status = 'ACTIVE'
      AND bundle.aggregate_version = 1
      AND bundle.effective_at <= transaction_timestamp()
      AND (
          bundle.effective_until IS NULL
          OR transaction_timestamp() < bundle.effective_until
      );
    IF release_count <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox seed release unavailable';
    END IF;

    SELECT count(*) INTO release_count
    FROM taxonomy.workload_authorizations
    WHERE workload_principal_id = p_workload_principal_id
      AND operation = 'PublishTaxonomyBundle'
      AND credential_sha256 = p_credential_sha256
      AND attestation_sha256 = p_attestation_sha256
      AND status = 'ACTIVE'
      AND transaction_timestamp() < valid_until;
    IF release_count <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox seed workload unavailable';
    END IF;

    INSERT INTO taxonomy.consumer_authorizations(
        authorization_digest,
        consumer_code,
        consumer_job_id,
        workload_principal_id,
        bundle_id,
        release_manifest_sha256,
        credential_sha256,
        attestation_sha256,
        valid_until
    ) VALUES (
        p_authorization_digest,
        p_consumer_code,
        p_consumer_job_id,
        p_workload_principal_id,
        p_bundle_id,
        p_release_manifest_sha256,
        p_credential_sha256,
        p_attestation_sha256,
        p_valid_until
    ) ON CONFLICT (authorization_digest) DO NOTHING;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;

    SELECT consumer_code, consumer_job_id, workload_principal_id, bundle_id,
           release_manifest_sha256, credential_sha256, attestation_sha256,
           valid_until
    INTO existing
    FROM taxonomy.consumer_authorizations
    WHERE authorization_digest = p_authorization_digest
    FOR UPDATE;
    IF existing IS NULL
       OR existing.consumer_code IS DISTINCT FROM p_consumer_code
       OR existing.consumer_job_id IS DISTINCT FROM p_consumer_job_id
       OR existing.workload_principal_id IS DISTINCT FROM p_workload_principal_id
       OR existing.bundle_id IS DISTINCT FROM p_bundle_id
       OR existing.release_manifest_sha256 IS DISTINCT FROM
            p_release_manifest_sha256
       OR existing.credential_sha256 IS DISTINCT FROM p_credential_sha256
       OR existing.attestation_sha256 IS DISTINCT FROM p_attestation_sha256
       OR existing.valid_until IS DISTINCT FROM p_valid_until THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox seed consumer drift';
    END IF;
    RETURN inserted_count = 1;
END
$function$;

ALTER FUNCTION taxonomy_api.provision_internal_sandbox_workload_v1(
    text, bytea, text, text, bytea, bytea, timestamptz
) OWNER TO taxonomy_schema_owner;
ALTER FUNCTION taxonomy_api.provision_internal_sandbox_profile_consumer_v1(
    text, bytea, bytea, text, text, text, text, bytea, bytea, bytea,
    timestamptz
) OWNER TO taxonomy_schema_owner;

REVOKE ALL ON FUNCTION taxonomy_api.provision_internal_sandbox_workload_v1(
    text, bytea, text, text, bytea, bytea, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION taxonomy_api.provision_internal_sandbox_profile_consumer_v1(
    text, bytea, bytea, text, text, text, text, bytea, bytea, bytea,
    timestamptz
) FROM PUBLIC;
GRANT USAGE ON SCHEMA taxonomy_api TO taxonomy_migration_runner;
GRANT USAGE ON SCHEMA taxonomy TO taxonomy_migration_runner;
GRANT SELECT ON taxonomy.schema_migrations,taxonomy.schema_contracts
TO taxonomy_migration_runner;
GRANT SELECT ON taxonomy.schema_compatibility TO taxonomy_migration_runner;
GRANT EXECUTE ON FUNCTION taxonomy_api.provision_internal_sandbox_workload_v1(
    text, bytea, text, text, bytea, bytea, timestamptz
) TO taxonomy_migration_runner;
GRANT EXECUTE ON FUNCTION taxonomy_api.provision_internal_sandbox_profile_consumer_v1(
    text, bytea, bytea, text, text, text, text, bytea, bytea, bytea,
    timestamptz
) TO taxonomy_migration_runner;

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
    WHERE namespace.nspname = 'taxonomy_api'
      AND procedure.proname IN (
          'provision_internal_sandbox_workload_v1',
          'provision_internal_sandbox_profile_consumer_v1'
      )
      AND (
          owner_role.rolname <> 'taxonomy_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 'v'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, taxonomy']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'taxonomy_migration_runner',
            'taxonomy_api.provision_internal_sandbox_workload_v1(text,bytea,text,text,bytea,bytea,timestamptz)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'taxonomy_publisher',
            'taxonomy_api.provision_internal_sandbox_workload_v1(text,bytea,text,text,bytea,bytea,timestamptz)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'internal sandbox seed authority assertion failed';
    END IF;
END
$assert$;
