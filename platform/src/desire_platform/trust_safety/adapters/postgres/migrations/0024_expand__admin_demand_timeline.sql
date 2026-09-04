-- Administrator demand progress projection. Runtime EXECUTE only; FORCE RLS remains enabled.
SET LOCAL search_path = pg_catalog, trust;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
GRANT USAGE ON SCHEMA trust_api TO iam_app;
CREATE POLICY rls_admin_demand_timeline_definer ON trust.cases
FOR SELECT TO trust_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON trust.case_assignments
FOR SELECT TO trust_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON trust.safety_holds
FOR SELECT TO trust_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON trust.appeals
FOR SELECT TO trust_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE FUNCTION trust_api.admin_demand_facts_v1(exact_organization_id uuid, exact_demand_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, trust, iam_api
AS $function$
DECLARE result jsonb; actors uuid[];
BEGIN
    IF exact_organization_id IS NULL OR exact_demand_id IS NULL
       OR NOT COALESCE(iam_api.admin_demand_scope_v1(exact_organization_id), false)
       OR COALESCE(current_setting('app.operation', true), '') NOT IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    THEN RETURN NULL; END IF;
    SELECT jsonb_build_object('cases',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',case_id,'report_id',report_id,'status',status,'assigned_officer_user_id',assigned_officer_user_id,'opened_at',opened_at,'updated_at',updated_at) ORDER BY case_id), '[]'::jsonb) FROM trust.cases WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'case_assignments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',assignment_id,'officer_user_id',officer_user_id,'assigned_at',assigned_at,'expires_at',expires_at) ORDER BY assignment_id), '[]'::jsonb) FROM trust.case_assignments WHERE organization_id=exact_organization_id AND case_id IN (SELECT case_id FROM trust.cases WHERE demand_id=exact_demand_id AND organization_id=exact_organization_id)),'safety_holds',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',hold_id,'status',status,'issued_by_user_id',issued_by_user_id,'released_by_user_id',released_by_user_id,'effective_at',effective_at,'expires_at',expires_at,'released_at',released_at) ORDER BY hold_id), '[]'::jsonb) FROM trust.safety_holds WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'appeals',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',appeal_id,'status',status,'opened_at',opened_at,'updated_at',updated_at) ORDER BY appeal_id), '[]'::jsonb) FROM trust.appeals WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id)) INTO result;
    SELECT array_agg(DISTINCT field.value::uuid) INTO actors
    FROM jsonb_each(result) groups CROSS JOIN LATERAL jsonb_array_elements(groups.value) item
    CROSS JOIN LATERAL jsonb_each_text(item) field(key,value)
    WHERE field.key LIKE '%user_id' AND field.value IS NOT NULL;
    RETURN result || jsonb_build_object('names',iam_api.admin_demand_participant_names_v1(actors));
END
$function$;
ALTER FUNCTION trust_api.admin_demand_facts_v1(uuid,uuid) OWNER TO trust_schema_owner;
REVOKE ALL ON FUNCTION trust_api.admin_demand_facts_v1(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.admin_demand_facts_v1(uuid,uuid) TO iam_app;

-- BEGIN ADMIN TIMELINE DEPENDENCY REPIN
SET LOCAL search_path = pg_catalog, trust_meta;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'trust_migration_runner'
       OR current_user IS DISTINCT FROM 'trust_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'TRUST_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

DO $trust23_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 23
                AND min_app_compatible_version = 23
                AND max_app_compatible_version = 23
                AND required_iam_schema_version = 47
                AND required_demand_schema_version = 15
                AND required_iam_contract_sha256 = decode(
                    'abc9924571cecb3027ec29ee7fdf34596bf8682d8b41c62d033964ec3094400f',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    'ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    '6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2',
                    'hex'
                )
                AND event_contract_sha256 = decode(
                    'a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582',
                    'hex'
                )
                AND report_contract_sha256 = decode(
                    '29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278',
                    'hex'
                )
                AND triage_contract_sha256 = decode(
                    'de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084',
                    'hex'
                )
                AND appeal_api_contract_sha256 = decode(
                    'ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46',
                    'hex'
                )
                AND appeal_event_contract_sha256 = decode(
                    '7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba',
                    'hex'
                )
                AND appeal_application_contract_sha256 = decode(
                    '3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223',
                    'hex'
                )
                AND appeal_review_contract_sha256 = decode(
                    '08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b',
                    'hex'
                )
                AND combined_contract_sha256 = decode(
                    '96ff2fd0b3e32143b4570fff008948d13fbe5f537a746712878bd2cca77255fa',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '0576a8872e2c9783e345d521f151b3d6f9bd7e1d9ee125ee1ef3810e01a05e47',
                    'hex'
                )
                AND generated_at IS NOT NULL
            ),
            true
        )
    INTO STRICT contract_count, contract_is_exact
    FROM trust_meta.schema_contracts;

    IF contract_count NOT BETWEEN 0 AND 1
       OR (contract_count = 1 AND contract_is_exact IS NOT TRUE)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST23_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust23_contract_baseline$;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 24
    AND min_app_compatible_version = 24
    AND max_app_compatible_version = 24
    AND required_iam_schema_version = 48
    AND required_demand_schema_version = 16
),
ADD CONSTRAINT ck_trust_schema_contract_hashes CHECK (
    octet_length(required_iam_contract_sha256) = 32
    AND octet_length(required_demand_contract_sha256) = 32
    AND octet_length(api_contract_sha256) = 32
    AND octet_length(event_contract_sha256) = 32
    AND octet_length(report_contract_sha256) = 32
    AND octet_length(triage_contract_sha256) = 32
    AND octet_length(appeal_api_contract_sha256) = 32
    AND octet_length(appeal_event_contract_sha256) = 32
    AND octet_length(appeal_application_contract_sha256) = 32
    AND octet_length(appeal_review_contract_sha256) = 32
    AND octet_length(combined_contract_sha256) = 32
    AND octet_length(migration_manifest_sha256) = 32
    AND required_iam_contract_sha256 = decode(
        '616cda6eac1e9f853be019f5790584e16826c295be08d10201f947e923a5ba3f',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        '3362a606f35221c61cfb302ee54ce13bea450a44a02b33217606003a89c569ce',
        'hex'
    )
    AND api_contract_sha256 = decode(
        '6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2',
        'hex'
    )
    AND event_contract_sha256 = decode(
        'a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582',
        'hex'
    )
    AND report_contract_sha256 = decode(
        '29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278',
        'hex'
    )
    AND triage_contract_sha256 = decode(
        'de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084',
        'hex'
    )
    AND appeal_api_contract_sha256 = decode(
        'ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46',
        'hex'
    )
    AND appeal_event_contract_sha256 = decode(
        '7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba',
        'hex'
    )
    AND appeal_application_contract_sha256 = decode(
        '3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223',
        'hex'
    )
    AND appeal_review_contract_sha256 = decode(
        '08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b',
        'hex'
    )
    AND combined_contract_sha256 = sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:combined-contract:v2',
        encode(required_iam_contract_sha256, 'hex'),
        encode(required_demand_contract_sha256, 'hex'),
        encode(api_contract_sha256, 'hex'),
        encode(event_contract_sha256, 'hex'),
        encode(report_contract_sha256, 'hex'),
        encode(triage_contract_sha256, 'hex'),
        encode(appeal_api_contract_sha256, 'hex'),
        encode(appeal_event_contract_sha256, 'hex'),
        encode(appeal_application_contract_sha256, 'hex'),
        encode(appeal_review_contract_sha256, 'hex'),
        encode(migration_manifest_sha256, 'hex')
    ), 'UTF8'))
);
