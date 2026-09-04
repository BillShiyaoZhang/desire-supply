-- Metadata-only Trust dependency repin from IAM0046 to IAM0047.
-- Every published Trust runtime ABI and the Demand0015 dependency stay frozen.

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

DO $trust22_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 22
                AND min_app_compatible_version = 22
                AND max_app_compatible_version = 22
                AND required_iam_schema_version = 46
                AND required_demand_schema_version = 15
                AND required_iam_contract_sha256 = decode(
                    '14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d',
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
                    '68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8',
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
            MESSAGE = 'TRUST22_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust22_contract_baseline$;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 23
    AND min_app_compatible_version = 23
    AND max_app_compatible_version = 23
    AND required_iam_schema_version = 47
    AND required_demand_schema_version = 15
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
