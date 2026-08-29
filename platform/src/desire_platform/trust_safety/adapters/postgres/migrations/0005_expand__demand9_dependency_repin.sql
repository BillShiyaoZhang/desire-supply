-- Metadata-only Trust dependency repin from the frozen Demand0008 boundary
-- to the reviewed Demand0009 compatibility projection.

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

DO $trust4_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 4
                AND min_app_compatible_version = 4
                AND max_app_compatible_version = 4
                AND required_iam_schema_version = 36
                AND required_demand_schema_version = 8
                AND required_iam_contract_sha256 = decode(
                    '8be48226b6fb409f442c6331dffcebc69435d401a75aa423614a9b7e60eb86a4',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    '7d67863b0ce45bf19011d7ed1975fb5a73068f257c13083274689b2c8aa160f3',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    '14572f7768f31e9ced0b6ede09eb6eea1da3d2d4abd1c6d80cc4229c28e158bd',
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
                    'e85d905e407679665e7bea0008253bc4ec2bd941c4442964016caeb4ce62ffa7',
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
                    '9829628dfb25415cb5b8880af131011ab61730839d05a836c4d2b5601521ae08',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8',
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
            MESSAGE = 'TRUST4_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust4_contract_baseline$;

DO $trust4_constraint_baseline$
DECLARE
    constraints_are_exact boolean;
BEGIN
    SELECT
        count(*) = 2
        AND count(*) FILTER (
            WHERE constraint_row.conname
                = 'ck_trust_schema_contract_versions'
        ) = 1
        AND count(*) FILTER (
            WHERE constraint_row.conname
                = 'ck_trust_schema_contract_hashes'
        ) = 1
        AND bool_and(
            relation.relkind = 'r'
            AND owner_role.rolname = 'trust_schema_owner'
            AND constraint_row.contype = 'c'
            AND constraint_row.convalidated
            AND NOT constraint_row.condeferrable
            AND NOT constraint_row.condeferred
            AND constraint_row.conislocal
            AND constraint_row.coninhcount = 0
            AND NOT constraint_row.connoinherit
            AND CASE constraint_row.conname
                WHEN 'ck_trust_schema_contract_versions' THEN
                    sha256(convert_to(pg_get_constraintdef(
                        constraint_row.oid,
                        true
                    ), 'UTF8')) = decode(
                        'a3ade02769b8a31ae0fe17e6f00099476352a6f4d0c1fe039d3e8a3b317db931',
                        'hex'
                    )
                WHEN 'ck_trust_schema_contract_hashes' THEN
                    sha256(convert_to(pg_get_constraintdef(
                        constraint_row.oid,
                        true
                    ), 'UTF8')) = decode(
                        'e692f199880e8367f9224c8b13604f15caf87066f4430f2407dbe5573d8c17a4',
                        'hex'
                    )
                ELSE false
            END
        )
    INTO STRICT constraints_are_exact
    FROM pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = constraint_row.conrelid
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = relation.relowner
    WHERE constraint_row.conrelid
        = 'trust_meta.schema_contracts'::regclass
      AND constraint_row.conname IN (
        'ck_trust_schema_contract_versions',
        'ck_trust_schema_contract_hashes'
      );

    IF constraints_are_exact IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST4_SCHEMA_CONSTRAINT_BASELINE_MISMATCH';
    END IF;
END
$trust4_constraint_baseline$;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 5
    AND min_app_compatible_version = 5
    AND max_app_compatible_version = 5
    AND required_iam_schema_version = 36
    AND required_demand_schema_version = 9
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
        '8be48226b6fb409f442c6331dffcebc69435d401a75aa423614a9b7e60eb86a4',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        '2ce5929295d30a91b55d9d907e0031707461498d3380e9e9e2e449eec06f9328',
        'hex'
    )
    AND api_contract_sha256 = decode(
        '14572f7768f31e9ced0b6ede09eb6eea1da3d2d4abd1c6d80cc4229c28e158bd',
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
        'e85d905e407679665e7bea0008253bc4ec2bd941c4442964016caeb4ce62ffa7',
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
