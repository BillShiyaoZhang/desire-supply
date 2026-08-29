-- Metadata-only Trust direct dependency repin from reviewed IAM0037 to
-- IAM0038. Demand0010 and its published transitive IAM0037 ABI stay frozen.

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

DO $trust7_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 7
                AND min_app_compatible_version = 7
                AND max_app_compatible_version = 7
                AND required_iam_schema_version = 37
                AND required_demand_schema_version = 10
                AND required_iam_contract_sha256 = decode(
                    '595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    '27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    'f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed',
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
                    '2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522',
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
                    'ab857f25969d17afe63886afe136cda10814e538517c54c180503b82f5785c1b',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124',
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
            MESSAGE = 'TRUST7_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust7_contract_baseline$;

DO $trust7_constraint_baseline$
DECLARE
    constraints_are_exact boolean;
BEGIN
    SELECT
        count(*) = 2
        AND count(*) FILTER (
            WHERE constraint_row.conname = 'ck_trust_schema_contract_versions'
        ) = 1
        AND count(*) FILTER (
            WHERE constraint_row.conname = 'ck_trust_schema_contract_hashes'
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
                        'd9e87f27d46d52cd147b1a4ed7564b135f918295589a8f910ceaa7464ad2cbf4',
                        'hex'
                    )
                WHEN 'ck_trust_schema_contract_hashes' THEN
                    sha256(convert_to(pg_get_constraintdef(
                        constraint_row.oid,
                        true
                    ), 'UTF8')) = decode(
                        '9864baeaebc04bcc3928075af4d7c00f5b85badc53866aea888e46c7168baef1',
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
    WHERE constraint_row.conrelid = 'trust_meta.schema_contracts'::regclass
      AND constraint_row.conname IN (
        'ck_trust_schema_contract_versions',
        'ck_trust_schema_contract_hashes'
      );

    IF constraints_are_exact IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST7_SCHEMA_CONSTRAINT_BASELINE_MISMATCH';
    END IF;
END
$trust7_constraint_baseline$;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 8
    AND min_app_compatible_version = 8
    AND max_app_compatible_version = 8
    AND required_iam_schema_version = 38
    AND required_demand_schema_version = 10
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
        '908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        '27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113',
        'hex'
    )
    AND api_contract_sha256 = decode(
        'f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed',
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
        '2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522',
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
