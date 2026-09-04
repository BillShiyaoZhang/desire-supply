-- Metadata-only Matching dependency repin to IAM0047 and Trust0023.
-- The runner publishes the current exact dependency pins and manifest in the
-- same transaction as this ledger entry, including upgrades from older heads.
-- Every published Matching runtime ABI and existing data stay unchanged.

SET LOCAL search_path = pg_catalog, matching_meta;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'matching_migration_runner'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'MATCHING_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;
