-- Permit the reviewed Demand system workload to request Matching without
-- borrowing a completed human reviewer assignment. The command remains
-- idempotent through an exact SYSTEM receipt and uses the existing workload
-- principal/authority marker pair in demand.receipt_key_policy.

SET LOCAL search_path = pg_catalog, demand;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_migration_runner'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
       OR pg_catalog.to_regclass('demand.command_receipts') IS NULL
       OR pg_catalog.to_regclass('demand.demand_funding_markers') IS NULL
       OR pg_catalog.to_regclass('demand.matching_requests') IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND14_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

ALTER TABLE demand.command_receipts
DROP CONSTRAINT ck_demand_receipt_transport;

ALTER TABLE demand.command_receipts
ADD CONSTRAINT ck_demand_receipt_transport CHECK (
    principal_kind IN ('USER', 'SYSTEM')
    AND command_version = 1
    AND http_method = 'POST'
    AND left(canonical_path, 4) = '/v1/'
    AND canonicalization_version = 'demand-command-json-v1'
);

GRANT SELECT ON demand.demand_funding_markers TO demand_system;
GRANT SELECT, INSERT ON demand.matching_requests TO demand_system;
GRANT SELECT, INSERT, UPDATE ON demand.command_receipts TO demand_system;

CREATE POLICY rls_demand_funding_system_matching
ON demand.demand_funding_markers
FOR SELECT TO demand_system
USING (
    organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
    AND NULLIF(current_setting('app.operation', true), '') = 'REQUEST_MATCHING'
);

CREATE POLICY rls_demand_matching_system_read
ON demand.matching_requests
FOR SELECT TO demand_system
USING (
    organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
    AND NULLIF(current_setting('app.operation', true), '') = 'REQUEST_MATCHING'
);

CREATE POLICY rls_demand_matching_system_insert
ON demand.matching_requests
FOR INSERT TO demand_system
WITH CHECK (
    organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
    AND NULLIF(current_setting('app.operation', true), '') = 'REQUEST_MATCHING'
);

CREATE POLICY rls_demand_receipt_system_matching
ON demand.command_receipts
FOR ALL TO demand_system
USING (
    principal_kind = 'SYSTEM'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND command_name = 'RequestMatching'
    AND (
        target_id IS NULL
        OR target_id::text
            = NULLIF(current_setting('app.demand_id', true), '')
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
    AND NULLIF(current_setting('app.operation', true), '') = 'REQUEST_MATCHING'
)
WITH CHECK (
    principal_kind = 'SYSTEM'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND command_name = 'RequestMatching'
    AND (
        target_id IS NULL
        OR target_id::text
            = NULLIF(current_setting('app.demand_id', true), '')
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_SYSTEM'
    AND NULLIF(current_setting('app.operation', true), '') = 'REQUEST_MATCHING'
);

DO $assert$
DECLARE
    receipt_check text;
BEGIN
    SELECT pg_catalog.pg_get_constraintdef(constraint_row.oid, true)
    INTO receipt_check
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = 'demand.command_receipts'::regclass
      AND constraint_row.conname = 'ck_demand_receipt_transport';

    IF receipt_check NOT LIKE '%principal_kind%USER%SYSTEM%'
       OR NOT pg_catalog.has_table_privilege(
            'demand_system',
            'demand.demand_funding_markers',
            'SELECT'
       )
       OR NOT pg_catalog.has_table_privilege(
            'demand_system',
            'demand.matching_requests',
            'SELECT,INSERT'
       )
       OR NOT pg_catalog.has_table_privilege(
            'demand_system',
            'demand.command_receipts',
            'SELECT,INSERT,UPDATE'
       )
       OR (
            SELECT count(*)
            FROM pg_catalog.pg_policy AS policy
            WHERE policy.polname IN (
                'rls_demand_funding_system_matching',
                'rls_demand_matching_system_read',
                'rls_demand_matching_system_insert',
                'rls_demand_receipt_system_matching'
            )
       ) IS DISTINCT FROM 4::bigint
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand14 system RequestMatching assertion failed';
    END IF;
END
$assert$;
