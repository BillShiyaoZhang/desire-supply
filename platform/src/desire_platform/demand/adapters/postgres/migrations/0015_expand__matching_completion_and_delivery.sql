-- Atomic Matching completion and a durable, fenced MatchingRequested handoff.
-- Runtime roles receive EXECUTE only; FORCE RLS and the fixed programs below
-- are the entire production authority surface.

SET LOCAL ROLE demand_schema_owner;
SET LOCAL search_path = pg_catalog, demand;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_migration_runner'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
       OR pg_catalog.to_regclass('demand.demands') IS NULL
       OR pg_catalog.to_regclass('demand.demand_versions') IS NULL
       OR pg_catalog.to_regclass('demand.demand_funding_markers') IS NULL
       OR pg_catalog.to_regclass('demand.matching_requests') IS NULL
       OR pg_catalog.to_regclass('infra.outbox_events') IS NULL
       OR pg_catalog.to_regclass('audit.audit_events') IS NULL
       OR pg_catalog.to_regrole('demand_matching') IS NULL
       OR pg_catalog.to_regrole('matching_coordinator') IS NULL
       OR pg_catalog.to_regrole('matching_schema_owner') IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND15_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

CREATE TABLE demand.matching_runtime_policy (
    singleton_key boolean PRIMARY KEY,
    retained_lease_digest_key_ids text[] NOT NULL,
    minimum_lease_seconds integer NOT NULL,
    maximum_lease_seconds integer NOT NULL,
    maximum_delivery_attempts integer NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_demand_matching_runtime_policy_singleton
        CHECK (singleton_key),
    CONSTRAINT ck_demand_matching_runtime_policy_shape CHECK (
        array_ndims(retained_lease_digest_key_ids) = 1
        AND array_lower(retained_lease_digest_key_ids, 1) = 1
        AND cardinality(retained_lease_digest_key_ids) BETWEEN 1 AND 4
        AND minimum_lease_seconds BETWEEN 1 AND 3600
        AND maximum_lease_seconds BETWEEN minimum_lease_seconds AND 86400
        AND maximum_delivery_attempts BETWEEN 1 AND 100
    )
);

INSERT INTO demand.matching_runtime_policy (
    singleton_key,
    retained_lease_digest_key_ids,
    minimum_lease_seconds,
    maximum_lease_seconds,
    maximum_delivery_attempts,
    updated_at
) VALUES (
    true,
    ARRAY['demand-matching-delivery-lease-v1']::text[],
    5,
    900,
    10,
    transaction_timestamp()
);

CREATE TABLE demand.matching_requested_deliveries (
    delivery_id uuid PRIMARY KEY,
    source_event_id uuid NOT NULL,
    source_occurred_at timestamptz NOT NULL,
    event_type varchar(96) NOT NULL,
    schema_version integer NOT NULL,
    aggregate_type varchar(64) NOT NULL,
    source_aggregate_id uuid NOT NULL,
    source_aggregate_version bigint NOT NULL,
    original_actor_user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    envelope_sha256 bytea NOT NULL,
    demand_content_sha256 bytea NOT NULL,
    demand_aggregate_version bigint NOT NULL,
    matching_request_id uuid NOT NULL,
    matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    composite_rule_requirement_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    matching_selector_digest bytea NOT NULL,
    rule_requirement_sha256 bytea NOT NULL,
    authorization_digest bytea NOT NULL,
    authorized_workload_principal_id uuid NOT NULL,
    status varchar(16) NOT NULL,
    attempt_count integer NOT NULL,
    fencing_generation bigint NOT NULL,
    active_workload_id uuid NULL,
    active_authority_marker_sha256 bytea NULL,
    lease_digest_key_id text NULL,
    lease_digest bytea NULL,
    lease_until timestamptz NULL,
    next_available_at timestamptz NULL,
    matching_attempt_id uuid NULL,
    last_failure_fencing_generation bigint NULL,
    last_failure_lease_digest_key_id text NULL,
    last_failure_lease_digest bytea NULL,
    last_failure_code varchar(64) NULL,
    last_retry_available_at timestamptz NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    terminal_at timestamptz NULL,
    CONSTRAINT uq_demand_matching_delivery_source_event UNIQUE (
        source_event_id
    ),
    CONSTRAINT uq_demand_matching_delivery_id_source UNIQUE (
        delivery_id,
        source_event_id
    ),
    CONSTRAINT uq_demand_matching_delivery_source_tuple UNIQUE (
        source_event_id,
        source_aggregate_id,
        source_aggregate_version,
        organization_id,
        demand_id,
        demand_version_id
    ),
    CONSTRAINT ck_demand_matching_delivery_projection CHECK (
        event_type = 'MatchingRequested'
        AND schema_version = 1
        AND aggregate_type = 'Demand'
        AND source_aggregate_id = demand_id
        AND source_aggregate_version = demand_aggregate_version
        AND source_aggregate_version >= 1
        AND demand_aggregate_version >= 1
        AND octet_length(envelope_sha256) = 32
        AND octet_length(demand_content_sha256) = 32
        AND octet_length(matching_selector_digest) = 32
        AND octet_length(rule_requirement_sha256) = 32
        AND octet_length(authorization_digest) = 32
    ),
    CONSTRAINT ck_demand_matching_delivery_state CHECK (
        status IN ('AVAILABLE', 'LEASED', 'COMPLETED', 'FAILED')
        AND attempt_count >= 0
        AND fencing_generation >= 0
        AND updated_at >= created_at
        AND (
            (status = 'AVAILABLE'
                AND active_workload_id IS NULL
                AND active_authority_marker_sha256 IS NULL
                AND lease_digest_key_id IS NULL
                AND lease_digest IS NULL
                AND lease_until IS NULL
                AND next_available_at IS NOT NULL
                AND matching_attempt_id IS NULL
                AND completed_at IS NULL
                AND terminal_at IS NULL)
            OR
            (status = 'LEASED'
                AND active_workload_id IS NOT NULL
                AND octet_length(active_authority_marker_sha256) = 32
                AND NULLIF(lease_digest_key_id, '') IS NOT NULL
                AND octet_length(lease_digest) = 32
                AND lease_until IS NOT NULL
                AND next_available_at IS NULL
                AND matching_attempt_id IS NULL
                AND completed_at IS NULL
                AND terminal_at IS NULL)
            OR
            (status = 'COMPLETED'
                AND active_workload_id IS NOT NULL
                AND octet_length(active_authority_marker_sha256) = 32
                AND NULLIF(lease_digest_key_id, '') IS NOT NULL
                AND octet_length(lease_digest) = 32
                AND lease_until IS NOT NULL
                AND next_available_at IS NULL
                AND matching_attempt_id IS NOT NULL
                AND completed_at IS NOT NULL
                AND terminal_at = completed_at)
            OR
            (status = 'FAILED'
                AND active_workload_id IS NULL
                AND active_authority_marker_sha256 IS NULL
                AND lease_digest_key_id IS NULL
                AND lease_digest IS NULL
                AND lease_until IS NULL
                AND next_available_at IS NULL
                AND matching_attempt_id IS NULL
                AND completed_at IS NULL
                AND terminal_at IS NOT NULL)
        )
        AND (
            (last_failure_fencing_generation IS NULL
                AND last_failure_lease_digest_key_id IS NULL
                AND last_failure_lease_digest IS NULL
                AND last_failure_code IS NULL
                AND last_retry_available_at IS NULL)
            OR
            (last_failure_fencing_generation >= 1
                AND NULLIF(last_failure_lease_digest_key_id, '') IS NOT NULL
                AND octet_length(last_failure_lease_digest) = 32
                AND last_failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
                AND last_retry_available_at IS NOT NULL)
        )
    )
);

CREATE INDEX ix_demand_matching_delivery_claim
ON demand.matching_requested_deliveries (
    source_occurred_at,
    source_event_id
)
WHERE status IN ('AVAILABLE', 'LEASED');

CREATE TABLE demand.matching_delivery_claim_receipts (
    lease_digest_key_id text NOT NULL,
    lease_digest bytea NOT NULL,
    delivery_id uuid NOT NULL,
    source_event_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    fencing_generation bigint NOT NULL,
    lease_until timestamptz NOT NULL,
    attempt_count integer NOT NULL,
    claimed_at timestamptz NOT NULL,
    CONSTRAINT pk_demand_matching_delivery_claim_receipt PRIMARY KEY (
        lease_digest_key_id,
        lease_digest
    ),
    CONSTRAINT uq_demand_matching_delivery_claim_fence UNIQUE (
        delivery_id,
        fencing_generation
    ),
    CONSTRAINT fk_demand_matching_delivery_claim FOREIGN KEY (
        delivery_id,
        source_event_id
    ) REFERENCES demand.matching_requested_deliveries (
        delivery_id,
        source_event_id
    ),
    CONSTRAINT ck_demand_matching_delivery_claim_receipt_shape CHECK (
        NULLIF(lease_digest_key_id, '') IS NOT NULL
        AND octet_length(lease_digest) = 32
        AND octet_length(authority_marker_sha256) = 32
        AND fencing_generation >= 1
        AND attempt_count >= 1
        AND lease_until > claimed_at
    )
);

CREATE TABLE demand.complete_selection_receipts (
    completion_command_id uuid PRIMARY KEY,
    choose_receipt_id uuid NOT NULL UNIQUE,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    expected_demand_version bigint NOT NULL,
    completed_demand_version bigint NOT NULL,
    demand_version_id uuid NOT NULL,
    matching_request_id uuid NOT NULL,
    expected_matching_request_version bigint NOT NULL,
    completed_matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    original_actor_user_id uuid NOT NULL,
    coordinator_workload_id uuid NOT NULL,
    coordinator_authority_marker_sha256 bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_hash bytea NOT NULL,
    demand_matched_event_id uuid NOT NULL UNIQUE,
    correlation_id uuid NOT NULL,
    trace_id uuid NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT ck_demand_complete_selection_receipt_shape CHECK (
        expected_demand_version >= 1
        AND completed_demand_version = expected_demand_version + 1
        AND expected_matching_request_version >= 1
        AND completed_matching_request_version
            = expected_matching_request_version + 1
        AND octet_length(coordinator_authority_marker_sha256) = 32
        AND NULLIF(payload_hash_key_id, '') IS NOT NULL
        AND octet_length(payload_hash) = 32
    )
);

CREATE TABLE demand.close_matching_without_selection_receipts (
    completion_command_id uuid PRIMARY KEY,
    close_receipt_id uuid NOT NULL UNIQUE,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    expected_demand_version bigint NOT NULL,
    completed_demand_version bigint NOT NULL,
    demand_version_id uuid NOT NULL,
    matching_request_id uuid NOT NULL,
    expected_matching_request_version bigint NOT NULL,
    completed_matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    original_actor_user_id uuid NOT NULL,
    coordinator_workload_id uuid NOT NULL,
    coordinator_authority_marker_sha256 bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_hash bytea NOT NULL,
    demand_closed_event_id uuid NOT NULL UNIQUE,
    correlation_id uuid NOT NULL,
    trace_id uuid NOT NULL,
    reason_code varchar(64) NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT ck_demand_close_without_selection_receipt_shape CHECK (
        expected_demand_version >= 1
        AND completed_demand_version = expected_demand_version + 1
        AND expected_matching_request_version >= 1
        AND completed_matching_request_version
            = expected_matching_request_version + 1
        AND octet_length(coordinator_authority_marker_sha256) = 32
        AND NULLIF(payload_hash_key_id, '') IS NOT NULL
        AND octet_length(payload_hash) = 32
        AND reason_code ~ '^[A-Z][A-Z0-9_]{1,63}$'
    )
);

CREATE FUNCTION demand.protect_matching_delivery_projection_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    IF NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
       OR NEW.source_event_id IS DISTINCT FROM OLD.source_event_id
       OR NEW.source_occurred_at IS DISTINCT FROM OLD.source_occurred_at
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.source_aggregate_id IS DISTINCT FROM OLD.source_aggregate_id
       OR NEW.source_aggregate_version IS DISTINCT FROM OLD.source_aggregate_version
       OR NEW.original_actor_user_id
            IS DISTINCT FROM OLD.original_actor_user_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.demand_id IS DISTINCT FROM OLD.demand_id
       OR NEW.demand_version_id IS DISTINCT FROM OLD.demand_version_id
       OR NEW.envelope_sha256 IS DISTINCT FROM OLD.envelope_sha256
       OR NEW.demand_content_sha256 IS DISTINCT FROM OLD.demand_content_sha256
       OR NEW.demand_aggregate_version IS DISTINCT FROM OLD.demand_aggregate_version
       OR NEW.matching_request_id IS DISTINCT FROM OLD.matching_request_id
       OR NEW.matching_request_version IS DISTINCT FROM OLD.matching_request_version
       OR NEW.funding_id IS DISTINCT FROM OLD.funding_id
       OR NEW.composite_rule_requirement_id
            IS DISTINCT FROM OLD.composite_rule_requirement_id
       OR NEW.matching_rule_bundle_id IS DISTINCT FROM OLD.matching_rule_bundle_id
       OR NEW.matching_selector_digest IS DISTINCT FROM OLD.matching_selector_digest
       OR NEW.rule_requirement_sha256 IS DISTINCT FROM OLD.rule_requirement_sha256
       OR NEW.authorization_digest IS DISTINCT FROM OLD.authorization_digest
       OR NEW.authorized_workload_principal_id
            IS DISTINCT FROM OLD.authorized_workload_principal_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'DEMAND_MATCHING_DELIVERY_PROJECTION_IMMUTABLE';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_demand_matching_delivery_projection
BEFORE UPDATE ON demand.matching_requested_deliveries
FOR EACH ROW EXECUTE FUNCTION demand.protect_matching_delivery_projection_v1();

CREATE TRIGGER trg_demand_matching_claim_receipt_immutable
BEFORE UPDATE OR DELETE ON demand.matching_delivery_claim_receipts
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE TRIGGER trg_demand_complete_selection_receipt_immutable
BEFORE UPDATE OR DELETE ON demand.complete_selection_receipts
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE TRIGGER trg_demand_close_without_selection_receipt_immutable
BEFORE UPDATE OR DELETE ON demand.close_matching_without_selection_receipts
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

ALTER TABLE demand.matching_runtime_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_runtime_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_requested_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_requested_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_delivery_claim_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.matching_delivery_claim_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.complete_selection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.complete_selection_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.close_matching_without_selection_receipts
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.close_matching_without_selection_receipts
    FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_demand_matching_runtime_policy_definer
ON demand.matching_runtime_policy
FOR SELECT TO demand_schema_owner
USING (
    singleton_key
    AND session_user IN ('demand_matching', 'matching_coordinator')
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'DEMAND_MATCH_DELIVERY',
        'DEMAND_MATCHING_COORDINATOR'
    )
);

CREATE POLICY rls_demand_matching_delivery_definer
ON demand.matching_requested_deliveries
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_MATCHING_REQUESTED_DELIVERY',
        'COMPLETE_MATCHING_REQUESTED_DELIVERY',
        'FAIL_MATCHING_REQUESTED_DELIVERY'
    )
)
WITH CHECK (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_MATCHING_REQUESTED_DELIVERY',
        'COMPLETE_MATCHING_REQUESTED_DELIVERY',
        'FAIL_MATCHING_REQUESTED_DELIVERY'
    )
);

CREATE POLICY rls_demand_matching_claim_receipt_definer
ON demand.matching_delivery_claim_receipts
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
)
WITH CHECK (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
);

CREATE POLICY rls_demand_complete_selection_receipt_definer
ON demand.complete_selection_receipts
FOR ALL TO demand_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND completion_command_id::text
        = NULLIF(current_setting('app.command_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'COMPLETE_SELECTION'
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND completion_command_id::text
        = NULLIF(current_setting('app.command_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'COMPLETE_SELECTION'
);

CREATE POLICY rls_demand_close_without_selection_receipt_definer
ON demand.close_matching_without_selection_receipts
FOR ALL TO demand_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND completion_command_id::text
        = NULLIF(current_setting('app.command_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'COMPLETE_SELECTION'
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND completion_command_id::text
        = NULLIF(current_setting('app.command_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'COMPLETE_SELECTION'
);

CREATE POLICY rls_demand_matching_delivery_root_definer
ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REQUESTED_DELIVERY'
    AND status = 'MATCHING'
);

CREATE POLICY rls_demand_matching_delivery_version_definer
ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REQUESTED_DELIVERY'
);

CREATE POLICY rls_demand_matching_delivery_funding_definer
ON demand.demand_funding_markers
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REQUESTED_DELIVERY'
    AND status = 'SECURED'
);

CREATE POLICY rls_demand_matching_delivery_request_definer
ON demand.matching_requests
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REQUESTED_DELIVERY'
    AND status = 'OPEN'
    AND authorized_workload_principal_id::text
        = NULLIF(current_setting('app.workload_id', true), '')
    AND authorization_digest = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
);

CREATE POLICY rls_demand_matching_coordinator_root_definer
ON demand.demands
FOR ALL TO demand_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
);

CREATE POLICY rls_demand_matching_coordinator_funding_definer
ON demand.demand_funding_markers
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND status = 'SECURED'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
);

CREATE POLICY rls_demand_matching_coordinator_request_definer
ON demand.matching_requests
FOR ALL TO demand_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
)
WITH CHECK (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
);

SET LOCAL ROLE schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO demand_schema_owner;
GRANT SELECT ON infra.outbox_events TO demand_schema_owner;
GRANT INSERT ON audit.audit_events TO demand_schema_owner;
GRANT INSERT ON infra.outbox_events TO demand_schema_owner;

CREATE POLICY rls_demand_matching_requested_outbox_definer
ON infra.outbox_events
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_matching'
    AND event_type = 'MatchingRequested'
    AND schema_version = 1
    AND aggregate_type = 'Demand'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCH_DELIVERY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REQUESTED_DELIVERY'
);

CREATE POLICY rls_demand_matching_coordinator_audit_definer
ON audit.audit_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'matching_coordinator'
    AND actor_kind = 'SYSTEM'
    AND actor_id::text = NULLIF(current_setting('app.workload_id', true), '')
    AND original_actor_id::text
        = NULLIF(current_setting('app.actor_user_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND target_kind = 'Demand'
    AND target_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND command_id::text = NULLIF(current_setting('app.command_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
);

CREATE POLICY rls_demand_matching_coordinator_outbox_definer
ON infra.outbox_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'matching_coordinator'
    AND actor_kind = 'SYSTEM'
    AND actor_id::text = NULLIF(current_setting('app.workload_id', true), '')
    AND original_actor_id::text
        = NULLIF(current_setting('app.actor_user_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND aggregate_type = 'Demand'
    AND aggregate_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'COMPLETE_SELECTION',
        'CLOSE_MATCHING_WITHOUT_SELECTION'
    )
);

CREATE POLICY rls_demand_matching_coordinator_outbox_read_definer
ON infra.outbox_events
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND aggregate_type = 'Demand'
    AND aggregate_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND event_type IN (
        'DemandMatched',
        'DemandMatchingClosedWithoutSelection'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'COMPLETE_SELECTION'
);

SET LOCAL ROLE demand_schema_owner;

CREATE FUNCTION demand.assert_matching_delivery_context_v1(
    exact_operation text
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_matching'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_operation NOT IN (
            'CLAIM_MATCHING_REQUESTED_DELIVERY',
            'COMPLETE_MATCHING_REQUESTED_DELIVERY',
            'FAIL_MATCHING_REQUESTED_DELIVERY'
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_MATCH_DELIVERY'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.workload_id', true), '') IS NULL
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_ACCESS_DENIED';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION demand.assert_matching_delivery_context_v1(text)
FROM PUBLIC;

CREATE FUNCTION demand.assert_matching_coordinator_context_v1(
    exact_completion_command_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_original_actor_user_id uuid,
    exact_coordinator_workload_id uuid,
    exact_coordinator_authority_marker_sha256 bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'matching_coordinator'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_MATCHING_COORDINATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'COMPLETE_SELECTION'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_original_actor_user_id::text
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM exact_coordinator_workload_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_completion_command_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(
                exact_coordinator_authority_marker_sha256,
                'hex'
            ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_MATCHING_COORDINATOR_ACCESS_DENIED';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION demand.assert_matching_coordinator_context_v1(
    uuid, uuid, uuid, uuid, uuid, bytea
) FROM PUBLIC;

CREATE FUNCTION demand_api.claim_matching_requested_delivery_v1(
    workload_id uuid,
    authority_marker_sha256 bytea,
    lease_digest_key_id text,
    lease_digest bytea,
    lease_seconds integer
)
RETURNS TABLE (
    delivery_id uuid,
    source_event_id uuid,
    fencing_generation bigint,
    lease_until timestamptz,
    event_type varchar,
    schema_version integer,
    aggregate_type varchar,
    source_aggregate_id uuid,
    source_aggregate_version bigint,
    original_actor_user_id uuid,
    organization_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    envelope_sha256 bytea,
    demand_content_sha256 bytea,
    demand_aggregate_version bigint,
    matching_request_id uuid,
    matching_request_version bigint,
    funding_id uuid,
    composite_rule_requirement_id uuid,
    matching_rule_bundle_id uuid,
    matching_selector_digest bytea,
    rule_requirement_sha256 bytea,
    authorization_digest bytea,
    authorized_workload_principal_id uuid,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand
AS $function$
#variable_conflict use_variable
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    policy_row demand.matching_runtime_policy%ROWTYPE;
    prior_claim demand.matching_delivery_claim_receipts%ROWTYPE;
    delivery_row demand.matching_requested_deliveries%ROWTYPE;
    now_at timestamptz := transaction_timestamp();
    is_replay boolean := false;
BEGIN
    PERFORM demand.assert_matching_delivery_context_v1(
        'CLAIM_MATCHING_REQUESTED_DELIVERY'
    );
    IF workload_id IS NULL OR workload_id = zero_uuid
       OR octet_length(authority_marker_sha256) <> 32
       OR NULLIF(lease_digest_key_id, '') IS NULL
       OR lease_digest_key_id <> btrim(lease_digest_key_id)
       OR octet_length(lease_digest_key_id) > 128
       OR octet_length(lease_digest) <> 32
       OR lease_seconds IS NULL
       OR NULLIF(current_setting('app.workload_id', true), '')
            IS DISTINCT FROM workload_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(authority_marker_sha256, 'hex') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    SELECT policy.* INTO STRICT policy_row
    FROM demand.matching_runtime_policy AS policy
    WHERE policy.singleton_key;
    IF lease_digest_key_id <> ALL(policy_row.retained_lease_digest_key_ids)
       OR lease_seconds NOT BETWEEN policy_row.minimum_lease_seconds
            AND policy_row.maximum_lease_seconds THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_KEY_POLICY_UNAVAILABLE';
    END IF;

    SELECT receipt.* INTO prior_claim
    FROM demand.matching_delivery_claim_receipts AS receipt
    WHERE receipt.lease_digest_key_id = lease_digest_key_id
      AND receipt.lease_digest = lease_digest;
    IF FOUND THEN
        SELECT delivery.* INTO STRICT delivery_row
        FROM demand.matching_requested_deliveries AS delivery
        WHERE delivery.delivery_id = prior_claim.delivery_id;
        IF prior_claim.workload_id IS DISTINCT FROM workload_id
           OR prior_claim.authority_marker_sha256
                IS DISTINCT FROM authority_marker_sha256
           OR delivery_row.source_event_id
                IS DISTINCT FROM prior_claim.source_event_id
           OR delivery_row.fencing_generation
                IS DISTINCT FROM prior_claim.fencing_generation
           OR delivery_row.active_workload_id IS DISTINCT FROM workload_id
           OR delivery_row.active_authority_marker_sha256
                IS DISTINCT FROM authority_marker_sha256
           OR delivery_row.lease_digest_key_id
                IS DISTINCT FROM lease_digest_key_id
           OR delivery_row.lease_digest IS DISTINCT FROM lease_digest
           OR delivery_row.status NOT IN ('LEASED', 'COMPLETED')
           OR (delivery_row.status = 'LEASED'
                AND delivery_row.lease_until <= now_at) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001',
                MESSAGE = 'DEMAND_MATCH_DELIVERY_STALE_LEASE';
        END IF;
        is_replay := true;
    ELSE
        INSERT INTO demand.matching_requested_deliveries (
            delivery_id, source_event_id, source_occurred_at,
            event_type, schema_version, aggregate_type, source_aggregate_id,
            source_aggregate_version, original_actor_user_id,
            organization_id, demand_id,
            demand_version_id, envelope_sha256, demand_content_sha256,
            demand_aggregate_version, matching_request_id,
            matching_request_version, funding_id,
            composite_rule_requirement_id, matching_rule_bundle_id,
            matching_selector_digest, rule_requirement_sha256,
            authorization_digest, authorized_workload_principal_id,
            status, attempt_count, fencing_generation,
            active_workload_id, active_authority_marker_sha256,
            lease_digest_key_id, lease_digest, lease_until,
            next_available_at, matching_attempt_id,
            last_failure_fencing_generation,
            last_failure_lease_digest_key_id, last_failure_lease_digest,
            last_failure_code, last_retry_available_at,
            created_at, updated_at, completed_at, terminal_at
        )
        SELECT
            pg_catalog.uuidv7(), event.event_id, event.occurred_at,
            'MatchingRequested', 1, 'Demand', root.id, root.aggregate_version,
            CASE event.actor_kind
                WHEN 'USER' THEN event.actor_id
                ELSE event.original_actor_id
            END,
            root.organization_id, root.id, version.id,
            sha256(convert_to(concat_ws('|',
                'demand-outbox-envelope-v1',
                event.event_id::text,
                event.event_type,
                event.schema_version::text,
                extract(epoch FROM event.occurred_at)::text,
                event.aggregate_type,
                event.aggregate_id::text,
                event.aggregate_version::text,
                event.actor_kind,
                event.actor_id::text,
                COALESCE(event.original_actor_id::text, ''),
                event.correlation_id::text,
                event.causation_id::text,
                event.trace_id::text,
                root.organization_id::text,
                event.payload::text
            ), 'UTF8')),
            version.content_sha256, root.aggregate_version,
            request.id, request.aggregate_version, request.funding_id,
            request.composite_rule_requirement_id,
            request.matching_rule_bundle_id,
            request.matching_selector_digest,
            request.rule_requirement_sha256,
            request.authorization_digest,
            request.authorized_workload_principal_id,
            'AVAILABLE', 0, 0,
            NULL, NULL, NULL, NULL, NULL,
            now_at, NULL,
            NULL, NULL, NULL, NULL, NULL,
            now_at, now_at, NULL, NULL
        FROM infra.outbox_events AS event
        JOIN demand.demands AS root
          ON root.organization_id = event.organization_id
         AND root.id = event.aggregate_id
         AND root.aggregate_version = event.aggregate_version
         AND root.status = 'MATCHING'
        JOIN demand.matching_requests AS request
          ON request.organization_id = root.organization_id
         AND request.demand_id = root.id
         AND request.id = root.current_matching_request_id
         AND request.status = 'OPEN'
         AND request.authorized_workload_principal_id = workload_id
         AND request.authorization_digest = authority_marker_sha256
        JOIN demand.demand_versions AS version
          ON version.organization_id = root.organization_id
         AND version.demand_id = root.id
         AND version.id = root.current_version_id
         AND version.id = root.verified_version_id
         AND version.id = request.demand_version_id
        JOIN demand.demand_funding_markers AS funding
          ON funding.organization_id = root.organization_id
         AND funding.demand_id = root.id
         AND funding.id = root.current_funding_marker_id
         AND funding.id = request.funding_marker_id
         AND funding.demand_version_id = version.id
         AND funding.funding_id = request.funding_id
         AND funding.status = 'SECURED'
        WHERE event.event_type = 'MatchingRequested'
          AND event.schema_version = 1
          AND event.aggregate_type = 'Demand'
          AND (
                (event.actor_kind = 'USER'
                    AND event.original_actor_id IS NULL)
                OR
                (event.actor_kind = 'SYSTEM'
                    AND event.original_actor_id IS NOT NULL)
          )
          AND event.payload = jsonb_build_object(
                'demand_id', root.id::text,
                'demand_version_id', version.id::text,
                'funding_id', funding.funding_id::text,
                'matching_request_id', request.id::text,
                'composite_rule_requirement_id',
                    request.composite_rule_requirement_id::text,
                'status', 'MATCHING'
          )
          AND NOT EXISTS (
                SELECT 1
                FROM demand.matching_requested_deliveries AS existing
                WHERE existing.source_event_id = event.event_id
          )
        ORDER BY event.occurred_at, event.event_id
        LIMIT 32
        ON CONFLICT ON CONSTRAINT uq_demand_matching_delivery_source_event
        DO NOTHING;

        UPDATE demand.matching_requested_deliveries AS expired
        SET status = 'FAILED',
            active_workload_id = NULL,
            active_authority_marker_sha256 = NULL,
            lease_digest_key_id = NULL,
            lease_digest = NULL,
            lease_until = NULL,
            next_available_at = NULL,
            terminal_at = now_at,
            updated_at = now_at,
            last_failure_fencing_generation = expired.fencing_generation,
            last_failure_lease_digest_key_id = expired.lease_digest_key_id,
            last_failure_lease_digest = expired.lease_digest,
            last_failure_code = 'LEASE_EXPIRED',
            last_retry_available_at = now_at
        WHERE expired.status = 'LEASED'
          AND expired.lease_until <= now_at
          AND expired.attempt_count >= policy_row.maximum_delivery_attempts
          AND expired.authorized_workload_principal_id = workload_id
          AND expired.authorization_digest = authority_marker_sha256;

        SELECT delivery.* INTO delivery_row
        FROM demand.matching_requested_deliveries AS delivery
        WHERE delivery.authorized_workload_principal_id = workload_id
          AND delivery.authorization_digest = authority_marker_sha256
          AND delivery.attempt_count < policy_row.maximum_delivery_attempts
          AND (
                (delivery.status = 'AVAILABLE'
                    AND delivery.next_available_at <= now_at)
                OR
                (delivery.status = 'LEASED'
                    AND delivery.lease_until <= now_at)
          )
        ORDER BY delivery.source_occurred_at, delivery.source_event_id
        FOR UPDATE SKIP LOCKED
        LIMIT 1;
        IF NOT FOUND THEN
            RETURN;
        END IF;

        UPDATE demand.matching_requested_deliveries AS delivery
        SET status = 'LEASED',
            attempt_count = delivery.attempt_count + 1,
            fencing_generation = delivery.fencing_generation + 1,
            active_workload_id = workload_id,
            active_authority_marker_sha256 = authority_marker_sha256,
            lease_digest_key_id = lease_digest_key_id,
            lease_digest = lease_digest,
            lease_until = now_at + make_interval(secs => lease_seconds),
            next_available_at = NULL,
            updated_at = now_at,
            terminal_at = NULL
        WHERE delivery.delivery_id = delivery_row.delivery_id
        RETURNING delivery.* INTO STRICT delivery_row;

        INSERT INTO demand.matching_delivery_claim_receipts (
            lease_digest_key_id, lease_digest, delivery_id,
            source_event_id, workload_id, authority_marker_sha256,
            fencing_generation, lease_until, attempt_count, claimed_at
        ) VALUES (
            lease_digest_key_id, lease_digest, delivery_row.delivery_id,
            delivery_row.source_event_id, workload_id,
            authority_marker_sha256, delivery_row.fencing_generation,
            delivery_row.lease_until, delivery_row.attempt_count, now_at
        );
    END IF;

    RETURN QUERY SELECT
        delivery_row.delivery_id,
        delivery_row.source_event_id,
        delivery_row.fencing_generation,
        CASE WHEN is_replay
            THEN prior_claim.lease_until
            ELSE delivery_row.lease_until END,
        delivery_row.event_type,
        delivery_row.schema_version,
        delivery_row.aggregate_type,
        delivery_row.source_aggregate_id,
        delivery_row.source_aggregate_version,
        delivery_row.original_actor_user_id,
        delivery_row.organization_id,
        delivery_row.demand_id,
        delivery_row.demand_version_id,
        delivery_row.envelope_sha256,
        delivery_row.demand_content_sha256,
        delivery_row.demand_aggregate_version,
        delivery_row.matching_request_id,
        delivery_row.matching_request_version,
        delivery_row.funding_id,
        delivery_row.composite_rule_requirement_id,
        delivery_row.matching_rule_bundle_id,
        delivery_row.matching_selector_digest,
        delivery_row.rule_requirement_sha256,
        delivery_row.authorization_digest,
        delivery_row.authorized_workload_principal_id,
        is_replay;
END
$function$;

CREATE FUNCTION demand_api.complete_matching_requested_delivery_v1(
    delivery_id uuid,
    source_event_id uuid,
    fencing_generation bigint,
    lease_digest_key_id text,
    lease_digest bytea,
    matching_attempt_id uuid
)
RETURNS TABLE (
    status varchar,
    attempt_count integer,
    next_available_at timestamptz,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand
AS $function$
#variable_conflict use_variable
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    claim_row demand.matching_delivery_claim_receipts%ROWTYPE;
    delivery_row demand.matching_requested_deliveries%ROWTYPE;
    now_at timestamptz := transaction_timestamp();
BEGIN
    PERFORM demand.assert_matching_delivery_context_v1(
        'COMPLETE_MATCHING_REQUESTED_DELIVERY'
    );
    IF delivery_id IS NULL OR delivery_id = zero_uuid
       OR source_event_id IS NULL OR source_event_id = zero_uuid
       OR fencing_generation IS NULL OR fencing_generation < 1
       OR NULLIF(lease_digest_key_id, '') IS NULL
       OR lease_digest_key_id <> btrim(lease_digest_key_id)
       OR octet_length(lease_digest_key_id) > 128
       OR octet_length(lease_digest) <> 32
       OR matching_attempt_id IS NULL OR matching_attempt_id = zero_uuid THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    SELECT delivery.* INTO delivery_row
    FROM demand.matching_requested_deliveries AS delivery
    WHERE delivery.delivery_id = delivery_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_NOT_FOUND';
    END IF;

    SELECT receipt.* INTO claim_row
    FROM demand.matching_delivery_claim_receipts AS receipt
    WHERE receipt.lease_digest_key_id = lease_digest_key_id
      AND receipt.lease_digest = lease_digest;
    IF NOT FOUND
       OR claim_row.delivery_id IS DISTINCT FROM delivery_id
       OR claim_row.source_event_id IS DISTINCT FROM source_event_id
       OR claim_row.fencing_generation IS DISTINCT FROM fencing_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_RECEIPT_MISMATCH';
    END IF;

    IF claim_row.workload_id::text
            IS DISTINCT FROM NULLIF(
                current_setting('app.workload_id', true), ''
            )
       OR encode(claim_row.authority_marker_sha256, 'hex')
            IS DISTINCT FROM NULLIF(
                current_setting('app.authority_marker_sha256', true), ''
            ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_ACCESS_DENIED';
    END IF;

    IF delivery_row.status = 'COMPLETED' THEN
        IF delivery_row.source_event_id IS DISTINCT FROM source_event_id
           OR delivery_row.fencing_generation
                IS DISTINCT FROM fencing_generation
           OR delivery_row.lease_digest_key_id
                IS DISTINCT FROM lease_digest_key_id
           OR delivery_row.lease_digest IS DISTINCT FROM lease_digest
           OR delivery_row.matching_attempt_id
                IS DISTINCT FROM matching_attempt_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001',
                MESSAGE = 'DEMAND_MATCH_DELIVERY_RECEIPT_MISMATCH';
        END IF;
        RETURN QUERY SELECT
            delivery_row.status,
            delivery_row.attempt_count,
            delivery_row.next_available_at,
            true;
        RETURN;
    END IF;

    IF delivery_row.status IS DISTINCT FROM 'LEASED'
       OR delivery_row.source_event_id IS DISTINCT FROM source_event_id
       OR delivery_row.fencing_generation IS DISTINCT FROM fencing_generation
       OR delivery_row.lease_digest_key_id
            IS DISTINCT FROM lease_digest_key_id
       OR delivery_row.lease_digest IS DISTINCT FROM lease_digest
       OR delivery_row.lease_until <= now_at THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_STALE_LEASE';
    END IF;

    UPDATE demand.matching_requested_deliveries AS delivery
    SET status = 'COMPLETED',
        matching_attempt_id = matching_attempt_id,
        completed_at = now_at,
        terminal_at = now_at,
        updated_at = now_at
    WHERE delivery.delivery_id = delivery_row.delivery_id
    RETURNING delivery.* INTO STRICT delivery_row;

    RETURN QUERY SELECT
        delivery_row.status,
        delivery_row.attempt_count,
        delivery_row.next_available_at,
        false;
END
$function$;

CREATE FUNCTION demand_api.fail_matching_requested_delivery_v1(
    delivery_id uuid,
    source_event_id uuid,
    fencing_generation bigint,
    lease_digest_key_id text,
    lease_digest bytea,
    failure_code varchar(64),
    retry_available_at timestamptz
)
RETURNS TABLE (
    status varchar,
    attempt_count integer,
    next_available_at timestamptz,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand
AS $function$
#variable_conflict use_variable
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    policy_row demand.matching_runtime_policy%ROWTYPE;
    claim_row demand.matching_delivery_claim_receipts%ROWTYPE;
    delivery_row demand.matching_requested_deliveries%ROWTYPE;
    now_at timestamptz := transaction_timestamp();
    next_status varchar(16);
BEGIN
    PERFORM demand.assert_matching_delivery_context_v1(
        'FAIL_MATCHING_REQUESTED_DELIVERY'
    );
    IF delivery_id IS NULL OR delivery_id = zero_uuid
       OR source_event_id IS NULL OR source_event_id = zero_uuid
       OR fencing_generation IS NULL OR fencing_generation < 1
       OR NULLIF(lease_digest_key_id, '') IS NULL
       OR lease_digest_key_id <> btrim(lease_digest_key_id)
       OR octet_length(lease_digest_key_id) > 128
       OR octet_length(lease_digest) <> 32
       OR failure_code IS NULL
       OR failure_code <> btrim(failure_code)
       OR failure_code !~ '^[A-Z][A-Z0-9_]{0,63}$'
       OR retry_available_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    SELECT policy.* INTO STRICT policy_row
    FROM demand.matching_runtime_policy AS policy
    WHERE policy.singleton_key;

    SELECT delivery.* INTO delivery_row
    FROM demand.matching_requested_deliveries AS delivery
    WHERE delivery.delivery_id = delivery_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_NOT_FOUND';
    END IF;

    SELECT receipt.* INTO claim_row
    FROM demand.matching_delivery_claim_receipts AS receipt
    WHERE receipt.lease_digest_key_id = lease_digest_key_id
      AND receipt.lease_digest = lease_digest;
    IF NOT FOUND
       OR claim_row.delivery_id IS DISTINCT FROM delivery_id
       OR claim_row.source_event_id IS DISTINCT FROM source_event_id
       OR claim_row.fencing_generation IS DISTINCT FROM fencing_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_RECEIPT_MISMATCH';
    END IF;
    IF claim_row.workload_id::text
            IS DISTINCT FROM NULLIF(
                current_setting('app.workload_id', true), ''
            )
       OR encode(claim_row.authority_marker_sha256, 'hex')
            IS DISTINCT FROM NULLIF(
                current_setting('app.authority_marker_sha256', true), ''
            ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_ACCESS_DENIED';
    END IF;

    IF delivery_row.status IN ('AVAILABLE', 'FAILED')
       AND delivery_row.source_event_id IS NOT DISTINCT FROM source_event_id
       AND delivery_row.last_failure_fencing_generation
            IS NOT DISTINCT FROM fencing_generation
       AND delivery_row.last_failure_lease_digest_key_id
            IS NOT DISTINCT FROM lease_digest_key_id
       AND delivery_row.last_failure_lease_digest
            IS NOT DISTINCT FROM lease_digest
       AND delivery_row.last_failure_code IS NOT DISTINCT FROM failure_code
       AND delivery_row.last_retry_available_at
            IS NOT DISTINCT FROM retry_available_at THEN
        RETURN QUERY SELECT
            delivery_row.status,
            delivery_row.attempt_count,
            delivery_row.next_available_at,
            true;
        RETURN;
    END IF;

    IF delivery_row.active_workload_id::text
            IS DISTINCT FROM NULLIF(
                current_setting('app.workload_id', true), ''
            )
       OR encode(delivery_row.active_authority_marker_sha256, 'hex')
            IS DISTINCT FROM NULLIF(
                current_setting('app.authority_marker_sha256', true), ''
            ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_ACCESS_DENIED';
    END IF;

    IF delivery_row.status IS DISTINCT FROM 'LEASED'
       OR delivery_row.source_event_id IS DISTINCT FROM source_event_id
       OR delivery_row.fencing_generation IS DISTINCT FROM fencing_generation
       OR delivery_row.lease_digest_key_id
            IS DISTINCT FROM lease_digest_key_id
       OR delivery_row.lease_digest IS DISTINCT FROM lease_digest
       OR delivery_row.lease_until <= now_at THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'DEMAND_MATCH_DELIVERY_STALE_LEASE';
    END IF;

    IF delivery_row.attempt_count < policy_row.maximum_delivery_attempts THEN
        IF retry_available_at < now_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'INVALID_RETRY_AVAILABLE_AT';
        END IF;
        next_status := 'AVAILABLE';
    ELSE
        next_status := 'FAILED';
    END IF;

    UPDATE demand.matching_requested_deliveries AS delivery
    SET status = next_status,
        active_workload_id = NULL,
        active_authority_marker_sha256 = NULL,
        lease_digest_key_id = NULL,
        lease_digest = NULL,
        lease_until = NULL,
        next_available_at = CASE
            WHEN next_status = 'AVAILABLE' THEN retry_available_at
            ELSE NULL END,
        last_failure_fencing_generation = fencing_generation,
        last_failure_lease_digest_key_id = lease_digest_key_id,
        last_failure_lease_digest = lease_digest,
        last_failure_code = failure_code,
        last_retry_available_at = retry_available_at,
        terminal_at = CASE
            WHEN next_status = 'FAILED' THEN now_at
            ELSE NULL END,
        updated_at = now_at
    WHERE delivery.delivery_id = delivery_row.delivery_id
    RETURNING delivery.* INTO STRICT delivery_row;

    RETURN QUERY SELECT
        delivery_row.status,
        delivery_row.attempt_count,
        delivery_row.next_available_at,
        false;
END
$function$;

CREATE FUNCTION demand_api.execute_complete_selection_system_v1(
    exact_completion_command_id uuid,
    exact_choose_receipt_id uuid,
    exact_selection_id uuid,
    exact_attempt_id uuid,
    exact_invitation_id uuid,
    exact_match_run_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_expected_demand_version bigint,
    exact_demand_version_id uuid,
    exact_matching_request_id uuid,
    exact_matching_request_version bigint,
    exact_funding_id uuid,
    exact_original_actor_user_id uuid,
    exact_coordinator_workload_id uuid,
    exact_coordinator_authority_marker_sha256 bytea,
    exact_payload_hash_key_id varchar,
    exact_payload_hash bytea,
    exact_demand_matched_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (
    demand_id uuid,
    demand_version bigint,
    matching_request_version bigint,
    demand_status varchar,
    matching_request_status varchar,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand
AS $function$
#variable_conflict use_variable
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    root_row demand.demands%ROWTYPE;
    request_row demand.matching_requests%ROWTYPE;
    receipt_row demand.complete_selection_receipts%ROWTYPE;
    now_at timestamptz := transaction_timestamp();
BEGIN
    IF exact_completion_command_id IS NULL
            OR exact_completion_command_id = zero_uuid
       OR exact_choose_receipt_id IS NULL OR exact_choose_receipt_id = zero_uuid
       OR exact_selection_id IS NULL OR exact_selection_id = zero_uuid
       OR exact_attempt_id IS NULL OR exact_attempt_id = zero_uuid
       OR exact_invitation_id IS NULL OR exact_invitation_id = zero_uuid
       OR exact_match_run_id IS NULL OR exact_match_run_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_expected_demand_version IS NULL
            OR exact_expected_demand_version < 1
       OR exact_demand_version_id IS NULL OR exact_demand_version_id = zero_uuid
       OR exact_matching_request_id IS NULL
            OR exact_matching_request_id = zero_uuid
       OR exact_matching_request_version IS NULL
            OR exact_matching_request_version < 1
       OR exact_funding_id IS NULL OR exact_funding_id = zero_uuid
       OR exact_original_actor_user_id IS NULL
            OR exact_original_actor_user_id = zero_uuid
       OR exact_coordinator_workload_id IS NULL
            OR exact_coordinator_workload_id = zero_uuid
       OR octet_length(exact_coordinator_authority_marker_sha256) <> 32
       OR NULLIF(exact_payload_hash_key_id, '') IS NULL
       OR exact_payload_hash_key_id <> btrim(exact_payload_hash_key_id)
       OR octet_length(exact_payload_hash_key_id) > 128
       OR octet_length(exact_payload_hash) <> 32
       OR exact_demand_matched_event_id IS NULL
            OR exact_demand_matched_event_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    PERFORM demand.assert_matching_coordinator_context_v1(
        exact_completion_command_id,
        exact_organization_id,
        exact_demand_id,
        exact_original_actor_user_id,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256
    );

    -- The cross-component lock order is fixed: Demand root first, then the
    -- exact MatchingRequest. Matching v3 locks its own tuple only afterward.
    SELECT root.* INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;

    SELECT receipt.* INTO receipt_row
    FROM demand.complete_selection_receipts AS receipt
    WHERE receipt.completion_command_id = exact_completion_command_id;

    SELECT request.* INTO request_row
    FROM demand.matching_requests AS request
    WHERE request.organization_id = exact_organization_id
      AND request.demand_id = exact_demand_id
      AND request.id = exact_matching_request_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;

    IF receipt_row.completion_command_id IS NOT NULL THEN
        IF receipt_row.choose_receipt_id IS DISTINCT FROM exact_choose_receipt_id
           OR receipt_row.selection_id IS DISTINCT FROM exact_selection_id
           OR receipt_row.attempt_id IS DISTINCT FROM exact_attempt_id
           OR receipt_row.invitation_id IS DISTINCT FROM exact_invitation_id
           OR receipt_row.match_run_id IS DISTINCT FROM exact_match_run_id
           OR receipt_row.organization_id IS DISTINCT FROM exact_organization_id
           OR receipt_row.demand_id IS DISTINCT FROM exact_demand_id
           OR receipt_row.expected_demand_version
                IS DISTINCT FROM exact_expected_demand_version
           OR receipt_row.demand_version_id
                IS DISTINCT FROM exact_demand_version_id
           OR receipt_row.matching_request_id
                IS DISTINCT FROM exact_matching_request_id
           OR receipt_row.expected_matching_request_version
                IS DISTINCT FROM exact_matching_request_version
           OR receipt_row.funding_id IS DISTINCT FROM exact_funding_id
           OR receipt_row.original_actor_user_id
                IS DISTINCT FROM exact_original_actor_user_id
           OR receipt_row.coordinator_workload_id
                IS DISTINCT FROM exact_coordinator_workload_id
           OR receipt_row.coordinator_authority_marker_sha256
                IS DISTINCT FROM exact_coordinator_authority_marker_sha256
           OR receipt_row.payload_hash_key_id
                IS DISTINCT FROM exact_payload_hash_key_id
           OR receipt_row.payload_hash IS DISTINCT FROM exact_payload_hash
           OR receipt_row.demand_matched_event_id
                IS DISTINCT FROM exact_demand_matched_event_id
           OR receipt_row.correlation_id IS DISTINCT FROM exact_correlation_id
           OR receipt_row.trace_id IS DISTINCT FROM exact_trace_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001',
                MESSAGE = 'DEMAND_COMPLETE_SELECTION_RECEIPT_MISMATCH';
        END IF;
        IF root_row.status IS DISTINCT FROM 'MATCHED'
           OR root_row.aggregate_version
                IS DISTINCT FROM receipt_row.completed_demand_version
           OR root_row.current_version_id
                IS DISTINCT FROM exact_demand_version_id
           OR root_row.verified_version_id
                IS DISTINCT FROM exact_demand_version_id
           OR root_row.current_matching_request_id
                IS DISTINCT FROM exact_matching_request_id
           OR request_row.status IS DISTINCT FROM 'CLOSED'
           OR request_row.aggregate_version
                IS DISTINCT FROM receipt_row.completed_matching_request_version
           OR NOT EXISTS (
                SELECT 1
                FROM infra.outbox_events AS event
                WHERE event.event_id = exact_demand_matched_event_id
                  AND event.event_type = 'DemandMatched'
                  AND event.schema_version = 1
                  AND event.aggregate_type = 'Demand'
                  AND event.aggregate_id = exact_demand_id
                  AND event.aggregate_version
                        = receipt_row.completed_demand_version
                  AND event.actor_kind = 'SYSTEM'
                  AND event.actor_id = exact_coordinator_workload_id
                  AND event.original_actor_id = exact_original_actor_user_id
                  AND event.correlation_id = exact_correlation_id
                  AND event.causation_id = exact_choose_receipt_id
                  AND event.trace_id = exact_trace_id
                  AND event.organization_id = exact_organization_id
                  AND event.payload = jsonb_build_object(
                        'demand_id', exact_demand_id::text,
                        'status', 'MATCHED',
                        'reason_code', NULL
                  )
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'DEMAND_COMPLETE_SELECTION_REPLAY_DRIFTED';
        END IF;
        RETURN QUERY SELECT
            exact_demand_id,
            receipt_row.completed_demand_version,
            receipt_row.completed_matching_request_version,
            'MATCHED'::varchar,
            'CLOSED'::varchar,
            true;
        RETURN;
    END IF;

    IF root_row.status IS DISTINCT FROM 'MATCHING'
       OR root_row.aggregate_version
            IS DISTINCT FROM exact_expected_demand_version
       OR root_row.current_version_id IS DISTINCT FROM exact_demand_version_id
       OR root_row.verified_version_id IS DISTINCT FROM exact_demand_version_id
       OR root_row.current_matching_request_id
            IS DISTINCT FROM exact_matching_request_id
       OR request_row.status IS DISTINCT FROM 'OPEN'
       OR request_row.aggregate_version
            IS DISTINCT FROM exact_matching_request_version
       OR request_row.demand_version_id
            IS DISTINCT FROM exact_demand_version_id
       OR request_row.funding_id IS DISTINCT FROM exact_funding_id
       OR request_row.funding_marker_id
            IS DISTINCT FROM root_row.current_funding_marker_id
       OR NOT EXISTS (
            SELECT 1
            FROM demand.demand_funding_markers AS funding
            WHERE funding.organization_id = exact_organization_id
              AND funding.demand_id = exact_demand_id
              AND funding.id = root_row.current_funding_marker_id
              AND funding.demand_version_id = exact_demand_version_id
              AND funding.funding_id = exact_funding_id
              AND funding.status = 'SECURED'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;

    UPDATE demand.demands AS root
    SET status = 'MATCHED',
        aggregate_version = exact_expected_demand_version + 1,
        updated_at = now_at
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id;

    UPDATE demand.matching_requests AS request
    SET status = 'CLOSED',
        aggregate_version = exact_matching_request_version + 1,
        closed_at = now_at
    WHERE request.organization_id = exact_organization_id
      AND request.demand_id = exact_demand_id
      AND request.id = exact_matching_request_id;

    INSERT INTO demand.complete_selection_receipts (
        completion_command_id, choose_receipt_id, selection_id, attempt_id,
        invitation_id, match_run_id, organization_id, demand_id,
        expected_demand_version, completed_demand_version,
        demand_version_id, matching_request_id,
        expected_matching_request_version,
        completed_matching_request_version, funding_id,
        original_actor_user_id, coordinator_workload_id,
        coordinator_authority_marker_sha256, payload_hash_key_id,
        payload_hash, demand_matched_event_id, correlation_id, trace_id,
        completed_at
    ) VALUES (
        exact_completion_command_id, exact_choose_receipt_id,
        exact_selection_id, exact_attempt_id, exact_invitation_id,
        exact_match_run_id, exact_organization_id, exact_demand_id,
        exact_expected_demand_version, exact_expected_demand_version + 1,
        exact_demand_version_id, exact_matching_request_id,
        exact_matching_request_version, exact_matching_request_version + 1,
        exact_funding_id, exact_original_actor_user_id,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        exact_payload_hash_key_id, exact_payload_hash,
        exact_demand_matched_event_id, exact_correlation_id, exact_trace_id,
        now_at
    );

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id,
        before_status, after_status, before_version, after_version,
        role_code, purpose_code, reason_code, auth_strength_code,
        result_code, command_id, correlation_id, causation_id, trace_id,
        safe_attributes
    ) VALUES (
        exact_demand_matched_event_id, now_at, 'SYSTEM',
        exact_coordinator_workload_id, exact_original_actor_user_id,
        'COMPLETE_SELECTION', 'Demand', exact_demand_id,
        exact_organization_id, 'MATCHING', 'MATCHED',
        exact_expected_demand_version, exact_expected_demand_version + 1,
        'MATCHING_COORDINATOR', 'COMPLETE_SELECTION', NULL, NULL,
        'SUCCEEDED', exact_completion_command_id, exact_correlation_id,
        exact_choose_receipt_id, exact_trace_id,
        jsonb_build_object(
            'selection_id', exact_selection_id::text,
            'attempt_id', exact_attempt_id::text,
            'invitation_id', exact_invitation_id::text,
            'match_run_id', exact_match_run_id::text,
            'matching_request_id', exact_matching_request_id::text,
            'matching_request_version', exact_matching_request_version + 1,
            'demand_version_id', exact_demand_version_id::text,
            'funding_id', exact_funding_id::text
        )
    );

    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at,
        aggregate_type, aggregate_id, aggregate_version,
        actor_kind, actor_id, original_actor_id,
        correlation_id, causation_id, trace_id, organization_id, payload,
        delivery_status, attempt_count, available_at,
        lease_owner, lease_until, published_at, last_error_code, created_at
    ) VALUES (
        exact_demand_matched_event_id, 'DemandMatched', 1, now_at,
        'Demand', exact_demand_id, exact_expected_demand_version + 1,
        'SYSTEM', exact_coordinator_workload_id,
        exact_original_actor_user_id, exact_correlation_id,
        exact_choose_receipt_id, exact_trace_id, exact_organization_id,
        jsonb_build_object(
            'demand_id', exact_demand_id::text,
            'status', 'MATCHED',
            'reason_code', NULL
        ),
        'PENDING', 0, now_at, NULL, NULL, NULL, NULL, now_at
    );

    RETURN QUERY SELECT
        exact_demand_id,
        exact_expected_demand_version + 1,
        exact_matching_request_version + 1,
        'MATCHED'::varchar,
        'CLOSED'::varchar,
        false;
END
$function$;

CREATE FUNCTION demand_api.execute_close_matching_without_selection_system_v1(
    exact_completion_command_id uuid,
    exact_close_receipt_id uuid,
    exact_selection_id uuid,
    exact_attempt_id uuid,
    exact_match_run_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_expected_demand_version bigint,
    exact_demand_version_id uuid,
    exact_matching_request_id uuid,
    exact_expected_matching_request_version bigint,
    exact_funding_id uuid,
    exact_original_actor_user_id uuid,
    exact_coordinator_workload_id uuid,
    exact_coordinator_authority_marker_sha256 bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_demand_closed_event_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_reason_code text
)
RETURNS TABLE (
    demand_id uuid,
    demand_version bigint,
    matching_request_version bigint,
    demand_status varchar,
    matching_request_status varchar,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand
AS $function$
#variable_conflict use_variable
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    root_row demand.demands%ROWTYPE;
    request_row demand.matching_requests%ROWTYPE;
    receipt_row demand.close_matching_without_selection_receipts%ROWTYPE;
    now_at timestamptz := transaction_timestamp();
BEGIN
    IF exact_completion_command_id IS NULL
            OR exact_completion_command_id = zero_uuid
       OR exact_close_receipt_id IS NULL OR exact_close_receipt_id = zero_uuid
       OR exact_selection_id IS NULL OR exact_selection_id = zero_uuid
       OR exact_attempt_id IS NULL OR exact_attempt_id = zero_uuid
       OR exact_match_run_id IS NULL OR exact_match_run_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_expected_demand_version IS NULL
            OR exact_expected_demand_version < 1
       OR exact_demand_version_id IS NULL OR exact_demand_version_id = zero_uuid
       OR exact_matching_request_id IS NULL
            OR exact_matching_request_id = zero_uuid
       OR exact_expected_matching_request_version IS NULL
            OR exact_expected_matching_request_version < 1
       OR exact_funding_id IS NULL OR exact_funding_id = zero_uuid
       OR exact_original_actor_user_id IS NULL
            OR exact_original_actor_user_id = zero_uuid
       OR exact_coordinator_workload_id IS NULL
            OR exact_coordinator_workload_id = zero_uuid
       OR octet_length(exact_coordinator_authority_marker_sha256) <> 32
       OR NULLIF(exact_payload_hash_key_id, '') IS NULL
       OR exact_payload_hash_key_id <> btrim(exact_payload_hash_key_id)
       OR octet_length(exact_payload_hash_key_id) > 128
       OR octet_length(exact_payload_hash) <> 32
       OR exact_demand_closed_event_id IS NULL
            OR exact_demand_closed_event_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_reason_code IS NULL
       OR exact_reason_code <> btrim(exact_reason_code)
       OR exact_reason_code !~ '^[A-Z][A-Z0-9_]{1,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    PERFORM demand.assert_matching_coordinator_context_v1(
        exact_completion_command_id,
        exact_organization_id,
        exact_demand_id,
        exact_original_actor_user_id,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256
    );

    SELECT root.* INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;

    SELECT receipt.* INTO receipt_row
    FROM demand.close_matching_without_selection_receipts AS receipt
    WHERE receipt.completion_command_id = exact_completion_command_id;

    SELECT request.* INTO request_row
    FROM demand.matching_requests AS request
    WHERE request.organization_id = exact_organization_id
      AND request.demand_id = exact_demand_id
      AND request.id = exact_matching_request_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;

    IF receipt_row.completion_command_id IS NOT NULL THEN
        IF receipt_row.close_receipt_id IS DISTINCT FROM exact_close_receipt_id
           OR receipt_row.selection_id IS DISTINCT FROM exact_selection_id
           OR receipt_row.attempt_id IS DISTINCT FROM exact_attempt_id
           OR receipt_row.match_run_id IS DISTINCT FROM exact_match_run_id
           OR receipt_row.organization_id IS DISTINCT FROM exact_organization_id
           OR receipt_row.demand_id IS DISTINCT FROM exact_demand_id
           OR receipt_row.expected_demand_version
                IS DISTINCT FROM exact_expected_demand_version
           OR receipt_row.demand_version_id
                IS DISTINCT FROM exact_demand_version_id
           OR receipt_row.matching_request_id
                IS DISTINCT FROM exact_matching_request_id
           OR receipt_row.expected_matching_request_version
                IS DISTINCT FROM exact_expected_matching_request_version
           OR receipt_row.funding_id IS DISTINCT FROM exact_funding_id
           OR receipt_row.original_actor_user_id
                IS DISTINCT FROM exact_original_actor_user_id
           OR receipt_row.coordinator_workload_id
                IS DISTINCT FROM exact_coordinator_workload_id
           OR receipt_row.coordinator_authority_marker_sha256
                IS DISTINCT FROM exact_coordinator_authority_marker_sha256
           OR receipt_row.payload_hash_key_id
                IS DISTINCT FROM exact_payload_hash_key_id
           OR receipt_row.payload_hash IS DISTINCT FROM exact_payload_hash
           OR receipt_row.demand_closed_event_id
                IS DISTINCT FROM exact_demand_closed_event_id
           OR receipt_row.correlation_id IS DISTINCT FROM exact_correlation_id
           OR receipt_row.trace_id IS DISTINCT FROM exact_trace_id
           OR receipt_row.reason_code IS DISTINCT FROM exact_reason_code THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001',
                MESSAGE = 'DEMAND_CLOSE_WITHOUT_SELECTION_RECEIPT_MISMATCH';
        END IF;
        IF root_row.status IS DISTINCT FROM 'NO_MATCH'
           OR root_row.aggregate_version
                IS DISTINCT FROM receipt_row.completed_demand_version
           OR root_row.current_version_id
                IS DISTINCT FROM exact_demand_version_id
           OR root_row.verified_version_id
                IS DISTINCT FROM exact_demand_version_id
           OR root_row.current_matching_request_id IS NOT NULL
           OR request_row.status IS DISTINCT FROM 'CLOSED'
           OR request_row.aggregate_version
                IS DISTINCT FROM receipt_row.completed_matching_request_version
           OR NOT EXISTS (
                SELECT 1
                FROM infra.outbox_events AS event
                WHERE event.event_id = exact_demand_closed_event_id
                  AND event.event_type
                        = 'DemandMatchingClosedWithoutSelection'
                  AND event.schema_version = 1
                  AND event.aggregate_type = 'Demand'
                  AND event.aggregate_id = exact_demand_id
                  AND event.aggregate_version
                        = receipt_row.completed_demand_version
                  AND event.actor_kind = 'SYSTEM'
                  AND event.actor_id = exact_coordinator_workload_id
                  AND event.original_actor_id = exact_original_actor_user_id
                  AND event.correlation_id = exact_correlation_id
                  AND event.causation_id = exact_close_receipt_id
                  AND event.trace_id = exact_trace_id
                  AND event.organization_id = exact_organization_id
                  AND event.payload = jsonb_build_object(
                        'demand_id', exact_demand_id::text,
                        'status', 'NO_MATCH',
                        'reason_code', NULL
                  )
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'DEMAND_CLOSE_WITHOUT_SELECTION_REPLAY_DRIFTED';
        END IF;
        RETURN QUERY SELECT
            exact_demand_id,
            receipt_row.completed_demand_version,
            receipt_row.completed_matching_request_version,
            'NO_MATCH'::varchar,
            'CLOSED'::varchar,
            true;
        RETURN;
    END IF;

    IF root_row.status IS DISTINCT FROM 'MATCHING'
       OR root_row.aggregate_version
            IS DISTINCT FROM exact_expected_demand_version
       OR root_row.current_version_id IS DISTINCT FROM exact_demand_version_id
       OR root_row.verified_version_id IS DISTINCT FROM exact_demand_version_id
       OR root_row.current_matching_request_id
            IS DISTINCT FROM exact_matching_request_id
       OR request_row.status IS DISTINCT FROM 'OPEN'
       OR request_row.aggregate_version
            IS DISTINCT FROM exact_expected_matching_request_version
       OR request_row.demand_version_id
            IS DISTINCT FROM exact_demand_version_id
       OR request_row.funding_id IS DISTINCT FROM exact_funding_id
       OR request_row.funding_marker_id
            IS DISTINCT FROM root_row.current_funding_marker_id
       OR NOT EXISTS (
            SELECT 1
            FROM demand.demand_funding_markers AS funding
            WHERE funding.organization_id = exact_organization_id
              AND funding.demand_id = exact_demand_id
              AND funding.id = root_row.current_funding_marker_id
              AND funding.demand_version_id = exact_demand_version_id
              AND funding.funding_id = exact_funding_id
              AND funding.status = 'SECURED'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PRECONDITION_FAILED';
    END IF;

    UPDATE demand.demands AS root
    SET status = 'NO_MATCH',
        aggregate_version = exact_expected_demand_version + 1,
        current_matching_request_id = NULL,
        updated_at = now_at
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id;

    UPDATE demand.matching_requests AS request
    SET status = 'CLOSED',
        aggregate_version = exact_expected_matching_request_version + 1,
        closed_at = now_at
    WHERE request.organization_id = exact_organization_id
      AND request.demand_id = exact_demand_id
      AND request.id = exact_matching_request_id;

    INSERT INTO demand.close_matching_without_selection_receipts (
        completion_command_id, close_receipt_id, selection_id, attempt_id,
        match_run_id, organization_id, demand_id,
        expected_demand_version, completed_demand_version,
        demand_version_id, matching_request_id,
        expected_matching_request_version,
        completed_matching_request_version, funding_id,
        original_actor_user_id, coordinator_workload_id,
        coordinator_authority_marker_sha256, payload_hash_key_id,
        payload_hash, demand_closed_event_id, correlation_id, trace_id,
        reason_code, completed_at
    ) VALUES (
        exact_completion_command_id, exact_close_receipt_id,
        exact_selection_id, exact_attempt_id, exact_match_run_id,
        exact_organization_id, exact_demand_id,
        exact_expected_demand_version, exact_expected_demand_version + 1,
        exact_demand_version_id, exact_matching_request_id,
        exact_expected_matching_request_version,
        exact_expected_matching_request_version + 1,
        exact_funding_id, exact_original_actor_user_id,
        exact_coordinator_workload_id,
        exact_coordinator_authority_marker_sha256,
        exact_payload_hash_key_id, exact_payload_hash,
        exact_demand_closed_event_id, exact_correlation_id, exact_trace_id,
        exact_reason_code, now_at
    );

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id,
        before_status, after_status, before_version, after_version,
        role_code, purpose_code, reason_code, auth_strength_code,
        result_code, command_id, correlation_id, causation_id, trace_id,
        safe_attributes
    ) VALUES (
        exact_demand_closed_event_id, now_at, 'SYSTEM',
        exact_coordinator_workload_id, exact_original_actor_user_id,
        'CLOSE_MATCHING_WITHOUT_SELECTION', 'Demand', exact_demand_id,
        exact_organization_id, 'MATCHING', 'NO_MATCH',
        exact_expected_demand_version, exact_expected_demand_version + 1,
        'MATCHING_COORDINATOR', 'COMPLETE_SELECTION', exact_reason_code,
        NULL, 'SUCCEEDED', exact_completion_command_id,
        exact_correlation_id, exact_close_receipt_id, exact_trace_id,
        jsonb_build_object(
            'selection_id', exact_selection_id::text,
            'attempt_id', exact_attempt_id::text,
            'match_run_id', exact_match_run_id::text,
            'matching_request_id', exact_matching_request_id::text,
            'matching_request_version',
                exact_expected_matching_request_version + 1,
            'demand_version_id', exact_demand_version_id::text,
            'funding_id', exact_funding_id::text,
            'reason_code', exact_reason_code
        )
    );

    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at,
        aggregate_type, aggregate_id, aggregate_version,
        actor_kind, actor_id, original_actor_id,
        correlation_id, causation_id, trace_id, organization_id, payload,
        delivery_status, attempt_count, available_at,
        lease_owner, lease_until, published_at, last_error_code, created_at
    ) VALUES (
        exact_demand_closed_event_id,
        'DemandMatchingClosedWithoutSelection', 1, now_at,
        'Demand', exact_demand_id, exact_expected_demand_version + 1,
        'SYSTEM', exact_coordinator_workload_id,
        exact_original_actor_user_id, exact_correlation_id,
        exact_close_receipt_id, exact_trace_id, exact_organization_id,
        jsonb_build_object(
            'demand_id', exact_demand_id::text,
            'status', 'NO_MATCH',
            'reason_code', NULL
        ),
        'PENDING', 0, now_at, NULL, NULL, NULL, NULL, now_at
    );

    RETURN QUERY SELECT
        exact_demand_id,
        exact_expected_demand_version + 1,
        exact_expected_matching_request_version + 1,
        'NO_MATCH'::varchar,
        'CLOSED'::varchar,
        false;
END
$function$;

ALTER FUNCTION demand_api.claim_matching_requested_delivery_v1(
    uuid, bytea, text, bytea, integer
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.complete_matching_requested_delivery_v1(
    uuid, uuid, bigint, text, bytea, uuid
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.fail_matching_requested_delivery_v1(
    uuid, uuid, bigint, text, bytea, varchar, timestamptz
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.execute_complete_selection_system_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, uuid,
    uuid, bigint, uuid, uuid, uuid, bytea, varchar, bytea, uuid, uuid,
    uuid
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.execute_close_matching_without_selection_system_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid,
    bigint, uuid, uuid, uuid, bytea, text, bytea, uuid, uuid, uuid, text
) OWNER TO demand_schema_owner;

REVOKE ALL PRIVILEGES ON demand.matching_runtime_policy,
    demand.matching_requested_deliveries,
    demand.matching_delivery_claim_receipts,
    demand.complete_selection_receipts,
    demand.close_matching_without_selection_receipts
FROM PUBLIC, demand_matching, matching_coordinator, matching_schema_owner;

REVOKE ALL ON FUNCTION demand.protect_matching_delivery_projection_v1()
FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.claim_matching_requested_delivery_v1(
    uuid, bytea, text, bytea, integer
) FROM PUBLIC, matching_coordinator, matching_schema_owner;
REVOKE ALL ON FUNCTION demand_api.complete_matching_requested_delivery_v1(
    uuid, uuid, bigint, text, bytea, uuid
) FROM PUBLIC, matching_coordinator, matching_schema_owner;
REVOKE ALL ON FUNCTION demand_api.fail_matching_requested_delivery_v1(
    uuid, uuid, bigint, text, bytea, varchar, timestamptz
) FROM PUBLIC, matching_coordinator, matching_schema_owner;
REVOKE ALL ON FUNCTION demand_api.execute_complete_selection_system_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, uuid,
    uuid, bigint, uuid, uuid, uuid, bytea, varchar, bytea, uuid, uuid,
    uuid
) FROM PUBLIC, demand_matching, matching_coordinator;
REVOKE ALL ON FUNCTION demand_api.execute_close_matching_without_selection_system_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid,
    bigint, uuid, uuid, uuid, bytea, text, bytea, uuid, uuid, uuid, text
) FROM PUBLIC, demand_matching, matching_coordinator;

GRANT USAGE ON SCHEMA demand_api TO
    demand_matching, matching_coordinator, matching_schema_owner;
GRANT EXECUTE ON FUNCTION demand_api.claim_matching_requested_delivery_v1(
    uuid, bytea, text, bytea, integer
) TO demand_matching;
GRANT EXECUTE ON FUNCTION demand_api.complete_matching_requested_delivery_v1(
    uuid, uuid, bigint, text, bytea, uuid
) TO demand_matching;
GRANT EXECUTE ON FUNCTION demand_api.fail_matching_requested_delivery_v1(
    uuid, uuid, bigint, text, bytea, varchar, timestamptz
) TO demand_matching;
GRANT EXECUTE ON FUNCTION demand_api.execute_complete_selection_system_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, uuid,
    uuid, bigint, uuid, uuid, uuid, bytea, varchar, bytea, uuid, uuid,
    uuid
) TO matching_schema_owner;
GRANT EXECUTE ON FUNCTION demand_api.execute_close_matching_without_selection_system_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid,
    bigint, uuid, uuid, uuid, bytea, text, bytea, uuid, uuid, uuid, text
) TO matching_schema_owner;

DO $assert$
DECLARE
    invalid_rls_count bigint;
BEGIN
    SELECT count(*) INTO invalid_rls_count
    FROM pg_catalog.pg_class AS relation
    WHERE relation.oid IN (
        'demand.matching_runtime_policy'::regclass,
        'demand.matching_requested_deliveries'::regclass,
        'demand.matching_delivery_claim_receipts'::regclass,
        'demand.complete_selection_receipts'::regclass,
        'demand.close_matching_without_selection_receipts'::regclass
    )
      AND (NOT relation.relrowsecurity OR NOT relation.relforcerowsecurity);

    IF invalid_rls_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand15 matching FORCE RLS assertion failed';
    END IF;
    IF pg_catalog.has_table_privilege(
            'demand_matching',
            'demand.matching_requested_deliveries',
            'SELECT,INSERT,UPDATE,DELETE'
       )
       OR pg_catalog.has_table_privilege(
            'matching_coordinator',
            'demand.complete_selection_receipts',
            'SELECT,INSERT,UPDATE,DELETE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand15 runtime direct table grant assertion failed';
    END IF;
    IF NOT pg_catalog.has_function_privilege(
            'demand_matching',
            'demand_api.claim_matching_requested_delivery_v1(uuid,bytea,text,bytea,integer)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_coordinator',
            'demand_api.execute_complete_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,character varying,bytea,uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'matching_coordinator',
            'demand_api.execute_close_matching_without_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,text,bytea,uuid,uuid,uuid,text)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_schema_owner',
            'demand_api.execute_complete_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,character varying,bytea,uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'matching_schema_owner',
            'demand_api.execute_close_matching_without_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,text,bytea,uuid,uuid,uuid,text)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_matching',
            'demand_api.execute_complete_selection_system_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,uuid,uuid,uuid,bytea,character varying,bytea,uuid,uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand15 Matching completion/delivery assertion failed';
    END IF;
END
$assert$;
