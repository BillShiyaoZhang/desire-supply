DO $outbox_role_guard$
DECLARE
    worker record;
    consumer record;
BEGIN
    SELECT rolsuper, rolbypassrls, rolinherit, rolcanlogin
    INTO worker
    FROM pg_catalog.pg_roles
    WHERE rolname = 'iam_outbox_worker';

    SELECT rolsuper, rolbypassrls, rolinherit, rolcanlogin
    INTO consumer
    FROM pg_catalog.pg_roles
    WHERE rolname = 'iam_projection_consumer';

    IF worker IS NULL
       OR worker.rolsuper
       OR worker.rolbypassrls
       OR worker.rolinherit
       OR NOT worker.rolcanlogin
       OR consumer IS NULL
       OR consumer.rolsuper
       OR consumer.rolbypassrls
       OR consumer.rolinherit
       OR NOT consumer.rolcanlogin THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_outbox_online_roles',
            MESSAGE = 'outbox online role attributes are unsafe';
    END IF;
END
$outbox_role_guard$;

DO $outbox_existing_lease_guard$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM infra.outbox_events
        WHERE delivery_status = 'LEASED'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_outbox_no_legacy_leases',
            MESSAGE = 'legacy outbox leases must be recovered before migration';
    END IF;
END
$outbox_existing_lease_guard$;

ALTER TABLE infra.outbox_events
    ADD COLUMN leased_at timestamptz NULL,
    ADD COLUMN lease_token uuid NULL,
    ADD COLUMN dead_at timestamptz NULL;

UPDATE infra.outbox_events
SET dead_at = created_at
WHERE delivery_status = 'DEAD';

ALTER TABLE infra.outbox_events
    ADD CONSTRAINT ck_outbox_delivery_shape_v2 CHECK (
        (
            delivery_status = 'PENDING'
            AND lease_owner IS NULL
            AND leased_at IS NULL
            AND lease_token IS NULL
            AND lease_until IS NULL
            AND published_at IS NULL
            AND dead_at IS NULL
            AND last_error_code IS NULL OR (
                delivery_status = 'PENDING'
                AND lease_owner IS NULL
                AND leased_at IS NULL
                AND lease_token IS NULL
                AND lease_until IS NULL
                AND published_at IS NULL
                AND dead_at IS NULL
                AND last_error_code IN (
                    'BROKER_UNAVAILABLE',
                    'BROKER_ACK_UNKNOWN'
                )
            )
        )
        OR
        (
            delivery_status = 'LEASED'
            AND attempt_count >= 1
            AND lease_owner IS NOT NULL
            AND leased_at IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_until IS NOT NULL
            AND leased_at < lease_until
            AND published_at IS NULL
            AND dead_at IS NULL
            AND last_error_code IS NULL
        )
        OR
        (
            delivery_status = 'PUBLISHED'
            AND lease_owner IS NULL
            AND leased_at IS NULL
            AND lease_token IS NULL
            AND lease_until IS NULL
            AND published_at IS NOT NULL
            AND dead_at IS NULL
            AND last_error_code IS NULL
        )
        OR
        (
            delivery_status = 'DEAD'
            AND lease_owner IS NULL
            AND leased_at IS NULL
            AND lease_token IS NULL
            AND lease_until IS NULL
            AND published_at IS NULL
            AND dead_at IS NOT NULL
            AND last_error_code IN (
                'OUTBOX_SCHEMA_UNSUPPORTED',
                'OUTBOX_EVENT_INVALID',
                'DELIVERY_ATTEMPTS_EXHAUSTED'
            )
        )
    ),
    ADD CONSTRAINT ck_outbox_transport_times_v2 CHECK (
        (leased_at IS NULL OR leased_at >= occurred_at)
        AND (dead_at IS NULL OR dead_at >= occurred_at)
    );

CREATE INDEX ix_outbox_delivery_queue_v2
    ON infra.outbox_events (
        delivery_status,
        available_at,
        created_at,
        event_id
    );

CREATE INDEX ix_outbox_expired_leases_v2
    ON infra.outbox_events (lease_until, created_at, event_id)
    WHERE delivery_status = 'LEASED';

CREATE TABLE infra.consumer_principals (
    database_role name NOT NULL,
    consumer_name varchar(96) NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_consumer_principals PRIMARY KEY (database_role),
    CONSTRAINT uq_consumer_principal_name UNIQUE (consumer_name),
    CONSTRAINT ck_consumer_principal_name CHECK (
        consumer_name ~ '^[a-z0-9][a-z0-9._-]{2,95}$'
    )
);

INSERT INTO infra.consumer_principals (
    database_role,
    consumer_name,
    created_at
) VALUES (
    'iam_projection_consumer'::name,
    'iam-policy-projection-v1',
    transaction_timestamp()
);

ALTER TABLE infra.consumer_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.consumer_principals FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_consumer_principal_owner_maintenance
ON infra.consumer_principals
FOR ALL TO schema_owner
USING (true)
WITH CHECK (true);

CREATE FUNCTION infra.consumer_session_matches_name(candidate_consumer_name text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL RESTRICTED
SET search_path = pg_catalog, infra
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM infra.consumer_principals AS principal
        WHERE principal.database_role = session_user::name
          AND principal.consumer_name = candidate_consumer_name
    )
$function$;

REVOKE ALL ON FUNCTION infra.consumer_session_matches_name(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION infra.consumer_session_matches_name(text)
    TO iam_projection_consumer;

CREATE TABLE infra.consumer_inbox_events (
    consumer_name varchar(96) NOT NULL,
    event_id uuid NOT NULL,
    event_type varchar(96) NOT NULL,
    schema_version integer NOT NULL,
    aggregate_type varchar(64) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    message_sha256 bytea NOT NULL,
    received_at timestamptz NOT NULL,
    processed_at timestamptz NOT NULL,
    CONSTRAINT pk_consumer_inbox_events PRIMARY KEY (consumer_name, event_id),
    CONSTRAINT ck_consumer_inbox_name CHECK (
        consumer_name ~ '^[a-z0-9][a-z0-9._-]{2,95}$'
    ),
    CONSTRAINT ck_consumer_inbox_event_type CHECK (
        event_type ~ '^[A-Za-z][A-Za-z0-9]{1,95}$'
    ),
    CONSTRAINT ck_consumer_inbox_schema_version CHECK (schema_version >= 1),
    CONSTRAINT ck_consumer_inbox_aggregate CHECK (
        aggregate_type ~ '^[A-Za-z][A-Za-z0-9]{1,63}$'
        AND aggregate_version >= 1
    ),
    CONSTRAINT ck_consumer_inbox_message_hash CHECK (
        octet_length(message_sha256) = 32
    ),
    CONSTRAINT ck_consumer_inbox_time CHECK (processed_at >= received_at)
);

CREATE INDEX ix_consumer_inbox_aggregate_version
    ON infra.consumer_inbox_events (
        consumer_name,
        aggregate_type,
        aggregate_id,
        aggregate_version,
        event_id
    );

CREATE FUNCTION infra.reject_consumer_inbox_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, infra
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'trg_consumer_inbox_append_only',
        MESSAGE = 'consumer inbox events are append only';
END
$function$;

CREATE TRIGGER trg_consumer_inbox_append_only
BEFORE UPDATE OR DELETE ON infra.consumer_inbox_events
FOR EACH ROW EXECUTE FUNCTION infra.reject_consumer_inbox_mutation();

ALTER TABLE infra.consumer_inbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.consumer_inbox_events FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_consumer_inbox_select
ON infra.consumer_inbox_events
FOR SELECT TO iam_projection_consumer
USING (
    consumer_name = NULLIF(current_setting('app.consumer_name', true), '')
    AND infra.consumer_session_matches_name(consumer_name)
);

CREATE POLICY rls_consumer_inbox_insert
ON infra.consumer_inbox_events
FOR INSERT TO iam_projection_consumer
WITH CHECK (
    consumer_name = NULLIF(current_setting('app.consumer_name', true), '')
    AND infra.consumer_session_matches_name(consumer_name)
);

CREATE POLICY rls_consumer_inbox_owner_maintenance
ON infra.consumer_inbox_events
FOR ALL TO schema_owner
USING (true)
WITH CHECK (true);

CREATE POLICY rls_outbox_worker_select
ON infra.outbox_events
FOR SELECT TO iam_outbox_worker
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'OUTBOX_DELIVERY'
    AND (
        (
            NULLIF(current_setting('app.operation', true), '')
                IN ('CLAIM', 'DEAD_EXHAUSTED')
            AND (
                (
                    delivery_status = 'PENDING'
                    AND available_at <= transaction_timestamp()
                )
                OR
                (
                    delivery_status = 'LEASED'
                    AND lease_until <= transaction_timestamp()
                )
            )
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') IN (
                'CLAIM',
                'MARK_PUBLISHED',
                'RESCHEDULE',
                'DEAD',
                'RELEASE_UNSTARTED'
            )
            AND delivery_status = 'LEASED'
            AND lease_owner = NULLIF(
                current_setting('app.outbox_worker_id', true),
                ''
            )
            AND lease_token = NULLIF(
                current_setting('app.outbox_claim_token', true),
                ''
            )::uuid
        )
        OR
        (
            event_id = NULLIF(
                current_setting('app.outbox_event_id', true),
                ''
            )::uuid
            AND (
                (
                    NULLIF(current_setting('app.operation', true), '')
                        = 'MARK_PUBLISHED'
                    AND delivery_status = 'PUBLISHED'
                )
                OR
                (
                    NULLIF(current_setting('app.operation', true), '')
                        IN ('RESCHEDULE', 'RELEASE_UNSTARTED')
                    AND delivery_status = 'PENDING'
                )
                OR
                (
                    NULLIF(current_setting('app.operation', true), '') = 'DEAD'
                    AND delivery_status = 'DEAD'
                )
            )
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '')
                = 'DEAD_EXHAUSTED'
            AND delivery_status = 'DEAD'
            AND last_error_code = 'DELIVERY_ATTEMPTS_EXHAUSTED'
        )
    )
);

CREATE POLICY rls_outbox_worker_update
ON infra.outbox_events
FOR UPDATE TO iam_outbox_worker
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'OUTBOX_DELIVERY'
    AND (
        (
            NULLIF(current_setting('app.operation', true), '')
                IN ('CLAIM', 'DEAD_EXHAUSTED')
            AND (
                (
                    delivery_status = 'PENDING'
                    AND available_at <= transaction_timestamp()
                )
                OR
                (
                    delivery_status = 'LEASED'
                    AND lease_until <= transaction_timestamp()
                )
            )
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') IN (
                'CLAIM',
                'MARK_PUBLISHED',
                'RESCHEDULE',
                'DEAD',
                'RELEASE_UNSTARTED'
            )
            AND delivery_status = 'LEASED'
            AND lease_owner = NULLIF(
                current_setting('app.outbox_worker_id', true),
                ''
            )
            AND lease_token = NULLIF(
                current_setting('app.outbox_claim_token', true),
                ''
            )::uuid
        )
    )
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'OUTBOX_DELIVERY'
    AND (
        (
            NULLIF(current_setting('app.operation', true), '') = 'CLAIM'
            AND delivery_status = 'LEASED'
            AND lease_owner = NULLIF(
                current_setting('app.outbox_worker_id', true),
                ''
            )
            AND lease_token = NULLIF(
                current_setting('app.outbox_claim_token', true),
                ''
            )::uuid
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') = 'DEAD_EXHAUSTED'
            AND delivery_status = 'DEAD'
            AND last_error_code = 'DELIVERY_ATTEMPTS_EXHAUSTED'
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') = 'MARK_PUBLISHED'
            AND delivery_status = 'PUBLISHED'
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') = 'RESCHEDULE'
            AND delivery_status = 'PENDING'
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') = 'DEAD'
            AND delivery_status = 'DEAD'
        )
        OR
        (
            NULLIF(current_setting('app.operation', true), '') = 'RELEASE_UNSTARTED'
            AND delivery_status = 'PENDING'
        )
    )
);

REVOKE ALL ON ALL TABLES IN SCHEMA infra FROM iam_projection_consumer;
GRANT USAGE ON SCHEMA infra TO iam_projection_consumer;

GRANT SELECT (
    event_id,
    event_type,
    schema_version,
    occurred_at,
    aggregate_type,
    aggregate_id,
    aggregate_version,
    actor_kind,
    actor_id,
    original_actor_id,
    correlation_id,
    causation_id,
    trace_id,
    organization_id,
    payload,
    delivery_status,
    attempt_count,
    available_at,
    lease_owner,
    leased_at,
    lease_token,
    lease_until,
    published_at,
    dead_at,
    last_error_code,
    created_at
) ON infra.outbox_events TO iam_outbox_worker;

GRANT UPDATE (
    delivery_status,
    attempt_count,
    available_at,
    lease_owner,
    leased_at,
    lease_token,
    lease_until,
    published_at,
    dead_at,
    last_error_code
) ON infra.outbox_events TO iam_outbox_worker;

GRANT SELECT (
    consumer_name,
    event_id,
    event_type,
    schema_version,
    aggregate_type,
    aggregate_id,
    aggregate_version,
    message_sha256,
    received_at,
    processed_at
) ON infra.consumer_inbox_events TO iam_projection_consumer;

GRANT INSERT (
    consumer_name,
    event_id,
    event_type,
    schema_version,
    aggregate_type,
    aggregate_id,
    aggregate_version,
    message_sha256,
    received_at,
    processed_at
) ON infra.consumer_inbox_events TO iam_projection_consumer;

REVOKE ALL ON TABLE infra.consumer_principals FROM PUBLIC;
REVOKE ALL ON TABLE infra.consumer_principals FROM iam_projection_consumer;
REVOKE ALL ON TABLE infra.consumer_inbox_events FROM PUBLIC;
REVOKE ALL ON FUNCTION infra.reject_consumer_inbox_mutation() FROM PUBLIC;
