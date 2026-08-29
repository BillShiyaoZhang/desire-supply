CREATE TABLE infra.command_receipts (
    id uuid NOT NULL,
    principal_kind text NOT NULL,
    principal_id uuid NOT NULL,
    command_name varchar(96) NOT NULL,
    command_version integer NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    idempotency_key_digest_key_id varchar(64) NOT NULL,
    payload_hash bytea NOT NULL,
    payload_hash_key_id varchar(64) NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    target_kind varchar(64) NOT NULL,
    target_id uuid NOT NULL,
    http_method varchar(16) NOT NULL,
    canonical_path varchar(512) NOT NULL,
    if_match_version bigint NULL,
    status text NOT NULL,
    response_schema_version integer NULL,
    safe_response_body jsonb NULL,
    reconstruction_metadata jsonb NULL,
    created_at timestamptz NOT NULL,
    retain_until timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT pk_command_receipts PRIMARY KEY (id),
    CONSTRAINT uq_command_receipt_identity UNIQUE (
        principal_kind,
        principal_id,
        command_name,
        command_version,
        idempotency_key_digest
    ),
    CONSTRAINT ck_command_receipt_principal CHECK (
        principal_kind IN ('USER', 'SYSTEM')
    ),
    CONSTRAINT ck_command_receipt_version CHECK (command_version >= 1),
    CONSTRAINT ck_command_receipt_digests CHECK (
        octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
    ),
    CONSTRAINT ck_command_receipt_canonicalization CHECK (
        canonicalization_version = 'restricted-canonical-json-v1'
    ),
    CONSTRAINT ck_command_receipt_http CHECK (
        http_method IN ('POST', 'PUT', 'PATCH', 'DELETE')
        AND canonical_path ~ '^/v1/'
    ),
    CONSTRAINT ck_command_receipt_status CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
    ),
    CONSTRAINT ck_command_receipt_response_shape CHECK (
        (
            status = 'IN_PROGRESS'
            AND response_schema_version IS NULL
            AND safe_response_body IS NULL
            AND reconstruction_metadata IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            status = 'COMPLETED'
            AND response_schema_version >= 1
            AND safe_response_body IS NOT NULL
            AND jsonb_typeof(safe_response_body) = 'object'
            AND (
                reconstruction_metadata IS NULL
                OR jsonb_typeof(reconstruction_metadata) = 'object'
            )
            AND completed_at IS NOT NULL
        )
    ),
    CONSTRAINT ck_command_receipt_accept_shape CHECK (
        command_name <> 'AcceptAccessInvitation'
        OR (
            command_version = 1
            AND target_kind = 'AccessInvitation'
            AND http_method = 'POST'
            AND if_match_version >= 1
            AND reconstruction_metadata IS NULL
            AND canonical_path ~ '^/v1/access-invitations/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/accept$'
        )
    ),
    CONSTRAINT ck_command_receipt_time CHECK (
        retain_until > created_at
        AND (
            completed_at IS NULL
            OR (completed_at >= created_at AND completed_at < retain_until)
        )
    )
);

CREATE INDEX ix_receipt_idempotency_key_retention
    ON infra.command_receipts (idempotency_key_digest_key_id, retain_until);
CREATE INDEX ix_receipt_payload_key_retention
    ON infra.command_receipts (payload_hash_key_id, retain_until);
CREATE INDEX ix_receipt_canonicalizer_retention
    ON infra.command_receipts (canonicalization_version, retain_until);

CREATE FUNCTION infra.enforce_command_receipt_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, infra
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.command_name IS DISTINCT FROM OLD.command_name
       OR NEW.command_version IS DISTINCT FROM OLD.command_version
       OR NEW.idempotency_key_digest IS DISTINCT FROM OLD.idempotency_key_digest
       OR NEW.idempotency_key_digest_key_id IS DISTINCT FROM OLD.idempotency_key_digest_key_id
       OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
       OR NEW.payload_hash_key_id IS DISTINCT FROM OLD.payload_hash_key_id
       OR NEW.canonicalization_version IS DISTINCT FROM OLD.canonicalization_version
       OR NEW.target_kind IS DISTINCT FROM OLD.target_kind
       OR NEW.target_id IS DISTINCT FROM OLD.target_id
       OR NEW.http_method IS DISTINCT FROM OLD.http_method
       OR NEW.canonical_path IS DISTINCT FROM OLD.canonical_path
       OR NEW.if_match_version IS DISTINCT FROM OLD.if_match_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.retain_until IS DISTINCT FROM OLD.retain_until
       OR OLD.status <> 'IN_PROGRESS'
       OR NEW.status <> 'COMPLETED' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_command_receipt_transition',
            MESSAGE = 'invalid command receipt mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_command_receipt_transition
BEFORE UPDATE ON infra.command_receipts
FOR EACH ROW EXECUTE FUNCTION infra.enforce_command_receipt_transition();

CREATE FUNCTION infra.enforce_receipt_completed_at_commit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, infra
AS $function$
DECLARE
    current_receipt infra.command_receipts%ROWTYPE;
BEGIN
    SELECT * INTO current_receipt
    FROM infra.command_receipts
    WHERE id = NEW.id;

    IF NOT FOUND
       OR current_receipt.status <> 'COMPLETED'
       OR current_receipt.response_schema_version IS NULL
       OR current_receipt.safe_response_body IS NULL
       OR current_receipt.completed_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_receipt_completed_at_commit',
            MESSAGE = 'command receipt must be completed at commit';
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER trg_receipt_completed_at_commit
AFTER INSERT OR UPDATE ON infra.command_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION infra.enforce_receipt_completed_at_commit();

CREATE TABLE infra.iam_receipt_key_policy (
    singleton_key boolean NOT NULL,
    policy_version bigint NOT NULL,
    active_idempotency_key_id varchar(64) NOT NULL,
    active_payload_hash_key_id varchar(64) NOT NULL,
    active_canonicalization_version varchar(64) NOT NULL,
    retained_idempotency_key_ids varchar(64)[] NOT NULL,
    retained_payload_hash_key_ids varchar(64)[] NOT NULL,
    retained_canonicalization_versions varchar(64)[] NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_iam_receipt_key_policy PRIMARY KEY (singleton_key),
    CONSTRAINT ck_receipt_key_policy_singleton CHECK (singleton_key),
    CONSTRAINT ck_receipt_key_policy_version CHECK (policy_version >= 1),
    CONSTRAINT ck_receipt_key_policy_idempotency_set CHECK (
        iam.text_array_is_unique_nonnull(retained_idempotency_key_ids::text[])
        AND active_idempotency_key_id = ANY (retained_idempotency_key_ids)
    ),
    CONSTRAINT ck_receipt_key_policy_payload_set CHECK (
        iam.text_array_is_unique_nonnull(retained_payload_hash_key_ids::text[])
        AND active_payload_hash_key_id = ANY (retained_payload_hash_key_ids)
    ),
    CONSTRAINT ck_receipt_key_policy_canonicalizer_set CHECK (
        iam.text_array_is_unique_nonnull(retained_canonicalization_versions::text[])
        AND active_canonicalization_version = ANY (retained_canonicalization_versions)
        AND 'restricted-canonical-json-v1' = ANY (retained_canonicalization_versions)
    )
);

CREATE FUNCTION infra.enforce_receipt_key_policy_retention()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, infra
AS $function$
BEGIN
    IF NEW.singleton_key IS DISTINCT FROM OLD.singleton_key
       OR NEW.policy_version <> OLD.policy_version + 1
       OR NEW.updated_at < OLD.updated_at
       OR EXISTS (
            SELECT 1
            FROM infra.command_receipts AS receipt
            WHERE receipt.retain_until > transaction_timestamp()
              AND NOT (
                  receipt.idempotency_key_digest_key_id
                  = ANY (NEW.retained_idempotency_key_ids)
              )
       )
       OR EXISTS (
            SELECT 1
            FROM infra.command_receipts AS receipt
            WHERE receipt.retain_until > transaction_timestamp()
              AND NOT (
                  receipt.payload_hash_key_id
                  = ANY (NEW.retained_payload_hash_key_ids)
              )
       )
       OR EXISTS (
            SELECT 1
            FROM infra.command_receipts AS receipt
            WHERE receipt.retain_until > transaction_timestamp()
              AND NOT (
                  receipt.canonicalization_version
                  = ANY (NEW.retained_canonicalization_versions)
              )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_receipt_key_policy_retention',
            MESSAGE = 'receipt verification policy update is unsafe';
    END IF;
    RETURN NEW;
END
$function$;

REVOKE ALL ON FUNCTION infra.enforce_receipt_key_policy_retention() FROM PUBLIC;

CREATE TRIGGER trg_receipt_key_policy_retention
BEFORE UPDATE ON infra.iam_receipt_key_policy
FOR EACH ROW EXECUTE FUNCTION infra.enforce_receipt_key_policy_retention();

INSERT INTO infra.iam_receipt_key_policy (
    singleton_key,
    policy_version,
    active_idempotency_key_id,
    active_payload_hash_key_id,
    active_canonicalization_version,
    retained_idempotency_key_ids,
    retained_payload_hash_key_ids,
    retained_canonicalization_versions,
    updated_at
) VALUES (
    true,
    1,
    'iam-receipt-idempotency-hmac-2026-01',
    'iam-receipt-payload-hmac-2026-01',
    'restricted-canonical-json-v1',
    ARRAY['iam-receipt-idempotency-hmac-2026-01']::varchar(64)[],
    ARRAY['iam-receipt-payload-hmac-2026-01']::varchar(64)[],
    ARRAY['restricted-canonical-json-v1']::varchar(64)[],
    transaction_timestamp()
);

CREATE TABLE audit.audit_events (
    event_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor_kind text NOT NULL,
    actor_id uuid NOT NULL,
    original_actor_id uuid NULL,
    action_code varchar(96) NOT NULL,
    target_kind varchar(64) NOT NULL,
    target_id uuid NOT NULL,
    organization_id uuid NULL,
    before_status varchar(64) NULL,
    after_status varchar(64) NULL,
    before_version bigint NULL,
    after_version bigint NULL,
    role_code varchar(128) NULL,
    purpose_code varchar(128) NULL,
    reason_code varchar(128) NULL,
    auth_strength_code varchar(128) NULL,
    result_code varchar(64) NOT NULL,
    command_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid NOT NULL,
    trace_id uuid NOT NULL,
    safe_attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT pk_audit_events PRIMARY KEY (event_id),
    CONSTRAINT ck_audit_event_actor CHECK (actor_kind IN ('USER', 'SYSTEM')),
    CONSTRAINT ck_audit_event_action CHECK (length(action_code) > 0),
    CONSTRAINT ck_audit_event_versions CHECK (
        (before_version IS NULL OR before_version >= 1)
        AND (after_version IS NULL OR after_version >= 1)
    ),
    CONSTRAINT ck_audit_event_safe_attributes CHECK (
        jsonb_typeof(safe_attributes) = 'object'
    )
);

CREATE FUNCTION audit.reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, audit
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'trg_audit_event_append_only',
        MESSAGE = 'audit events are append only';
END
$function$;

CREATE TRIGGER trg_audit_event_append_only
BEFORE UPDATE OR DELETE ON audit.audit_events
FOR EACH ROW EXECUTE FUNCTION audit.reject_audit_event_mutation();

CREATE TABLE infra.outbox_events (
    event_id uuid NOT NULL,
    event_type varchar(96) NOT NULL,
    schema_version integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    aggregate_type varchar(64) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    actor_kind text NOT NULL,
    actor_id uuid NOT NULL,
    original_actor_id uuid NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid NOT NULL,
    trace_id uuid NOT NULL,
    organization_id uuid NULL,
    payload jsonb NOT NULL,
    delivery_status text NOT NULL,
    attempt_count integer NOT NULL,
    available_at timestamptz NOT NULL,
    lease_owner varchar(128) NULL,
    lease_until timestamptz NULL,
    published_at timestamptz NULL,
    last_error_code varchar(64) NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_outbox_events PRIMARY KEY (event_id),
    CONSTRAINT uq_outbox_command_event UNIQUE (
        causation_id,
        event_type,
        aggregate_type,
        aggregate_id
    ),
    CONSTRAINT ck_outbox_schema_version CHECK (schema_version = 1),
    CONSTRAINT ck_outbox_aggregate_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_outbox_actor CHECK (actor_kind IN ('USER', 'SYSTEM')),
    CONSTRAINT ck_outbox_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_outbox_delivery_status CHECK (
        delivery_status IN ('PENDING', 'LEASED', 'PUBLISHED', 'DEAD')
    ),
    CONSTRAINT ck_outbox_attempt_count CHECK (attempt_count >= 0),
    CONSTRAINT ck_outbox_delivery_shape CHECK (
        (
            delivery_status = 'PENDING'
            AND lease_owner IS NULL
            AND lease_until IS NULL
            AND published_at IS NULL
        )
        OR
        (
            delivery_status = 'LEASED'
            AND lease_owner IS NOT NULL
            AND lease_until IS NOT NULL
            AND published_at IS NULL
        )
        OR
        (
            delivery_status = 'PUBLISHED'
            AND lease_owner IS NULL
            AND lease_until IS NULL
            AND published_at IS NOT NULL
        )
        OR
        (
            delivery_status = 'DEAD'
            AND lease_owner IS NULL
            AND lease_until IS NULL
            AND published_at IS NULL
            AND last_error_code IS NOT NULL
        )
    ),
    CONSTRAINT ck_outbox_time CHECK (
        available_at >= occurred_at
        AND created_at >= occurred_at
        AND (lease_until IS NULL OR lease_until > available_at)
        AND (published_at IS NULL OR published_at >= occurred_at)
    )
);

CREATE INDEX ix_outbox_delivery_queue
    ON infra.outbox_events (delivery_status, available_at, event_id);

CREATE FUNCTION infra.enforce_outbox_envelope_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, infra
AS $function$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
       OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
       OR NEW.aggregate_version IS DISTINCT FROM OLD.aggregate_version
       OR NEW.actor_kind IS DISTINCT FROM OLD.actor_kind
       OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
       OR NEW.original_actor_id IS DISTINCT FROM OLD.original_actor_id
       OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
       OR NEW.causation_id IS DISTINCT FROM OLD.causation_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.attempt_count < OLD.attempt_count
       OR (OLD.delivery_status = 'PENDING' AND NEW.delivery_status NOT IN ('PENDING', 'LEASED', 'DEAD'))
       OR (OLD.delivery_status = 'LEASED' AND NEW.delivery_status NOT IN ('PENDING', 'LEASED', 'PUBLISHED', 'DEAD'))
       OR (OLD.delivery_status IN ('PUBLISHED', 'DEAD') AND NEW.delivery_status <> OLD.delivery_status) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_outbox_envelope_immutable',
            MESSAGE = 'outbox envelope is immutable';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_outbox_envelope_immutable
BEFORE UPDATE OR DELETE ON infra.outbox_events
FOR EACH ROW EXECUTE FUNCTION infra.enforce_outbox_envelope_immutable();

REVOKE ALL ON ALL TABLES IN SCHEMA infra FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA infra FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA audit FROM PUBLIC;
