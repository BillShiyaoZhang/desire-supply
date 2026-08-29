-- PostgreSQL-authoritative INTERNAL_SANDBOX Demand review queue and claim.

CREATE TABLE demand.review_claim_receipts (
    receipt_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    command_name varchar(64) NOT NULL,
    command_version integer NOT NULL,
    idempotency_key_digest_key_id varchar(128) NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    payload_hash bytea NOT NULL,
    expected_demand_revision bigint NOT NULL,
    status varchar(16) NOT NULL,
    assignment_id uuid NULL,
    assignment_expires_at timestamptz NULL,
    response_entity_tag varchar(128) NULL,
    event_types text[] NULL,
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_review_claim_receipt_identity UNIQUE (
        principal_id,
        command_name,
        command_version,
        idempotency_key_digest_key_id,
        idempotency_key_digest
    ),
    CONSTRAINT fk_review_claim_receipt_demand FOREIGN KEY (
        organization_id, demand_id
    ) REFERENCES demand.demands (organization_id, id),
    CONSTRAINT fk_review_claim_receipt_assignment FOREIGN KEY (
        organization_id, demand_id, assignment_id
    ) REFERENCES demand.demand_review_assignments (
        organization_id, demand_id, id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_review_claim_receipt_identity CHECK (
        command_name = 'ClaimDemandReview'
        AND command_version = 1
        AND canonicalization_version = 'demand-command-json-v1'
        AND idempotency_key_digest_key_id <> payload_hash_key_id
        AND octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
        AND expected_demand_revision >= 1
        AND retain_until >= created_at
    ),
    CONSTRAINT ck_review_claim_receipt_shape CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
        AND (
            (
                status = 'IN_PROGRESS'
                AND assignment_id IS NULL
                AND assignment_expires_at IS NULL
                AND response_entity_tag IS NULL
                AND event_types IS NULL
                AND completed_at IS NULL
            )
            OR
            (
                status = 'COMPLETED'
                AND assignment_id IS NOT NULL
                AND assignment_expires_at > created_at
                AND response_entity_tag IS NOT NULL
                AND event_types = ARRAY['DemandReviewClaimed']::text[]
                AND completed_at >= created_at
            )
        )
    )
);

ALTER TABLE demand.review_claim_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.review_claim_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE demand.review_claim_receipts FROM PUBLIC;

CREATE FUNCTION demand.protect_review_assignment_v2()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.demand_id IS DISTINCT FROM OLD.demand_id
       OR NEW.submission_id IS DISTINCT FROM OLD.submission_id
       OR NEW.demand_version_id IS DISTINCT FROM OLD.demand_version_id
       OR NEW.reviewer_user_id IS DISTINCT FROM OLD.reviewer_user_id
       OR NEW.duty_grant_id IS DISTINCT FROM OLD.duty_grant_id
       OR NEW.duty_grant_version IS DISTINCT FROM OLD.duty_grant_version
       OR NEW.purpose_code IS DISTINCT FROM OLD.purpose_code
       OR NEW.conflict_attestation_sha256
            IS DISTINCT FROM OLD.conflict_attestation_sha256
       OR NEW.authority_marker_sha256
            IS DISTINCT FROM OLD.authority_marker_sha256
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.status <> 'ACTIVE'
       OR NEW.status NOT IN ('COMPLETED', 'REVOKED')
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR NEW.completed_at IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_demand_review_assignment_v2',
            MESSAGE = 'Demand review assignment mutation is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_demand_review_assignment_v2
BEFORE UPDATE OR DELETE ON demand.demand_review_assignments
FOR EACH ROW EXECUTE FUNCTION demand.protect_review_assignment_v2();

REVOKE ALL ON FUNCTION demand.protect_review_assignment_v2() FROM PUBLIC;

CREATE POLICY rls_review_queue_root_definer
ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_REVIEW_QUEUE'
        OR (
            NULLIF(current_setting('app.operation', true), '') IN (
                'RESOLVE_REVIEW_QUEUE_TARGET', 'CLAIM_REVIEW'
            )
            AND id::text = NULLIF(
                current_setting('app.demand_id', true), ''
            )
        )
    )
);

CREATE POLICY rls_review_queue_version_definer
ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_REVIEW_QUEUE'
        OR (
            NULLIF(current_setting('app.operation', true), '') IN (
                'RESOLVE_REVIEW_QUEUE_TARGET', 'CLAIM_REVIEW'
            )
            AND demand_id::text = NULLIF(
                current_setting('app.demand_id', true), ''
            )
        )
    )
);

CREATE POLICY rls_review_queue_submission_definer
ON demand.demand_submissions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_REVIEW_QUEUE'
        OR (
            NULLIF(current_setting('app.operation', true), '') IN (
                'RESOLVE_REVIEW_QUEUE_TARGET', 'CLAIM_REVIEW'
            )
            AND demand_id::text = NULLIF(
                current_setting('app.demand_id', true), ''
            )
        )
    )
);

CREATE POLICY rls_review_queue_assignment_definer
ON demand.demand_review_assignments
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_REVIEW_QUEUE'
        OR (
            NULLIF(current_setting('app.operation', true), '')
                = 'CLAIM_REVIEW'
            AND demand_id::text = NULLIF(
                current_setting('app.demand_id', true), ''
            )
        )
    )
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
    AND reviewer_user_id::text = NULLIF(
        current_setting('app.actor_id', true), ''
    )
);

CREATE POLICY rls_review_claim_receipt_definer
ON demand.review_claim_receipts
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
    AND principal_id::text = NULLIF(
        current_setting('app.actor_id', true), ''
    )
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
    AND principal_id::text = NULLIF(
        current_setting('app.actor_id', true), ''
    )
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
);

CREATE POLICY rls_review_queue_key_policy_definer
ON demand.receipt_key_policy
FOR SELECT TO demand_schema_owner
USING (
    singleton_key
    AND session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
);

CREATE FUNCTION demand_api.list_available_demand_reviews_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea,
    maximum_items integer
)
RETURNS TABLE (
    demand_id uuid,
    demand_revision bigint,
    demand_version_no integer,
    submitted_at timestamptz,
    demand_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR maximum_items NOT BETWEEN 1 AND 100
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_REVIEW_QUEUE'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NOT EXISTS (
            SELECT 1
            FROM iam_api.authorize_demand_review_queue_v1(
                exact_actor_user_id,
                exact_session_id,
                expected_principal_marker_sha256
            )
       ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        root.id,
        root.aggregate_version,
        version.version_no,
        submission.submitted_at,
        root.expires_at
    FROM demand.demands AS root
    JOIN demand.demand_versions AS version
      ON version.organization_id = root.organization_id
     AND version.demand_id = root.id
     AND version.id = root.current_version_id
    JOIN demand.demand_submissions AS submission
      ON submission.organization_id = root.organization_id
     AND submission.demand_id = root.id
     AND submission.id = root.current_submission_id
     AND submission.demand_version_id = root.current_version_id
     AND submission.content_sha256 = version.content_sha256
    WHERE root.status = 'SUBMITTED'
      AND root.creator_user_id <> exact_actor_user_id
      AND transaction_timestamp() < root.expires_at
      AND NOT EXISTS (
          SELECT 1
          FROM demand.demand_review_assignments AS assignment
          WHERE assignment.organization_id = root.organization_id
            AND assignment.demand_id = root.id
            AND assignment.status = 'ACTIVE'
            AND transaction_timestamp() < assignment.expires_at
      )
    ORDER BY submission.submitted_at, root.id
    LIMIT maximum_items;
END
$function$;

CREATE FUNCTION demand_api.resolve_review_queue_target_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_demand_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    organization_id uuid,
    demand_revision bigint,
    demand_version_id uuid,
    submission_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_demand_id IS NULL
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'RESOLVE_REVIEW_QUEUE_TARGET'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NOT EXISTS (
            SELECT 1
            FROM iam_api.authorize_demand_review_queue_v1(
                exact_actor_user_id,
                exact_session_id,
                expected_principal_marker_sha256
            )
       ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        root.organization_id,
        root.aggregate_version,
        root.current_version_id,
        root.current_submission_id
    FROM demand.demands AS root
    WHERE root.id = exact_demand_id
      AND root.status = 'SUBMITTED'
      AND root.creator_user_id <> exact_actor_user_id
      AND root.current_submission_id IS NOT NULL
      AND transaction_timestamp() < root.expires_at;
END
$function$;

CREATE FUNCTION demand_api.claim_demand_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    expected_demand_revision bigint,
    expected_principal_marker_sha256 bytea,
    new_assignment_id uuid,
    new_receipt_id uuid,
    exact_idempotency_key_digest_key_id text,
    exact_idempotency_key_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    new_audit_event_id uuid,
    new_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (
    assignment_id uuid,
    demand_id uuid,
    demand_revision bigint,
    assignment_status text,
    assignment_expires_at timestamptz,
    response_entity_tag text,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, audit, infra, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    now_at timestamptz := transaction_timestamp();
    root_row record;
    submission_row record;
    version_hash bytea;
    authority_row record;
    receipt_row demand.review_claim_receipts%ROWTYPE;
    active_assignment record;
    expires_at timestamptz;
    conflict_digest bytea;
    result_etag text;
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR new_assignment_id IS NULL OR new_assignment_id = zero_uuid
       OR new_receipt_id IS NULL OR new_receipt_id = zero_uuid
       OR new_audit_event_id IS NULL OR new_audit_event_id = zero_uuid
       OR new_outbox_event_id IS NULL OR new_outbox_event_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR expected_demand_revision < 1
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR exact_idempotency_key_digest_key_id IS NULL
       OR length(exact_idempotency_key_digest_key_id) NOT BETWEEN 1 AND 128
       OR exact_payload_hash_key_id IS NULL
       OR length(exact_payload_hash_key_id) NOT BETWEEN 1 AND 128
       OR exact_idempotency_key_digest_key_id = exact_payload_hash_key_id
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text THEN
        RETURN;
    END IF;

    SELECT * INTO authority_row
    FROM iam_api.lock_demand_review_claim_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        exact_demand_id,
        expected_principal_marker_sha256
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        root.organization_id,
        root.creator_user_id,
        root.status,
        root.aggregate_version,
        root.current_version_id,
        root.current_submission_id,
        root.expires_at
    INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id
    FOR UPDATE;
    IF NOT FOUND OR root_row.creator_user_id = exact_actor_user_id THEN
        RETURN;
    END IF;

    PERFORM 1
    FROM demand.receipt_key_policy AS key_policy
    WHERE key_policy.singleton_key
      AND exact_idempotency_key_digest_key_id
            = ANY(key_policy.retained_idempotency_key_ids)
      AND exact_payload_hash_key_id
            = ANY(key_policy.retained_payload_key_ids)
      AND 'demand-command-json-v1'
            = ANY(key_policy.retained_canonicalization_versions);
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'review_claim_key_policy_unavailable',
            MESSAGE = 'review claim key policy is unavailable';
    END IF;

    INSERT INTO demand.review_claim_receipts (
        receipt_id,
        principal_id,
        organization_id,
        demand_id,
        command_name,
        command_version,
        idempotency_key_digest_key_id,
        idempotency_key_digest,
        payload_hash_key_id,
        canonicalization_version,
        payload_hash,
        expected_demand_revision,
        status,
        retain_until,
        created_at
    ) VALUES (
        new_receipt_id,
        exact_actor_user_id,
        exact_organization_id,
        exact_demand_id,
        'ClaimDemandReview',
        1,
        exact_idempotency_key_digest_key_id,
        exact_idempotency_key_digest,
        exact_payload_hash_key_id,
        'demand-command-json-v1',
        exact_payload_hash,
        expected_demand_revision,
        'IN_PROGRESS',
        now_at + interval '7 days',
        now_at
    ) ON CONFLICT DO NOTHING;

    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.review_claim_receipts AS receipt
        WHERE receipt.receipt_id = new_receipt_id
           OR (
                receipt.principal_id = exact_actor_user_id
                AND receipt.command_name = 'ClaimDemandReview'
                AND receipt.command_version = 1
                AND receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_id
                AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digest
           )
        FOR UPDATE;
        IF NOT FOUND
           OR receipt_row.organization_id <> exact_organization_id
           OR receipt_row.demand_id <> exact_demand_id
           OR receipt_row.expected_demand_revision <> expected_demand_revision
           OR receipt_row.payload_hash_key_id <> exact_payload_hash_key_id
           OR receipt_row.payload_hash <> exact_payload_hash THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'review_claim_idempotency_reused',
                MESSAGE = 'review claim receipt conflict';
        END IF;
        IF receipt_row.status <> 'COMPLETED'
           OR receipt_row.assignment_id IS NULL
           OR receipt_row.assignment_expires_at IS NULL
           OR receipt_row.response_entity_tag IS NULL
           OR receipt_row.event_types
                <> ARRAY['DemandReviewClaimed']::text[] THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'review_claim_receipt_incomplete',
                MESSAGE = 'review claim receipt is incomplete';
        END IF;
        RETURN QUERY SELECT
            receipt_row.assignment_id,
            receipt_row.demand_id,
            receipt_row.expected_demand_revision,
            'ACTIVE'::text,
            receipt_row.assignment_expires_at,
            receipt_row.response_entity_tag::text,
            true;
        RETURN;
    END IF;

    IF root_row.aggregate_version <> expected_demand_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            CONSTRAINT = 'review_claim_precondition_failed',
            MESSAGE = 'review claim precondition failed';
    END IF;
    IF root_row.status <> 'SUBMITTED'
       OR root_row.current_submission_id IS NULL
       OR now_at >= root_row.expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'review_claim_resource_not_found',
            MESSAGE = 'review queue target is unavailable';
    END IF;

    SELECT submission.demand_version_id, submission.content_sha256
    INTO submission_row
    FROM demand.demand_submissions AS submission
    WHERE submission.organization_id = exact_organization_id
      AND submission.demand_id = exact_demand_id
      AND submission.id = root_row.current_submission_id
      AND submission.demand_version_id = root_row.current_version_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'review_claim_resource_not_found',
            MESSAGE = 'review queue submission is unavailable';
    END IF;

    SELECT version.content_sha256 INTO version_hash
    FROM demand.demand_versions AS version
    WHERE version.organization_id = exact_organization_id
      AND version.demand_id = exact_demand_id
      AND version.id = root_row.current_version_id
    FOR SHARE;
    IF NOT FOUND OR version_hash <> submission_row.content_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'review_claim_resource_not_found',
            MESSAGE = 'review queue version is unavailable';
    END IF;

    SELECT assignment.id, assignment.status, assignment.expires_at
    INTO active_assignment
    FROM demand.demand_review_assignments AS assignment
    WHERE assignment.organization_id = exact_organization_id
      AND assignment.demand_id = exact_demand_id
      AND assignment.status = 'ACTIVE'
    FOR UPDATE;
    IF FOUND AND now_at < active_assignment.expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'review_already_claimed',
            MESSAGE = 'review already claimed';
    ELSIF FOUND THEN
        UPDATE demand.demand_review_assignments
        SET status = 'REVOKED',
            aggregate_version = aggregate_version + 1,
            completed_at = now_at
        WHERE id = active_assignment.id;
    END IF;

    expires_at := LEAST(
        now_at + interval '30 minutes',
        root_row.expires_at,
        COALESCE(
            authority_row.duty_expires_at,
            now_at + interval '30 minutes'
        )
    );
    IF expires_at <= now_at THEN
        RETURN;
    END IF;
    conflict_digest := sha256(convert_to(
        'demand-review-conflict-v1|' || exact_actor_user_id::text || '|' ||
        exact_organization_id::text || '|' || exact_demand_id::text || '|' ||
        root_row.current_submission_id::text || '|' ||
        root_row.current_version_id::text || '|' ||
        authority_row.duty_grant_id::text || '|' ||
        authority_row.duty_grant_version::text,
        'UTF8'
    ));

    INSERT INTO demand.demand_review_assignments (
        id,
        organization_id,
        demand_id,
        submission_id,
        demand_version_id,
        reviewer_user_id,
        duty_grant_id,
        duty_grant_version,
        purpose_code,
        conflict_attestation_sha256,
        authority_marker_sha256,
        status,
        expires_at,
        aggregate_version,
        created_at
    ) VALUES (
        new_assignment_id,
        exact_organization_id,
        exact_demand_id,
        root_row.current_submission_id,
        root_row.current_version_id,
        exact_actor_user_id,
        authority_row.duty_grant_id,
        authority_row.duty_grant_version,
        'DEMAND_REVIEW',
        conflict_digest,
        authority_row.authority_marker_sha256,
        'ACTIVE',
        expires_at,
        1,
        now_at
    );

    result_etag := '"demand-' || expected_demand_revision::text || '-review-queue"';

    INSERT INTO audit.audit_events (
        event_id,
        occurred_at,
        actor_kind,
        actor_id,
        original_actor_id,
        action_code,
        target_kind,
        target_id,
        organization_id,
        before_status,
        after_status,
        before_version,
        after_version,
        role_code,
        purpose_code,
        reason_code,
        auth_strength_code,
        result_code,
        command_id,
        correlation_id,
        causation_id,
        trace_id,
        safe_attributes
    ) VALUES (
        new_audit_event_id,
        now_at,
        'USER',
        exact_actor_user_id,
        NULL,
        'CLAIM_DEMAND_REVIEW',
        'Demand',
        exact_demand_id,
        exact_organization_id,
        'SUBMITTED',
        'SUBMITTED',
        expected_demand_revision,
        expected_demand_revision,
        'OPERATIONS_REVIEWER',
        'DEMAND_REVIEW',
        NULL,
        NULL,
        'SUCCEEDED',
        new_receipt_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        jsonb_build_object(
            'demand_version_id', root_row.current_version_id::text,
            'submission_id', root_row.current_submission_id::text
        )
    );

    INSERT INTO infra.outbox_events (
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
        created_at
    ) VALUES (
        new_outbox_event_id,
        'DemandReviewClaimed',
        1,
        now_at,
        'Demand',
        exact_demand_id,
        expected_demand_revision,
        'USER',
        exact_actor_user_id,
        NULL,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        exact_organization_id,
        jsonb_build_object(
            'demand_id', exact_demand_id::text,
            'demand_version_id', root_row.current_version_id::text,
            'status', 'SUBMITTED'
        ),
        'PENDING',
        0,
        now_at,
        now_at
    );

    UPDATE demand.review_claim_receipts
    SET status = 'COMPLETED',
        assignment_id = new_assignment_id,
        assignment_expires_at = expires_at,
        response_entity_tag = result_etag,
        event_types = ARRAY['DemandReviewClaimed']::text[],
        completed_at = now_at
    WHERE receipt_id = new_receipt_id;

    RETURN QUERY SELECT
        new_assignment_id,
        exact_demand_id,
        expected_demand_revision,
        'ACTIVE'::text,
        expires_at,
        result_etag,
        false;
END
$function$;

ALTER FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.resolve_review_queue_target_v1(
    uuid, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) OWNER TO demand_schema_owner;

REVOKE ALL ON FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.resolve_review_queue_target_v1(
    uuid, uuid, uuid, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
GRANT USAGE ON SCHEMA demand_api TO demand_review;
GRANT EXECUTE ON FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) TO demand_review;
GRANT EXECUTE ON FUNCTION demand_api.resolve_review_queue_target_v1(
    uuid, uuid, uuid, bytea
) TO demand_review;
GRANT EXECUTE ON FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_review;

SET LOCAL ROLE schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO demand_schema_owner;
GRANT INSERT ON audit.audit_events TO demand_schema_owner;
GRANT INSERT ON infra.outbox_events TO demand_schema_owner;

CREATE POLICY rls_review_claim_audit_definer
ON audit.audit_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
    AND actor_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND target_kind = 'Demand'
    AND target_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
    AND action_code = 'CLAIM_DEMAND_REVIEW'
);

CREATE POLICY rls_review_claim_outbox_definer
ON infra.outbox_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
    AND actor_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND aggregate_type = 'Demand'
    AND aggregate_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
    AND event_type = 'DemandReviewClaimed'
);

SET LOCAL ROLE demand_schema_owner;

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'demand'
      AND relation.relname = 'review_claim_receipts'
      AND (
          relation.relkind <> 'r'
          OR NOT relation.relrowsecurity
          OR NOT relation.relforcerowsecurity
      );
    IF invalid_count <> 0
       OR pg_catalog.has_table_privilege(
            'demand_review',
            'demand.review_claim_receipts',
            'SELECT,INSERT,UPDATE,DELETE'
       )
       OR pg_catalog.has_table_privilege(
            'demand_review',
            'demand.demand_review_assignments',
            'INSERT'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.claim_demand_review_v1(uuid,uuid,uuid,uuid,bigint,bytea,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand review queue assertion failed';
    END IF;
END
$assert$;
