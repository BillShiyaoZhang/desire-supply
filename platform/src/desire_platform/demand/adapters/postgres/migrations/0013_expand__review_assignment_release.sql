-- Reviewer-controlled release of an active Demand review assignment, plus
-- exact completed-receipt recovery after the ACTIVE assignment disappears.

SET LOCAL search_path = pg_catalog, demand;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_migration_runner'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname = 'iam_api'
              AND procedure.proname = 'lock_demand_reviewer_authority_v2'
              AND pg_get_functiondef(procedure.oid)
                    LIKE '%RELEASE_REVIEW_ASSIGNMENT%'
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND13_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

CREATE TABLE demand.demand_review_assignment_releases (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    submission_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    assignment_id uuid NOT NULL UNIQUE,
    reviewer_user_id uuid NOT NULL,
    reason_code varchar(32) NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    released_at timestamptz NOT NULL,
    CONSTRAINT uq_demand_review_release_org_id UNIQUE (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_demand_review_release_assignment FOREIGN KEY (
        organization_id, demand_id, assignment_id
    ) REFERENCES demand.demand_review_assignments (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_demand_review_release_submission FOREIGN KEY (
        organization_id, demand_id, submission_id
    ) REFERENCES demand.demand_submissions (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_demand_review_release_version FOREIGN KEY (
        organization_id, demand_id, demand_version_id
    ) REFERENCES demand.demand_versions (
        organization_id, demand_id, id
    ),
    CONSTRAINT ck_demand_review_release_shape CHECK (
        reason_code IN ('CONFLICT_DECLARED', 'WORKLOAD_RELEASE')
        AND octet_length(authority_marker_sha256) = 32
    )
);

ALTER TABLE demand.demand_review_assignment_releases
OWNER TO demand_schema_owner;
REVOKE ALL ON demand.demand_review_assignment_releases FROM PUBLIC;

CREATE FUNCTION demand.reject_review_assignment_release_mutation_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'trg_demand_review_assignment_release_immutable',
        MESSAGE = 'Demand review assignment releases are immutable';
END
$function$;

ALTER FUNCTION demand.reject_review_assignment_release_mutation_v1()
OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand.reject_review_assignment_release_mutation_v1()
FROM PUBLIC;

CREATE TRIGGER trg_demand_review_assignment_release_immutable
BEFORE UPDATE OR DELETE ON demand.demand_review_assignment_releases
FOR EACH ROW
EXECUTE FUNCTION demand.reject_review_assignment_release_mutation_v1();

GRANT SELECT, INSERT ON demand.demand_review_assignment_releases
TO demand_review;
ALTER TABLE demand.demand_review_assignment_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.demand_review_assignment_releases FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_demand_review_release_write
ON demand.demand_review_assignment_releases
FOR INSERT TO demand_review
WITH CHECK (
    id::text = NULLIF(current_setting('app.command_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND assignment_id::text
        = NULLIF(current_setting('app.assignment_id', true), '')
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'RELEASE_REVIEW_ASSIGNMENT'
);

CREATE POLICY rls_demand_review_release_read
ON demand.demand_review_assignment_releases
FOR SELECT TO demand_review
USING (
    reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND assignment_id::text
        = NULLIF(current_setting('app.assignment_id', true), '')
    AND (
        (
            organization_id::text
                = NULLIF(current_setting('app.organization_id', true), '')
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'DEMAND_REVIEW'
            AND NULLIF(current_setting('app.operation', true), '')
                = 'RELEASE_REVIEW_ASSIGNMENT'
        )
        OR (
            id::text = NULLIF(current_setting('app.command_id', true), '')
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'DEMAND_REVIEW_RELEASE_REPLAY'
            AND NULLIF(current_setting('app.operation', true), '')
                = 'RELEASE_REVIEW_ASSIGNMENT'
        )
    )
);

-- Queue discovery runs through SECURITY DEFINER functions.  Expose only the
-- caller's own conflict declarations so those functions can exclude the same
-- submission without exposing release facts to another reviewer.
CREATE POLICY rls_demand_review_release_queue_definer
ON demand.demand_review_assignment_releases
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'LIST_REVIEW_QUEUE',
        'RESOLVE_REVIEW_QUEUE_TARGET',
        'CLAIM_REVIEW'
    )
);

CREATE OR REPLACE FUNCTION demand_api.list_available_demand_reviews_v1(
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
      AND NOT EXISTS (
          SELECT 1
          FROM demand.demand_review_assignment_releases AS release_row
          WHERE release_row.organization_id = root.organization_id
            AND release_row.demand_id = root.id
            AND release_row.submission_id = root.current_submission_id
            AND release_row.demand_version_id = root.current_version_id
            AND release_row.reviewer_user_id = exact_actor_user_id
            AND release_row.reason_code = 'CONFLICT_DECLARED'
      )
    ORDER BY submission.submitted_at, root.id
    LIMIT maximum_items;
END
$function$;

CREATE OR REPLACE FUNCTION demand_api.resolve_review_queue_target_v1(
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
      AND transaction_timestamp() < root.expires_at
      AND NOT EXISTS (
          SELECT 1
          FROM demand.demand_review_assignment_releases AS release_row
          WHERE release_row.organization_id = root.organization_id
            AND release_row.demand_id = root.id
            AND release_row.submission_id = root.current_submission_id
            AND release_row.demand_version_id = root.current_version_id
            AND release_row.reviewer_user_id = exact_actor_user_id
            AND release_row.reason_code = 'CONFLICT_DECLARED'
      );
END
$function$;

ALTER FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid,uuid,bytea,integer
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.resolve_review_queue_target_v1(
    uuid,uuid,uuid,bytea
) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid,uuid,bytea,integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.resolve_review_queue_target_v1(
    uuid,uuid,uuid,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid,uuid,bytea,integer
) TO demand_review;
GRANT EXECUTE ON FUNCTION demand_api.resolve_review_queue_target_v1(
    uuid,uuid,uuid,bytea
) TO demand_review;

CREATE FUNCTION demand.reject_conflicted_review_reclaim_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    IF session_user = 'demand_review'
       AND current_user = 'demand_schema_owner'
       AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'DEMAND_REVIEW'
       AND NULLIF(current_setting('app.operation', true), '') = 'CLAIM_REVIEW'
       AND NEW.reviewer_user_id::text
            = NULLIF(current_setting('app.actor_id', true), '')
       AND EXISTS (
            SELECT 1
            FROM demand.demand_review_assignment_releases AS release_row
            WHERE release_row.organization_id = NEW.organization_id
              AND release_row.demand_id = NEW.demand_id
              AND release_row.submission_id = NEW.submission_id
              AND release_row.demand_version_id = NEW.demand_version_id
              AND release_row.reviewer_user_id = NEW.reviewer_user_id
              AND release_row.reason_code = 'CONFLICT_DECLARED'
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'review_claim_conflict_declared',
            MESSAGE = 'review queue target is unavailable';
    END IF;
    RETURN NEW;
END
$function$;

ALTER FUNCTION demand.reject_conflicted_review_reclaim_v1()
OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand.reject_conflicted_review_reclaim_v1()
FROM PUBLIC;

CREATE TRIGGER reject_conflicted_review_reclaim
BEFORE INSERT ON demand.demand_review_assignments
FOR EACH ROW
EXECUTE FUNCTION demand.reject_conflicted_review_reclaim_v1();

CREATE POLICY rls_demand_release_replay_receipt_discovery
ON demand.command_receipts
FOR SELECT TO demand_review
USING (
    session_user = 'demand_review'
    AND current_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW_RELEASE_REPLAY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'RELEASE_REVIEW_ASSIGNMENT'
    AND receipt_id::text
        = NULLIF(current_setting('app.command_id', true), '')
);

CREATE POLICY rls_demand_release_replay_receipt_lock
ON demand.command_receipts
FOR UPDATE TO demand_review
USING (
    session_user = 'demand_review'
    AND current_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW_RELEASE_REPLAY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'RELEASE_REVIEW_ASSIGNMENT'
    AND receipt_id::text
        = NULLIF(current_setting('app.command_id', true), '')
)
WITH CHECK (
    session_user = 'demand_review'
    AND current_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW_RELEASE_REPLAY'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'RELEASE_REVIEW_ASSIGNMENT'
    AND receipt_id::text
        = NULLIF(current_setting('app.command_id', true), '')
);

CREATE FUNCTION demand.reject_release_replay_receipt_mutation_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand
AS $function$
BEGIN
    IF session_user = 'demand_review'
       AND current_user = 'demand_review'
       AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'DEMAND_REVIEW_RELEASE_REPLAY' THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'DEMAND_RELEASE_REPLAY_IS_READ_ONLY';
    END IF;
    RETURN NEW;
END
$function$;

ALTER FUNCTION demand.reject_release_replay_receipt_mutation_v1()
OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand.reject_release_replay_receipt_mutation_v1()
FROM PUBLIC;

CREATE TRIGGER command_receipts_release_replay_read_only
BEFORE UPDATE ON demand.command_receipts
FOR EACH ROW
EXECUTE FUNCTION demand.reject_release_replay_receipt_mutation_v1();

CREATE FUNCTION demand_api.read_completed_review_assignment_release_receipt_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_receipt_id uuid,
    exact_demand_id uuid,
    exact_assignment_id uuid,
    exact_if_match_version bigint,
    exact_idempotency_key_digest_key_ids text[],
    exact_idempotency_key_digests bytea[],
    exact_payload_hash_key_ids text[],
    exact_payload_hashes bytea[]
)
RETURNS TABLE (
    organization_id uuid,
    authority_marker_sha256 bytea,
    aggregate_version bigint,
    demand_version_id uuid
)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    existing demand.command_receipts%ROWTYPE;
    key_policy demand.receipt_key_policy%ROWTYPE;
    current_authority_marker bytea;
    current_duty_grant_id uuid;
    current_duty_grant_version bigint;
    receipt_keys text[];
BEGIN
    IF session_user IS DISTINCT FROM 'demand_review'
       OR current_user IS DISTINCT FROM 'demand_review'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_assignment_id IS NULL OR exact_assignment_id = zero_uuid
       OR exact_if_match_version IS NULL OR exact_if_match_version < 1
       OR exact_idempotency_key_digest_key_ids IS NULL
       OR exact_idempotency_key_digests IS NULL
       OR exact_payload_hash_key_ids IS NULL
       OR exact_payload_hashes IS NULL
       OR array_ndims(exact_idempotency_key_digest_key_ids) <> 1
       OR array_ndims(exact_idempotency_key_digests) <> 1
       OR array_ndims(exact_payload_hash_key_ids) <> 1
       OR array_ndims(exact_payload_hashes) <> 1
       OR cardinality(exact_idempotency_key_digest_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_key_digest_key_ids)
            <> cardinality(exact_idempotency_key_digests)
       OR cardinality(exact_payload_hash_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_payload_hash_key_ids)
            <> cardinality(exact_payload_hashes)
       OR array_lower(exact_idempotency_key_digest_key_ids, 1) <> 1
       OR array_lower(exact_idempotency_key_digests, 1) <> 1
       OR array_lower(exact_payload_hash_key_ids, 1) <> 1
       OR array_lower(exact_payload_hashes, 1) <> 1
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_key_digest_key_ids) AS item(value)
            WHERE item.value IS NULL OR item.value = ''
               OR octet_length(item.value) > 128
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
            WHERE item.value IS NULL OR item.value = ''
               OR octet_length(item.value) > 128
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_key_digests) AS item(value)
            WHERE item.value IS NULL OR octet_length(item.value) <> 32
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hashes) AS item(value)
            WHERE item.value IS NULL OR octet_length(item.value) <> 32
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_idempotency_key_digest_key_ids) AS item(value)
       )
       OR (
            SELECT count(DISTINCT value) <> count(*)
            FROM unnest(exact_payload_hash_key_ids) AS item(value)
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_REVIEW_RELEASE_REPLAY'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'RELEASE_REVIEW_ASSIGNMENT'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '')
            IS DISTINCT FROM exact_assignment_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_receipt_id::text
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'INVALID_REQUEST';
    END IF;

    SELECT receipt.* INTO existing
    FROM demand.command_receipts AS receipt
    WHERE receipt.receipt_id = exact_receipt_id
    FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT policy.* INTO STRICT key_policy
    FROM demand.receipt_key_policy AS policy
    WHERE policy.singleton_key;
    IF key_policy.active_canonicalization_version
            IS DISTINCT FROM 'demand-command-json-v1'
       OR array_ndims(key_policy.retained_idempotency_key_ids)
            IS DISTINCT FROM 1
       OR array_lower(key_policy.retained_idempotency_key_ids, 1)
            IS DISTINCT FROM 1
       OR cardinality(key_policy.retained_idempotency_key_ids)
            NOT BETWEEN 1 AND 4
       OR key_policy.retained_idempotency_key_ids[1]
            IS DISTINCT FROM key_policy.active_idempotency_key_id
       OR EXISTS (
            SELECT 1
            FROM unnest(
                key_policy.retained_idempotency_key_ids
            ) AS key_id(value)
            WHERE key_id.value IS NULL
               OR key_id.value = ''
               OR octet_length(key_id.value) > 128
       )
       OR (
            SELECT count(DISTINCT value) IS DISTINCT FROM count(*)
            FROM unnest(
                key_policy.retained_idempotency_key_ids
            ) AS key_id(value)
       )
       OR array_ndims(key_policy.retained_payload_key_ids)
            IS DISTINCT FROM 1
       OR array_lower(key_policy.retained_payload_key_ids, 1)
            IS DISTINCT FROM 1
       OR cardinality(key_policy.retained_payload_key_ids)
            NOT BETWEEN 1 AND 4
       OR key_policy.retained_payload_key_ids[1]
            IS DISTINCT FROM key_policy.active_payload_key_id
       OR EXISTS (
            SELECT 1
            FROM unnest(
                key_policy.retained_payload_key_ids
            ) AS key_id(value)
            WHERE key_id.value IS NULL
               OR key_id.value = ''
               OR octet_length(key_id.value) > 128
       )
       OR (
            SELECT count(DISTINCT value) IS DISTINCT FROM count(*)
            FROM unnest(
                key_policy.retained_payload_key_ids
            ) AS key_id(value)
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(
                key_policy.retained_idempotency_key_ids
            ) AS idempotency_key(key_id)
            JOIN unnest(
                key_policy.retained_payload_key_ids
            ) AS payload_key(key_id)
              ON idempotency_key.key_id = payload_key.key_id
       )
       OR exact_idempotency_key_digest_key_ids[1]
            IS DISTINCT FROM key_policy.active_idempotency_key_id
       OR exact_payload_hash_key_ids[1]
            IS DISTINCT FROM key_policy.active_payload_key_id
       OR EXISTS (
            SELECT 1
            FROM unnest(
                exact_idempotency_key_digest_key_ids
            ) AS candidate(key_id)
            WHERE NOT EXISTS (
                SELECT 1
                FROM unnest(
                    key_policy.retained_idempotency_key_ids
                ) AS retained(key_id)
                WHERE retained.key_id = candidate.key_id
            )
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_hash_key_ids) AS candidate(key_id)
            WHERE NOT EXISTS (
                SELECT 1
                FROM unnest(
                    key_policy.retained_payload_key_ids
                ) AS retained(key_id)
                WHERE retained.key_id = candidate.key_id
            )
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_RECEIPT_KEY_POLICY_UNAVAILABLE';
    END IF;

    IF existing.principal_kind IS DISTINCT FROM 'USER'
       OR existing.principal_id IS DISTINCT FROM exact_actor_user_id
       OR existing.command_name IS DISTINCT FROM
            'ReleaseDemandReviewAssignment'
       OR existing.command_version IS DISTINCT FROM 1
       OR existing.canonicalization_version
            IS DISTINCT FROM 'demand-command-json-v1'
       OR NOT EXISTS (
            SELECT 1
            FROM generate_subscripts(
                exact_idempotency_key_digests, 1
            ) AS slot(index)
            WHERE exact_idempotency_key_digest_key_ids[slot.index]
                    = existing.idempotency_key_digest_key_id
              AND exact_idempotency_key_digests[slot.index]
                    = existing.idempotency_key_digest
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_RELEASE_RECEIPT_REPLAY_INVALID';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM generate_subscripts(exact_payload_hashes, 1) AS slot(index)
        WHERE exact_payload_hash_key_ids[slot.index]
                = existing.payload_hash_key_id
          AND exact_payload_hashes[slot.index] = existing.payload_hash
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'uq_demand_receipt_identity',
            MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
    END IF;

    IF existing.http_method IS DISTINCT FROM 'POST'
       OR existing.canonical_path IS DISTINCT FROM
            '/v1/operations/demand-review-assignments/' ||
            exact_assignment_id::text || '/release'
       OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
       OR existing.retain_until <= transaction_timestamp()
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DEMAND_RELEASE_RECEIPT_REPLAY_INVALID';
    END IF;
    IF existing.status = 'IN_PROGRESS' THEN
        IF existing.response_http_status IS NOT NULL
           OR existing.response_schema_name IS NOT NULL
           OR existing.response_schema_version IS NOT NULL
           OR existing.response_entity_tag IS NOT NULL
           OR existing.safe_response_body IS NOT NULL
           OR existing.target_id IS NOT NULL
           OR existing.target_version IS NOT NULL
           OR existing.result_status IS NOT NULL
           OR existing.event_types IS NOT NULL
           OR existing.completed_at IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'DEMAND_RELEASE_RECEIPT_REPLAY_INVALID';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;

    IF existing.status IS DISTINCT FROM 'COMPLETED'
       OR jsonb_typeof(existing.safe_response_body) IS DISTINCT FROM 'object'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;

    SELECT array_agg(key_name ORDER BY key_name) INTO receipt_keys
    FROM jsonb_object_keys(existing.safe_response_body) AS key_name;
    IF existing.target_id IS DISTINCT FROM exact_demand_id
       OR existing.response_http_status IS DISTINCT FROM 200
       OR existing.response_schema_name IS DISTINCT FROM 'DemandDto'
       OR existing.response_schema_version IS DISTINCT FROM 1
       OR existing.target_version IS DISTINCT FROM exact_if_match_version + 1
       OR existing.result_status IS DISTINCT FROM 'SUBMITTED'
       OR existing.event_types IS DISTINCT FROM
            ARRAY['DemandReviewAssignmentReleased']::text[]
       OR existing.completed_at IS NULL
       OR existing.response_entity_tag IS DISTINCT FROM
            '"v' || existing.target_version::text || '"'
       OR receipt_keys IS DISTINCT FROM ARRAY[
            'aggregate_version','demand_id','demand_version_id','status'
       ]::text[]
       OR existing.safe_response_body->>'aggregate_version'
            IS DISTINCT FROM existing.target_version::text
       OR existing.safe_response_body->>'demand_id'
            IS DISTINCT FROM exact_demand_id::text
       OR existing.safe_response_body->>'status' IS DISTINCT FROM 'SUBMITTED'
       OR jsonb_typeof(existing.safe_response_body->'aggregate_version')
            IS DISTINCT FROM 'number'
       OR jsonb_typeof(existing.safe_response_body->'demand_id')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(existing.safe_response_body->'demand_version_id')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(existing.safe_response_body->'status')
            IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;

    PERFORM set_config('app.scope_kind', 'DEMAND_REVIEW', true);
    PERFORM set_config(
        'app.organization_id', existing.organization_id::text, true
    );
    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT current_authority_marker
        FROM iam_api.resolve_demand_reviewer_authority_marker_v2(
            exact_actor_user_id, exact_session_id, existing.organization_id,
            'RELEASE_REVIEW_ASSIGNMENT', exact_demand_id,
            exact_assignment_id
        ) AS marker;
        SELECT authority.duty_grant_id, authority.duty_grant_version
        INTO STRICT current_duty_grant_id, current_duty_grant_version
        FROM iam_api.lock_demand_reviewer_authority_v2(
            exact_actor_user_id, exact_session_id, existing.organization_id,
            exact_demand_id, exact_assignment_id,
            'RELEASE_REVIEW_ASSIGNMENT', current_authority_marker
        ) AS authority;
        IF current_duty_grant_id IS NULL OR current_duty_grant_id = zero_uuid
           OR current_duty_grant_version IS NULL
           OR current_duty_grant_version < 1
           OR octet_length(current_authority_marker) <> 32 THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002';
        END IF;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'ACCESS_DENIED';
    END;

    PERFORM 1
    FROM demand.demands AS root
    JOIN demand.demand_versions AS version_row
      ON version_row.organization_id = root.organization_id
     AND version_row.demand_id = root.id
     AND version_row.id = root.current_version_id
    JOIN demand.demand_submissions AS submission
      ON submission.organization_id = root.organization_id
     AND submission.demand_id = root.id
     AND submission.id = root.current_submission_id
     AND submission.demand_version_id = version_row.id
     AND submission.content_sha256 = version_row.content_sha256
    JOIN demand.demand_review_assignments AS assignment
      ON assignment.organization_id = root.organization_id
     AND assignment.demand_id = root.id
     AND assignment.id = exact_assignment_id
     AND assignment.submission_id = submission.id
     AND assignment.demand_version_id = version_row.id
    JOIN demand.demand_review_assignment_releases AS release_row
      ON release_row.organization_id = root.organization_id
     AND release_row.demand_id = root.id
     AND release_row.id = exact_receipt_id
     AND release_row.assignment_id = assignment.id
     AND release_row.submission_id = submission.id
     AND release_row.demand_version_id = version_row.id
    WHERE root.organization_id = existing.organization_id
      AND root.id = exact_demand_id
      AND root.status = 'SUBMITTED'
      AND root.aggregate_version = existing.target_version
      AND root.current_review_id IS NULL
      AND root.verified_version_id IS NULL
      AND root.current_funding_marker_id IS NULL
      AND root.current_matching_request_id IS NULL
      AND root.updated_at = existing.completed_at
      AND assignment.reviewer_user_id = exact_actor_user_id
      AND assignment.duty_grant_id <> zero_uuid
      AND assignment.duty_grant_version >= 1
      AND assignment.purpose_code = 'DEMAND_REVIEW'
      AND assignment.status = 'REVOKED'
      AND assignment.aggregate_version = 2
      AND assignment.completed_at = existing.completed_at
      AND release_row.reviewer_user_id = exact_actor_user_id
      AND release_row.reason_code IN (
            'CONFLICT_DECLARED','WORKLOAD_RELEASE'
      )
      AND octet_length(release_row.authority_marker_sha256) = 32
      AND release_row.released_at = existing.completed_at
      AND version_row.id::text =
            existing.safe_response_body->>'demand_version_id'
      AND NOT EXISTS (
            SELECT 1 FROM demand.demand_reviews AS review_row
            WHERE review_row.assignment_id = assignment.id
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40003',
            MESSAGE = 'COMMAND_OUTCOME_UNKNOWN';
    END IF;

    RETURN QUERY SELECT
        existing.organization_id,
        current_authority_marker,
        existing.target_version,
        (existing.safe_response_body->>'demand_version_id')::uuid;
END
$function$;

ALTER FUNCTION demand_api.read_completed_review_assignment_release_receipt_v1(
    uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[]
) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION
demand_api.read_completed_review_assignment_release_receipt_v1(
    uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
demand_api.read_completed_review_assignment_release_receipt_v1(
    uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[]
) TO demand_review;

DO $assert$
DECLARE
    release_relation pg_catalog.pg_class%ROWTYPE;
BEGIN
    SELECT relation.* INTO STRICT release_relation
    FROM pg_catalog.pg_class AS relation
    WHERE relation.oid = 'demand.demand_review_assignment_releases'::regclass;

    IF NOT pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.read_completed_review_assignment_release_receipt_v1(uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[])',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.read_completed_review_assignment_release_receipt_v1(uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[])',
            'EXECUTE'
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS procedure
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    procedure.proacl,
                    pg_catalog.acldefault('f', procedure.proowner)
                )
            ) AS privilege
            WHERE procedure.oid = pg_catalog.to_regprocedure(
                    'demand_api.read_completed_review_assignment_release_receipt_v1(uuid,uuid,uuid,uuid,uuid,bigint,text[],bytea[],text[],bytea[])'
              )
              AND privilege.grantee = 0
              AND privilege.privilege_type = 'EXECUTE'
       )
       OR release_relation.relkind IS DISTINCT FROM 'r'
       OR release_relation.relowner IS DISTINCT FROM (
            SELECT role.oid FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = 'demand_schema_owner'
       )
       OR release_relation.relrowsecurity IS NOT TRUE
       OR release_relation.relforcerowsecurity IS NOT TRUE
       OR NOT pg_catalog.has_table_privilege(
            'demand_review',
            'demand.demand_review_assignment_releases',
            'SELECT'
       )
       OR NOT pg_catalog.has_table_privilege(
            'demand_review',
            'demand.demand_review_assignment_releases',
            'INSERT'
       )
       OR pg_catalog.has_table_privilege(
            'demand_review',
            'demand.demand_review_assignment_releases',
            'UPDATE,DELETE,TRUNCATE'
       )
       OR pg_catalog.has_table_privilege(
            'demand_self',
            'demand.demand_review_assignment_releases',
            'SELECT,INSERT,UPDATE,DELETE'
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(
                COALESCE(
                    release_relation.relacl,
                    pg_catalog.acldefault('r', release_relation.relowner)
                )
            ) AS privilege
            WHERE privilege.grantee = 0
       )
       OR (
            SELECT count(*)
            FROM pg_catalog.pg_policy AS policy
            WHERE policy.polrelid = release_relation.oid
              AND policy.polname IN (
                    'rls_demand_review_release_write',
                    'rls_demand_review_release_read',
                    'rls_demand_review_release_queue_definer'
              )
       ) IS DISTINCT FROM 3::bigint
       OR (
            SELECT count(*)
            FROM pg_catalog.pg_policy AS policy
            WHERE policy.polrelid = release_relation.oid
       ) IS DISTINCT FROM 3::bigint
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid = release_relation.oid
              AND trigger.tgname =
                    'trg_demand_review_assignment_release_immutable'
              AND trigger.tgfoid = pg_catalog.to_regprocedure(
                    'demand.reject_review_assignment_release_mutation_v1()'
              )
              AND trigger.tgenabled = 'O'
              AND NOT trigger.tgisinternal
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid =
                    'demand.demand_review_assignments'::regclass
              AND trigger.tgname = 'reject_conflicted_review_reclaim'
              AND trigger.tgfoid = pg_catalog.to_regprocedure(
                    'demand.reject_conflicted_review_reclaim_v1()'
              )
              AND trigger.tgenabled = 'O'
              AND NOT trigger.tgisinternal
       )
       OR (
            SELECT count(*)
            FROM pg_catalog.pg_policy AS policy
            WHERE policy.polrelid = 'demand.command_receipts'::regclass
              AND policy.polname IN (
                    'rls_demand_release_replay_receipt_discovery',
                    'rls_demand_release_replay_receipt_lock'
              )
       ) IS DISTINCT FROM 2::bigint
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid = 'demand.command_receipts'::regclass
              AND trigger.tgname =
                    'command_receipts_release_replay_read_only'
              AND trigger.tgfoid = pg_catalog.to_regprocedure(
                    'demand.reject_release_replay_receipt_mutation_v1()'
              )
              AND trigger.tgenabled = 'O'
              AND NOT trigger.tgisinternal
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand13 review assignment release assertion failed';
    END IF;
END
$assert$;
