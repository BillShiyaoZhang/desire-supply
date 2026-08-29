-- INTERNAL_SANDBOX zero-funds manual review for two independent Finance Operators.
-- This migration records attestations only; it cannot represent real money,
-- provider state, payment operations, settlement, escrow, or a legal promise.

CREATE TABLE demand.manual_funding_review_cases (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    funding_id uuid NOT NULL UNIQUE,
    status varchar(16) NOT NULL,
    aggregate_version bigint NOT NULL,
    target_sha256 bytea NOT NULL,
    evidence_kind varchar(64) NOT NULL,
    evidence_reference_sha256 bytea NOT NULL,
    sandbox_funds_amount_minor bigint NOT NULL,
    legal_effect varchar(64) NOT NULL,
    required_confirmations integer NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_manual_funding_case_demand UNIQUE (organization_id, demand_id),
    CONSTRAINT uq_manual_funding_case_org_id UNIQUE (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_manual_funding_case_version FOREIGN KEY (
        organization_id, demand_id, demand_version_id
    ) REFERENCES demand.demand_versions (organization_id, demand_id, id),
    CONSTRAINT ck_manual_funding_case_hashes CHECK (
        octet_length(target_sha256) = 32
        AND octet_length(evidence_reference_sha256) = 32
    ),
    CONSTRAINT ck_manual_funding_case_sandbox CHECK (
        evidence_kind = 'INTERNAL_SANDBOX_ZERO_FUNDS_V1'
        AND sandbox_funds_amount_minor = 0
        AND legal_effect = 'NO_REAL_FUNDS_OR_PAYMENT'
        AND required_confirmations = 2
    ),
    CONSTRAINT ck_manual_funding_case_shape CHECK (
        aggregate_version >= 1
        AND status IN ('PENDING', 'SECURED')
        AND expires_at > created_at
        AND (
            (status = 'PENDING' AND completed_at IS NULL)
            OR (status = 'SECURED' AND completed_at >= created_at)
        )
    )
);

CREATE TABLE demand.manual_funding_review_assignments (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    funding_review_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    duty_grant_id uuid NOT NULL,
    duty_grant_version bigint NOT NULL,
    purpose_code varchar(64) NOT NULL,
    conflict_attestation_sha256 bytea NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    status varchar(16) NOT NULL,
    aggregate_version bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_manual_funding_assignment_actor UNIQUE (
        funding_review_id, actor_user_id
    ),
    CONSTRAINT uq_manual_funding_assignment_org_id UNIQUE (
        organization_id, demand_id, funding_review_id, id
    ),
    CONSTRAINT fk_manual_funding_assignment_case FOREIGN KEY (
        organization_id, demand_id, funding_review_id
    ) REFERENCES demand.manual_funding_review_cases (
        organization_id, demand_id, id
    ),
    CONSTRAINT ck_manual_funding_assignment_shape CHECK (
        purpose_code = 'MANUAL_FUNDING_REVIEW'
        AND duty_grant_version >= 1
        AND aggregate_version >= 1
        AND octet_length(conflict_attestation_sha256) = 32
        AND octet_length(authority_marker_sha256) = 32
        AND expires_at > created_at
        AND status IN ('ACTIVE', 'COMPLETED', 'REVOKED')
        AND (
            (status = 'ACTIVE' AND completed_at IS NULL)
            OR (status <> 'ACTIVE' AND completed_at >= created_at)
        )
    )
);

CREATE TABLE demand.manual_funding_confirmations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    funding_review_id uuid NOT NULL,
    assignment_id uuid NOT NULL UNIQUE,
    actor_user_id uuid NOT NULL,
    attestation_codes text[] NOT NULL,
    target_sha256 bytea NOT NULL,
    evidence_reference_sha256 bytea NOT NULL,
    confirmed_at timestamptz NOT NULL,
    CONSTRAINT uq_manual_funding_confirmation_actor UNIQUE (
        funding_review_id, actor_user_id
    ),
    CONSTRAINT fk_manual_funding_confirmation_case FOREIGN KEY (
        organization_id, demand_id, funding_review_id
    ) REFERENCES demand.manual_funding_review_cases (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_manual_funding_confirmation_assignment FOREIGN KEY (
        organization_id, demand_id, funding_review_id, assignment_id
    ) REFERENCES demand.manual_funding_review_assignments (
        organization_id, demand_id, funding_review_id, id
    ),
    CONSTRAINT ck_manual_funding_confirmation_shape CHECK (
        attestation_codes = ARRAY[
            'SYNTHETIC_ONLY',
            'ZERO_REAL_FUNDS',
            'NO_PROVIDER_OR_PAYMENT',
            'TARGET_AND_EVIDENCE_MATCH'
        ]::text[]
        AND octet_length(target_sha256) = 32
        AND octet_length(evidence_reference_sha256) = 32
    )
);

CREATE TABLE demand.manual_funding_receipts (
    receipt_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    funding_review_id uuid NOT NULL,
    command_name varchar(64) NOT NULL,
    command_version integer NOT NULL,
    idempotency_key_digest_key_id varchar(128) NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    payload_hash bytea NOT NULL,
    expected_demand_revision bigint NULL,
    expected_review_revision bigint NULL,
    status varchar(16) NOT NULL,
    safe_response_body jsonb NULL,
    response_entity_tag varchar(128) NULL,
    result_event_type varchar(64) NULL,
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT uq_manual_funding_receipt_identity UNIQUE (
        principal_id,
        command_name,
        command_version,
        idempotency_key_digest_key_id,
        idempotency_key_digest
    ),
    CONSTRAINT fk_manual_funding_receipt_case FOREIGN KEY (
        organization_id, demand_id, funding_review_id
    ) REFERENCES demand.manual_funding_review_cases (
        organization_id, demand_id, id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_manual_funding_receipt_identity CHECK (
        command_name IN (
            'ClaimManualFundingReview', 'ConfirmManualFundingReview'
        )
        AND command_version = 1
        AND canonicalization_version = 'demand-command-json-v1'
        AND idempotency_key_digest_key_id <> payload_hash_key_id
        AND octet_length(idempotency_key_digest) = 32
        AND octet_length(payload_hash) = 32
        AND (
            (command_name = 'ClaimManualFundingReview'
                AND num_nonnulls(
                    expected_demand_revision, expected_review_revision
                ) = 1)
            OR (command_name = 'ConfirmManualFundingReview'
                AND expected_demand_revision IS NULL
                AND expected_review_revision >= 1)
        )
        AND retain_until >= created_at
    ),
    CONSTRAINT ck_manual_funding_receipt_shape CHECK (
        status IN ('IN_PROGRESS', 'COMPLETED')
        AND (
            (status = 'IN_PROGRESS'
                AND safe_response_body IS NULL
                AND response_entity_tag IS NULL
                AND result_event_type IS NULL
                AND completed_at IS NULL)
            OR (status = 'COMPLETED'
                AND jsonb_typeof(safe_response_body) = 'object'
                AND response_entity_tag IS NOT NULL
                AND result_event_type IN (
                    'DemandFundingRequested',
                    'DemandFundingReviewClaimed',
                    'DemandFundingEvidenceConfirmed',
                    'DemandFunded'
                )
                AND completed_at >= created_at)
        )
    )
);

ALTER TABLE demand.manual_funding_review_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_review_cases FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_review_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_review_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_confirmations FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_receipts FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE demand.manual_funding_review_cases FROM PUBLIC;
REVOKE ALL ON TABLE demand.manual_funding_review_assignments FROM PUBLIC;
REVOKE ALL ON TABLE demand.manual_funding_confirmations FROM PUBLIC;
REVOKE ALL ON TABLE demand.manual_funding_receipts FROM PUBLIC;

CREATE FUNCTION demand.protect_manual_funding_case_v1()
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
       OR NEW.demand_version_id IS DISTINCT FROM OLD.demand_version_id
       OR NEW.funding_id IS DISTINCT FROM OLD.funding_id
       OR NEW.target_sha256 IS DISTINCT FROM OLD.target_sha256
       OR NEW.evidence_kind IS DISTINCT FROM OLD.evidence_kind
       OR NEW.evidence_reference_sha256
            IS DISTINCT FROM OLD.evidence_reference_sha256
       OR NEW.sandbox_funds_amount_minor
            IS DISTINCT FROM OLD.sandbox_funds_amount_minor
       OR NEW.legal_effect IS DISTINCT FROM OLD.legal_effect
       OR NEW.required_confirmations IS DISTINCT FROM OLD.required_confirmations
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.status <> 'PENDING'
       OR NEW.status NOT IN ('PENDING', 'SECURED')
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (NEW.status = 'PENDING' AND NEW.completed_at IS NOT NULL)
       OR (NEW.status = 'SECURED' AND NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_manual_funding_case_immutable',
            MESSAGE = 'manual funding case mutation is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_manual_funding_case_immutable
BEFORE UPDATE OR DELETE ON demand.manual_funding_review_cases
FOR EACH ROW EXECUTE FUNCTION demand.protect_manual_funding_case_v1();

CREATE FUNCTION demand.protect_manual_funding_assignment_v1()
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
       OR NEW.funding_review_id IS DISTINCT FROM OLD.funding_review_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
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
       OR NEW.completed_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_manual_funding_assignment_immutable',
            MESSAGE = 'manual funding assignment mutation is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_manual_funding_assignment_immutable
BEFORE UPDATE OR DELETE ON demand.manual_funding_review_assignments
FOR EACH ROW EXECUTE FUNCTION demand.protect_manual_funding_assignment_v1();

CREATE TRIGGER trg_manual_funding_confirmation_immutable
BEFORE UPDATE OR DELETE ON demand.manual_funding_confirmations
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

REVOKE ALL ON FUNCTION demand.protect_manual_funding_case_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION demand.protect_manual_funding_assignment_v1() FROM PUBLIC;

-- SECURITY DEFINER functions run as demand_schema_owner while FORCE RLS stays
-- active.  Every policy additionally proves the physical session role.
CREATE POLICY rls_finance_funding_root_definer
ON demand.demands
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_FUNDING_REVIEWS'
        OR id::text = NULLIF(current_setting('app.demand_id', true), '')
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
);

CREATE POLICY rls_finance_funding_version_definer
ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_FUNDING_REVIEWS'
        OR demand_id::text
            = NULLIF(current_setting('app.demand_id', true), '')
    )
);

CREATE POLICY rls_finance_funding_case_definer
ON demand.manual_funding_review_cases
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_FUNDING_REVIEWS'
        OR demand_id::text
            = NULLIF(current_setting('app.demand_id', true), '')
        OR id::text
            = NULLIF(current_setting('app.funding_review_id', true), '')
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
);

CREATE POLICY rls_finance_funding_assignment_definer
ON demand.manual_funding_review_assignments
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_FUNDING_REVIEWS'
        OR demand_id::text
            = NULLIF(current_setting('app.demand_id', true), '')
        OR funding_review_id::text
            = NULLIF(current_setting('app.funding_review_id', true), '')
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
);

CREATE POLICY rls_finance_funding_confirmation_definer
ON demand.manual_funding_confirmations
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_FUNDING_REVIEWS'
        OR demand_id::text
            = NULLIF(current_setting('app.demand_id', true), '')
        OR funding_review_id::text
            = NULLIF(current_setting('app.funding_review_id', true), '')
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CONFIRM_FUNDING_REVIEW'
);

CREATE POLICY rls_finance_funding_receipt_definer
ON demand.manual_funding_receipts
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
);

CREATE POLICY rls_finance_funding_marker_definer
ON demand.demand_funding_markers
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CONFIRM_FUNDING_REVIEW'
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
);

CREATE POLICY rls_finance_funding_key_policy_definer
ON demand.receipt_key_policy
FOR SELECT TO demand_schema_owner
USING (
    singleton_key
    AND session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
);

CREATE FUNCTION demand_api.list_manual_funding_reviews_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea,
    maximum_items integer
)
RETURNS TABLE (
    demand_id uuid,
    demand_version_id uuid,
    demand_revision bigint,
    funding_review_id uuid,
    review_status text,
    confirmation_count bigint,
    review_revision bigint,
    assigned_to_me boolean,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR maximum_items NOT BETWEEN 1 AND 100
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_FUNDING_REVIEWS'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NOT EXISTS (
            SELECT 1
            FROM iam_api.authorize_finance_funding_queue_v1(
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
        root.current_version_id,
        root.aggregate_version,
        review.id,
        CASE WHEN review.id IS NULL THEN 'AVAILABLE' ELSE 'PENDING' END,
        COALESCE(confirmation.total, 0),
        review.aggregate_version,
        EXISTS (
            SELECT 1
            FROM demand.manual_funding_review_assignments AS own_assignment
            WHERE own_assignment.funding_review_id = review.id
              AND own_assignment.actor_user_id = exact_actor_user_id
        ),
        COALESCE(review.expires_at, root.expires_at)
    FROM demand.demands AS root
    LEFT JOIN demand.manual_funding_review_cases AS review
      ON review.organization_id = root.organization_id
     AND review.demand_id = root.id
     AND review.demand_version_id = root.current_version_id
     AND review.status = 'PENDING'
    LEFT JOIN LATERAL (
        SELECT count(*) AS total
        FROM demand.manual_funding_confirmations AS item
        WHERE item.organization_id = review.organization_id
          AND item.demand_id = review.demand_id
          AND item.funding_review_id = review.id
    ) AS confirmation ON true
    WHERE (
        (root.status = 'VERIFIED' AND review.id IS NULL)
        OR (root.status = 'FUNDING_PENDING' AND review.id IS NOT NULL)
    )
      AND root.verified_version_id = root.current_version_id
      AND transaction_timestamp() < root.expires_at
      AND (review.id IS NULL OR transaction_timestamp() < review.expires_at)
      AND (
          review.id IS NULL
          OR EXISTS (
              SELECT 1
              FROM demand.manual_funding_review_assignments AS own_assignment
              WHERE own_assignment.funding_review_id = review.id
                AND own_assignment.actor_user_id = exact_actor_user_id
          )
          OR (
              confirmation.total < 2
              AND NOT EXISTS (
                  SELECT 1
                  FROM demand.manual_funding_review_assignments AS own_assignment
                  WHERE own_assignment.funding_review_id = review.id
                    AND own_assignment.actor_user_id = exact_actor_user_id
              )
              AND (
                  SELECT count(*)
                  FROM demand.manual_funding_review_assignments AS assignment
                  WHERE assignment.funding_review_id = review.id
                    AND assignment.status IN ('ACTIVE', 'COMPLETED')
              ) < 2
          )
      )
    ORDER BY root.updated_at, root.id
    LIMIT maximum_items;
END
$function$;

CREATE FUNCTION demand_api.get_manual_funding_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_funding_review_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    funding_review_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    status text,
    review_revision bigint,
    assignment_id uuid,
    assignment_expires_at timestamptz,
    target_sha256 bytea,
    evidence_reference_sha256 bytea,
    confirmation_count bigint,
    can_confirm boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_funding_review_id IS NULL
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'GET_FUNDING_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.funding_review_id', true), '')
            IS DISTINCT FROM exact_funding_review_id::text
       OR NOT EXISTS (
            SELECT 1
            FROM iam_api.authorize_finance_funding_queue_v1(
                exact_actor_user_id,
                exact_session_id,
                expected_principal_marker_sha256
            )
       ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        review.id,
        review.demand_id,
        review.demand_version_id,
        review.status::text,
        review.aggregate_version,
        assignment.id,
        assignment.expires_at,
        review.target_sha256,
        review.evidence_reference_sha256,
        (
            SELECT count(*)
            FROM demand.manual_funding_confirmations AS confirmation
            WHERE confirmation.funding_review_id = review.id
        ),
        review.status = 'PENDING'
            AND assignment.status = 'ACTIVE'
            AND transaction_timestamp() < assignment.expires_at
            AND transaction_timestamp() < review.expires_at
            AND NOT EXISTS (
                SELECT 1
                FROM demand.manual_funding_confirmations AS confirmation
                WHERE confirmation.funding_review_id = review.id
                  AND confirmation.actor_user_id = exact_actor_user_id
            )
    FROM demand.manual_funding_review_cases AS review
    JOIN demand.manual_funding_review_assignments AS assignment
      ON assignment.organization_id = review.organization_id
     AND assignment.demand_id = review.demand_id
     AND assignment.funding_review_id = review.id
     AND assignment.actor_user_id = exact_actor_user_id
    WHERE review.id = exact_funding_review_id;
END
$function$;

-- Claims create the synthetic case on the first claim and join that exact case
-- on the second.  Both paths bind a receipt before any durable business write.
CREATE FUNCTION demand_api.claim_manual_funding_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_demand_id uuid,
    expected_demand_revision bigint,
    expected_review_revision bigint,
    expected_principal_marker_sha256 bytea,
    new_funding_review_id uuid,
    new_funding_id uuid,
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
    exact_trace_id uuid,
    exact_evidence_kind text,
    exact_legal_effect text,
    sandbox_funds_amount_minor bigint
)
RETURNS TABLE (
    funding_review_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    status text,
    review_revision bigint,
    assignment_id uuid,
    assignment_expires_at timestamptz,
    target_sha256 bytea,
    evidence_reference_sha256 bytea,
    confirmation_count bigint,
    can_confirm boolean,
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
    review_row demand.manual_funding_review_cases%ROWTYPE;
    authority_row record;
    receipt_row demand.manual_funding_receipts%ROWTYPE;
    assignment_expires timestamptz;
    case_expires timestamptz;
    target_digest bytea;
    evidence_digest bytea;
    conflict_digest bytea;
    result_event text;
    result_etag text;
    next_demand_revision bigint;
    next_review_revision bigint;
    confirmation_total bigint;
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR new_funding_review_id IS NULL OR new_funding_review_id = zero_uuid
       OR new_funding_id IS NULL OR new_funding_id = zero_uuid
       OR new_assignment_id IS NULL OR new_assignment_id = zero_uuid
       OR new_receipt_id IS NULL OR new_receipt_id = zero_uuid
       OR new_audit_event_id IS NULL OR new_audit_event_id = zero_uuid
       OR new_outbox_event_id IS NULL OR new_outbox_event_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR num_nonnulls(
            expected_demand_revision, expected_review_revision
       ) <> 1
       OR COALESCE(expected_demand_revision, expected_review_revision) < 1
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR exact_idempotency_key_digest_key_id IS NULL
       OR exact_payload_hash_key_id IS NULL
       OR exact_idempotency_key_digest_key_id = exact_payload_hash_key_id
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_evidence_kind <> 'INTERNAL_SANDBOX_ZERO_FUNDS_V1'
       OR exact_legal_effect <> 'NO_REAL_FUNDS_OR_PAYMENT'
       OR sandbox_funds_amount_minor <> 0
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CLAIM_FUNDING_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text THEN
        RETURN;
    END IF;

    SELECT
        root.organization_id,
        root.status,
        root.aggregate_version,
        root.current_version_id,
        root.verified_version_id,
        root.current_funding_marker_id,
        root.expires_at
    INTO root_row
    FROM demand.demands AS root
    WHERE root.id = exact_demand_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM pg_catalog.set_config(
        'app.organization_id', root_row.organization_id::text, true
    );

    SELECT * INTO authority_row
    FROM iam_api.lock_finance_funding_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        root_row.organization_id,
        exact_demand_id,
        'CLAIM_FUNDING_REVIEW',
        expected_principal_marker_sha256
    );
    IF NOT FOUND THEN RETURN; END IF;

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
            CONSTRAINT = 'finance_funding_key_policy_unavailable',
            MESSAGE = 'Finance funding key policy is unavailable';
    END IF;

    SELECT * INTO receipt_row
    FROM demand.manual_funding_receipts AS receipt
    WHERE receipt.receipt_id = new_receipt_id
       OR (
            receipt.principal_id = exact_actor_user_id
            AND receipt.command_name = 'ClaimManualFundingReview'
            AND receipt.command_version = 1
            AND receipt.idempotency_key_digest_key_id
                = exact_idempotency_key_digest_key_id
            AND receipt.idempotency_key_digest
                = exact_idempotency_key_digest
       )
    FOR UPDATE;
    IF FOUND THEN
        IF receipt_row.demand_id <> exact_demand_id
           OR receipt_row.expected_demand_revision
                IS DISTINCT FROM expected_demand_revision
           OR receipt_row.expected_review_revision
                IS DISTINCT FROM expected_review_revision
           OR receipt_row.payload_hash_key_id <> exact_payload_hash_key_id
           OR receipt_row.payload_hash <> exact_payload_hash THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'finance_funding_idempotency_reused',
                MESSAGE = 'Finance funding claim idempotency conflict';
        END IF;
        IF receipt_row.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'finance_funding_receipt_incomplete',
                MESSAGE = 'Finance funding claim receipt is incomplete';
        END IF;
        RETURN QUERY SELECT
            (receipt_row.safe_response_body->>'funding_review_id')::uuid,
            receipt_row.demand_id,
            (receipt_row.safe_response_body->>'demand_version_id')::uuid,
            receipt_row.safe_response_body->>'status',
            (receipt_row.safe_response_body->>'review_revision')::bigint,
            (receipt_row.safe_response_body->>'assignment_id')::uuid,
            (receipt_row.safe_response_body->>'assignment_expires_at')::timestamptz,
            decode(receipt_row.safe_response_body->>'target_sha256', 'hex'),
            decode(
                receipt_row.safe_response_body->>'evidence_reference_sha256',
                'hex'
            ),
            (receipt_row.safe_response_body->>'confirmation_count')::bigint,
            (receipt_row.safe_response_body->>'can_confirm')::boolean,
            true;
        RETURN;
    END IF;

    SELECT * INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.organization_id = root_row.organization_id
      AND review.demand_id = exact_demand_id
    FOR UPDATE;

    IF FOUND THEN
        IF expected_demand_revision IS NOT NULL
           OR review_row.aggregate_version <> expected_review_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                CONSTRAINT = 'finance_funding_precondition_failed',
                MESSAGE = 'Finance funding review precondition failed';
        END IF;
        IF root_row.status <> 'FUNDING_PENDING'
           OR review_row.status <> 'PENDING'
           OR review_row.demand_version_id <> root_row.current_version_id
           OR now_at >= review_row.expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'finance_funding_state_conflict',
                MESSAGE = 'Finance funding review state changed';
        END IF;
    ELSE
        IF expected_review_revision IS NOT NULL
           OR root_row.aggregate_version <> expected_demand_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                CONSTRAINT = 'finance_funding_precondition_failed',
                MESSAGE = 'Finance funding Demand precondition failed';
        END IF;
        IF root_row.status <> 'VERIFIED'
           OR root_row.current_version_id <> root_row.verified_version_id
           OR root_row.current_funding_marker_id IS NOT NULL
           OR now_at >= root_row.expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'finance_funding_state_conflict',
                MESSAGE = 'Finance funding target is unavailable';
        END IF;
        case_expires := LEAST(
            root_row.expires_at,
            now_at + interval '7 days',
            COALESCE(
                authority_row.duty_expires_at,
                now_at + interval '7 days'
            )
        );
        IF case_expires <= now_at THEN RETURN; END IF;
        target_digest := sha256(convert_to(
            'manual-funding-target-v1|' ||
            root_row.organization_id::text || '|' ||
            exact_demand_id::text || '|' ||
            root_row.current_version_id::text || '|' ||
            new_funding_id::text || '|0',
            'UTF8'
        ));
        evidence_digest := sha256(convert_to(
            'internal-sandbox-zero-funds-evidence-v1|' ||
            new_funding_review_id::text || '|' ||
            encode(target_digest, 'hex'),
            'UTF8'
        ));
        INSERT INTO demand.manual_funding_review_cases (
            id, organization_id, demand_id, demand_version_id, funding_id,
            status, aggregate_version, target_sha256, evidence_kind,
            evidence_reference_sha256, sandbox_funds_amount_minor,
            legal_effect, required_confirmations, expires_at, created_at
        ) VALUES (
            new_funding_review_id, root_row.organization_id, exact_demand_id,
            root_row.current_version_id, new_funding_id, 'PENDING', 1,
            target_digest, exact_evidence_kind, evidence_digest,
            sandbox_funds_amount_minor, exact_legal_effect, 2,
            case_expires, now_at
        );
        SELECT * INTO review_row
        FROM demand.manual_funding_review_cases AS review
        WHERE review.id = new_funding_review_id;
    END IF;

    SELECT count(DISTINCT confirmation.actor_user_id)
    INTO confirmation_total
    FROM demand.manual_funding_confirmations AS confirmation
    WHERE confirmation.funding_review_id = review_row.id;
    IF confirmation_total NOT IN (0, 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_state_conflict',
            MESSAGE = 'Finance funding confirmation count is invalid';
    END IF;

    INSERT INTO demand.manual_funding_receipts (
        receipt_id, principal_id, organization_id, demand_id,
        funding_review_id, command_name, command_version,
        idempotency_key_digest_key_id, idempotency_key_digest,
        payload_hash_key_id, canonicalization_version, payload_hash,
        expected_demand_revision, expected_review_revision, status,
        retain_until, created_at
    ) VALUES (
        new_receipt_id, exact_actor_user_id, root_row.organization_id,
        exact_demand_id, review_row.id, 'ClaimManualFundingReview', 1,
        exact_idempotency_key_digest_key_id, exact_idempotency_key_digest,
        exact_payload_hash_key_id, 'demand-command-json-v1',
        exact_payload_hash, expected_demand_revision,
        expected_review_revision, 'IN_PROGRESS', now_at + interval '7 days',
        now_at
    ) ON CONFLICT DO NOTHING;

    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.receipt_id = new_receipt_id
           OR (
                receipt.principal_id = exact_actor_user_id
                AND receipt.command_name = 'ClaimManualFundingReview'
                AND receipt.command_version = 1
                AND receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_id
                AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digest
           )
        FOR UPDATE;
        IF NOT FOUND
           OR receipt_row.demand_id <> exact_demand_id
           OR receipt_row.expected_demand_revision
                IS DISTINCT FROM expected_demand_revision
           OR receipt_row.expected_review_revision
                IS DISTINCT FROM expected_review_revision
           OR receipt_row.payload_hash_key_id <> exact_payload_hash_key_id
           OR receipt_row.payload_hash <> exact_payload_hash THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'finance_funding_idempotency_reused',
                MESSAGE = 'Finance funding claim idempotency conflict';
        END IF;
        IF receipt_row.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'finance_funding_receipt_incomplete',
                MESSAGE = 'Finance funding claim receipt is incomplete';
        END IF;
        RETURN QUERY SELECT
            (receipt_row.safe_response_body->>'funding_review_id')::uuid,
            receipt_row.demand_id,
            (receipt_row.safe_response_body->>'demand_version_id')::uuid,
            receipt_row.safe_response_body->>'status',
            (receipt_row.safe_response_body->>'review_revision')::bigint,
            (receipt_row.safe_response_body->>'assignment_id')::uuid,
            (receipt_row.safe_response_body->>'assignment_expires_at')::timestamptz,
            decode(receipt_row.safe_response_body->>'target_sha256', 'hex'),
            decode(
                receipt_row.safe_response_body->>'evidence_reference_sha256',
                'hex'
            ),
            (receipt_row.safe_response_body->>'confirmation_count')::bigint,
            (receipt_row.safe_response_body->>'can_confirm')::boolean,
            true;
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.funding_review_id = review_row.id
          AND assignment.actor_user_id = exact_actor_user_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'finance_funding_already_assigned',
            MESSAGE = 'Finance funding actor is already assigned';
    END IF;
    IF (
        SELECT count(*)
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.funding_review_id = review_row.id
          AND assignment.status IN ('ACTIVE', 'COMPLETED')
    ) >= 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'finance_funding_already_assigned',
            MESSAGE = 'Finance funding review already has two operators';
    END IF;

    assignment_expires := LEAST(
        review_row.expires_at,
        now_at + interval '30 minutes',
        COALESCE(
            authority_row.duty_expires_at,
            now_at + interval '30 minutes'
        )
    );
    IF assignment_expires <= now_at THEN RETURN; END IF;
    conflict_digest := sha256(convert_to(
        'manual-funding-conflict-v1|' || exact_actor_user_id::text || '|' ||
        root_row.organization_id::text || '|' || exact_demand_id::text || '|' ||
        review_row.id::text || '|' || review_row.demand_version_id::text || '|' ||
        authority_row.duty_grant_id::text || '|' ||
        authority_row.duty_grant_version::text,
        'UTF8'
    ));

    INSERT INTO demand.manual_funding_review_assignments (
        id, organization_id, demand_id, funding_review_id, actor_user_id,
        duty_grant_id, duty_grant_version, purpose_code,
        conflict_attestation_sha256, authority_marker_sha256, status,
        aggregate_version, expires_at, created_at
    ) VALUES (
        new_assignment_id, root_row.organization_id, exact_demand_id,
        review_row.id, exact_actor_user_id, authority_row.duty_grant_id,
        authority_row.duty_grant_version, 'MANUAL_FUNDING_REVIEW',
        conflict_digest, authority_row.authority_marker_sha256, 'ACTIVE', 1,
        assignment_expires, now_at
    );

    IF expected_demand_revision IS NOT NULL THEN
        next_review_revision := review_row.aggregate_version;
        result_event := 'DemandFundingRequested';
    ELSE
        next_review_revision := review_row.aggregate_version + 1;
        UPDATE demand.manual_funding_review_cases
        SET aggregate_version = next_review_revision
        WHERE id = review_row.id;
        result_event := 'DemandFundingReviewClaimed';
    END IF;
    next_demand_revision := root_row.aggregate_version + 1;
    UPDATE demand.demands
    SET status = 'FUNDING_PENDING',
        aggregate_version = next_demand_revision,
        updated_at = now_at
    WHERE id = exact_demand_id;

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id,
        before_status, after_status, before_version, after_version,
        role_code, purpose_code, reason_code, auth_strength_code,
        result_code, command_id, correlation_id, causation_id, trace_id,
        safe_attributes
    ) VALUES (
        new_audit_event_id, now_at, 'USER', exact_actor_user_id, NULL,
        CASE WHEN result_event = 'DemandFundingRequested'
            THEN 'START_MANUAL_FUNDING_REVIEW'
            ELSE 'JOIN_MANUAL_FUNDING_REVIEW' END,
        'Demand', exact_demand_id, root_row.organization_id,
        root_row.status, 'FUNDING_PENDING', root_row.aggregate_version,
        next_demand_revision, 'FINANCE_OPERATOR',
        'MANUAL_FUNDING_REVIEW', NULL, NULL, 'SUCCEEDED', new_receipt_id,
        exact_correlation_id, exact_causation_id, exact_trace_id,
        jsonb_build_object(
            'funding_review_id', review_row.id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'synthetic', true,
            'sandbox_funds_amount_minor', 0
        )
    );

    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at, aggregate_type,
        aggregate_id, aggregate_version, actor_kind, actor_id,
        original_actor_id, correlation_id, causation_id, trace_id,
        organization_id, payload, delivery_status, attempt_count,
        available_at, created_at
    ) VALUES (
        new_outbox_event_id, result_event, 1, now_at, 'Demand',
        exact_demand_id, next_demand_revision, 'USER', exact_actor_user_id,
        NULL, exact_correlation_id, exact_causation_id, exact_trace_id,
        root_row.organization_id,
        CASE WHEN result_event = 'DemandFundingRequested'
            THEN jsonb_build_object(
                'demand_id', exact_demand_id::text,
                'demand_version_id', review_row.demand_version_id::text,
                'funding_requirement_id', review_row.id::text,
                'status', 'FUNDING_PENDING'
            )
            ELSE jsonb_build_object(
                'demand_id', exact_demand_id::text,
                'demand_version_id', review_row.demand_version_id::text,
                'funding_requirement_id', review_row.id::text,
                'confirmation_count', confirmation_total,
                'status', 'FUNDING_PENDING'
            )
        END,
        'PENDING', 0, now_at, now_at
    );

    result_etag := '"funding-review-' || next_review_revision::text || '"';
    UPDATE demand.manual_funding_receipts
    SET status = 'COMPLETED',
        safe_response_body = jsonb_build_object(
            'funding_review_id', review_row.id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'status', 'PENDING',
            'review_revision', next_review_revision,
            'assignment_id', new_assignment_id::text,
            'assignment_expires_at',
                to_char(assignment_expires AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'target_sha256', encode(review_row.target_sha256, 'hex'),
            'evidence_reference_sha256',
                encode(review_row.evidence_reference_sha256, 'hex'),
            'confirmation_count', confirmation_total,
            'can_confirm', true
        ),
        response_entity_tag = result_etag,
        result_event_type = result_event,
        completed_at = now_at
    WHERE receipt_id = new_receipt_id;

    RETURN QUERY SELECT
        review_row.id,
        exact_demand_id,
        review_row.demand_version_id,
        'PENDING'::text,
        next_review_revision,
        new_assignment_id,
        assignment_expires,
        review_row.target_sha256,
        review_row.evidence_reference_sha256,
        confirmation_total,
        true,
        false;
END
$function$;

CREATE FUNCTION demand_api.confirm_manual_funding_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_funding_review_id uuid,
    expected_review_revision bigint,
    expected_principal_marker_sha256 bytea,
    exact_attestation_codes text[],
    new_confirmation_id uuid,
    new_funding_marker_id uuid,
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
    funding_review_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    status text,
    review_revision bigint,
    assignment_id uuid,
    assignment_expires_at timestamptz,
    target_sha256 bytea,
    evidence_reference_sha256 bytea,
    confirmation_count bigint,
    can_confirm boolean,
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
    review_row demand.manual_funding_review_cases%ROWTYPE;
    root_row record;
    assignment_row demand.manual_funding_review_assignments%ROWTYPE;
    authority_row record;
    receipt_row demand.manual_funding_receipts%ROWTYPE;
    confirmation_total bigint;
    next_review_revision bigint;
    next_demand_revision bigint;
    result_status text;
    result_event text;
    result_etag text;
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_funding_review_id IS NULL OR exact_funding_review_id = zero_uuid
       OR expected_review_revision IS NULL OR expected_review_revision < 1
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR exact_attestation_codes IS DISTINCT FROM ARRAY[
            'SYNTHETIC_ONLY',
            'ZERO_REAL_FUNDS',
            'NO_PROVIDER_OR_PAYMENT',
            'TARGET_AND_EVIDENCE_MATCH'
       ]::text[]
       OR new_confirmation_id IS NULL OR new_confirmation_id = zero_uuid
       OR new_funding_marker_id IS NULL OR new_funding_marker_id = zero_uuid
       OR new_receipt_id IS NULL OR new_receipt_id = zero_uuid
       OR new_audit_event_id IS NULL OR new_audit_event_id = zero_uuid
       OR new_outbox_event_id IS NULL OR new_outbox_event_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_idempotency_key_digest_key_id IS NULL
       OR exact_payload_hash_key_id IS NULL
       OR exact_idempotency_key_digest_key_id = exact_payload_hash_key_id
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CONFIRM_FUNDING_REVIEW'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.funding_review_id', true), '')
            IS DISTINCT FROM exact_funding_review_id::text THEN
        RETURN;
    END IF;

    SELECT * INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_catalog.set_config(
        'app.organization_id', review_row.organization_id::text, true
    );
    PERFORM pg_catalog.set_config(
        'app.demand_id', review_row.demand_id::text, true
    );

    SELECT * INTO authority_row
    FROM iam_api.lock_finance_funding_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        review_row.organization_id,
        review_row.demand_id,
        'CONFIRM_FUNDING_REVIEW',
        expected_principal_marker_sha256
    );
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = review_row.organization_id
      AND root.id = review_row.demand_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO assignment_row
    FROM demand.manual_funding_review_assignments AS assignment
    WHERE assignment.organization_id = review_row.organization_id
      AND assignment.demand_id = review_row.demand_id
      AND assignment.funding_review_id = review_row.id
      AND assignment.actor_user_id = exact_actor_user_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM pg_catalog.set_config(
        'app.assignment_id', assignment_row.id::text, true
    );

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
            CONSTRAINT = 'finance_funding_key_policy_unavailable',
            MESSAGE = 'Finance funding key policy is unavailable';
    END IF;

    INSERT INTO demand.manual_funding_receipts (
        receipt_id, principal_id, organization_id, demand_id,
        funding_review_id, command_name, command_version,
        idempotency_key_digest_key_id, idempotency_key_digest,
        payload_hash_key_id, canonicalization_version, payload_hash,
        expected_review_revision, status, retain_until, created_at
    ) VALUES (
        new_receipt_id, exact_actor_user_id, review_row.organization_id,
        review_row.demand_id, review_row.id, 'ConfirmManualFundingReview', 1,
        exact_idempotency_key_digest_key_id, exact_idempotency_key_digest,
        exact_payload_hash_key_id, 'demand-command-json-v1',
        exact_payload_hash, expected_review_revision, 'IN_PROGRESS',
        now_at + interval '7 days', now_at
    ) ON CONFLICT DO NOTHING;

    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.receipt_id = new_receipt_id
           OR (
                receipt.principal_id = exact_actor_user_id
                AND receipt.command_name = 'ConfirmManualFundingReview'
                AND receipt.command_version = 1
                AND receipt.idempotency_key_digest_key_id
                    = exact_idempotency_key_digest_key_id
                AND receipt.idempotency_key_digest
                    = exact_idempotency_key_digest
           )
        FOR UPDATE;
        IF NOT FOUND
           OR receipt_row.funding_review_id <> exact_funding_review_id
           OR receipt_row.expected_review_revision <> expected_review_revision
           OR receipt_row.payload_hash_key_id <> exact_payload_hash_key_id
           OR receipt_row.payload_hash <> exact_payload_hash THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'finance_funding_idempotency_reused',
                MESSAGE = 'Finance funding confirmation idempotency conflict';
        END IF;
        IF receipt_row.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'finance_funding_receipt_incomplete',
                MESSAGE = 'Finance funding confirmation receipt is incomplete';
        END IF;
        RETURN QUERY SELECT
            receipt_row.funding_review_id,
            receipt_row.demand_id,
            (receipt_row.safe_response_body->>'demand_version_id')::uuid,
            receipt_row.safe_response_body->>'status',
            (receipt_row.safe_response_body->>'review_revision')::bigint,
            (receipt_row.safe_response_body->>'assignment_id')::uuid,
            (receipt_row.safe_response_body->>'assignment_expires_at')::timestamptz,
            decode(receipt_row.safe_response_body->>'target_sha256', 'hex'),
            decode(
                receipt_row.safe_response_body->>'evidence_reference_sha256',
                'hex'
            ),
            (receipt_row.safe_response_body->>'confirmation_count')::bigint,
            false,
            true;
        RETURN;
    END IF;

    IF review_row.aggregate_version <> expected_review_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            CONSTRAINT = 'finance_funding_precondition_failed',
            MESSAGE = 'Finance funding confirmation precondition failed';
    END IF;
    IF review_row.status <> 'PENDING'
       OR root_row.status <> 'FUNDING_PENDING'
       OR root_row.current_version_id <> review_row.demand_version_id
       OR root_row.verified_version_id <> review_row.demand_version_id
       OR now_at >= review_row.expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_state_conflict',
            MESSAGE = 'Finance funding review cannot be confirmed';
    END IF;
    IF assignment_row.status <> 'ACTIVE'
       OR now_at >= assignment_row.expires_at
       OR assignment_row.duty_grant_id <> authority_row.duty_grant_id
       OR assignment_row.duty_grant_version
            <> authority_row.duty_grant_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_assignment_expired',
            MESSAGE = 'Finance funding assignment is unavailable';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM demand.manual_funding_confirmations AS confirmation
        WHERE confirmation.funding_review_id = review_row.id
          AND confirmation.actor_user_id = exact_actor_user_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'finance_funding_confirmation_duplicate',
            MESSAGE = 'Finance funding operator already confirmed';
    END IF;

    INSERT INTO demand.manual_funding_confirmations (
        id, organization_id, demand_id, funding_review_id, assignment_id,
        actor_user_id, attestation_codes, target_sha256,
        evidence_reference_sha256, confirmed_at
    ) VALUES (
        new_confirmation_id, review_row.organization_id,
        review_row.demand_id, review_row.id, assignment_row.id,
        exact_actor_user_id, exact_attestation_codes,
        review_row.target_sha256, review_row.evidence_reference_sha256,
        now_at
    );

    UPDATE demand.manual_funding_review_assignments
    SET status = 'COMPLETED',
        aggregate_version = aggregate_version + 1,
        completed_at = now_at
    WHERE id = assignment_row.id;

    SELECT count(DISTINCT confirmation.actor_user_id)
    INTO confirmation_total
    FROM demand.manual_funding_confirmations AS confirmation
    WHERE confirmation.funding_review_id = review_row.id;
    IF confirmation_total NOT IN (1, 2) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_state_conflict',
            MESSAGE = 'Finance funding confirmation count is invalid';
    END IF;
    -- Static and real-PG regressions pin the four-eyes predicate literally:
    -- count(DISTINCT confirmation.actor_user_id) = 2
    next_review_revision := review_row.aggregate_version + 1;
    next_demand_revision := root_row.aggregate_version + 1;
    IF confirmation_total = 2 THEN
        IF (
            SELECT count(DISTINCT confirmation.actor_user_id) = 2
            FROM demand.manual_funding_confirmations AS confirmation
            WHERE confirmation.funding_review_id = review_row.id
        ) IS NOT TRUE THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'finance_funding_state_conflict',
                MESSAGE = 'Finance funding four-eyes rule failed';
        END IF;
        INSERT INTO demand.demand_funding_markers (
            id, organization_id, demand_id, demand_version_id, funding_id,
            status, source_event_id, source_aggregate_version,
            amount_currency_sha256, verification_reference_sha256,
            occurred_at, created_at
        ) VALUES (
            new_funding_marker_id, review_row.organization_id,
            review_row.demand_id, review_row.demand_version_id,
            review_row.funding_id, 'SECURED', new_outbox_event_id,
            next_review_revision,
            sha256(convert_to(
                'internal-sandbox-zero-funds-v1|0|XXX', 'UTF8'
            )),
            review_row.evidence_reference_sha256, now_at, now_at
        );
        UPDATE demand.manual_funding_review_cases
        SET status = 'SECURED', aggregate_version = next_review_revision,
            completed_at = now_at
        WHERE id = review_row.id;
        UPDATE demand.demands
        SET status = 'FUNDED', aggregate_version = next_demand_revision,
            current_funding_marker_id = new_funding_marker_id,
            updated_at = now_at
        WHERE id = review_row.demand_id;
        result_status := 'SECURED';
        result_event := 'DemandFunded';
    ELSE
        UPDATE demand.manual_funding_review_cases
        SET aggregate_version = next_review_revision
        WHERE id = review_row.id;
        UPDATE demand.demands
        SET aggregate_version = next_demand_revision,
            updated_at = now_at
        WHERE id = review_row.demand_id;
        result_status := 'PENDING';
        result_event := 'DemandFundingEvidenceConfirmed';
    END IF;

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id,
        before_status, after_status, before_version, after_version,
        role_code, purpose_code, reason_code, auth_strength_code,
        result_code, command_id, correlation_id, causation_id, trace_id,
        safe_attributes
    ) VALUES (
        new_audit_event_id, now_at, 'USER', exact_actor_user_id, NULL,
        'CONFIRM_MANUAL_FUNDING_EVIDENCE', 'Demand', review_row.demand_id,
        review_row.organization_id, root_row.status,
        CASE WHEN result_status = 'SECURED' THEN 'FUNDED'
             ELSE 'FUNDING_PENDING' END,
        root_row.aggregate_version, next_demand_revision,
        'FINANCE_OPERATOR', 'MANUAL_FUNDING_REVIEW', NULL, NULL,
        'SUCCEEDED', new_receipt_id, exact_correlation_id,
        exact_causation_id, exact_trace_id,
        jsonb_build_object(
            'funding_review_id', review_row.id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'confirmation_count', confirmation_total,
            'synthetic', true,
            'sandbox_funds_amount_minor', 0
        )
    );

    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at, aggregate_type,
        aggregate_id, aggregate_version, actor_kind, actor_id,
        original_actor_id, correlation_id, causation_id, trace_id,
        organization_id, payload, delivery_status, attempt_count,
        available_at, created_at
    ) VALUES (
        new_outbox_event_id, result_event, 1, now_at, 'Demand',
        review_row.demand_id, next_demand_revision, 'USER',
        exact_actor_user_id, NULL, exact_correlation_id, exact_causation_id,
        exact_trace_id, review_row.organization_id,
        CASE WHEN result_event = 'DemandFunded'
            THEN jsonb_build_object(
                'demand_id', review_row.demand_id::text,
                'demand_version_id', review_row.demand_version_id::text,
                'funding_id', review_row.funding_id::text,
                'status', 'FUNDED'
            )
            ELSE jsonb_build_object(
                'demand_id', review_row.demand_id::text,
                'demand_version_id', review_row.demand_version_id::text,
                'funding_requirement_id', review_row.id::text,
                'confirmation_count', confirmation_total,
                'status', 'FUNDING_PENDING'
            )
        END,
        'PENDING', 0, now_at, now_at
    );

    result_etag := '"funding-review-' || next_review_revision::text || '"';
    UPDATE demand.manual_funding_receipts
    SET status = 'COMPLETED',
        safe_response_body = jsonb_build_object(
            'demand_version_id', review_row.demand_version_id::text,
            'status', result_status,
            'review_revision', next_review_revision,
            'assignment_id', assignment_row.id::text,
            'assignment_expires_at',
                to_char(assignment_row.expires_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'target_sha256', encode(review_row.target_sha256, 'hex'),
            'evidence_reference_sha256',
                encode(review_row.evidence_reference_sha256, 'hex'),
            'confirmation_count', confirmation_total,
            'can_confirm', false
        ),
        response_entity_tag = result_etag,
        result_event_type = result_event,
        completed_at = now_at
    WHERE receipt_id = new_receipt_id;

    RETURN QUERY SELECT
        review_row.id,
        review_row.demand_id,
        review_row.demand_version_id,
        result_status,
        next_review_revision,
        assignment_row.id,
        assignment_row.expires_at,
        review_row.target_sha256,
        review_row.evidence_reference_sha256,
        confirmation_total,
        false,
        false;
END
$function$;

ALTER FUNCTION demand_api.list_manual_funding_reviews_v1(
    uuid, uuid, bytea, integer
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.get_manual_funding_review_v1(
    uuid, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.claim_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.confirm_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) OWNER TO demand_schema_owner;

REVOKE ALL ON FUNCTION demand_api.list_manual_funding_reviews_v1(
    uuid, uuid, bytea, integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.get_manual_funding_review_v1(
    uuid, uuid, uuid, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.claim_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION demand_api.confirm_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;

GRANT USAGE ON SCHEMA demand_api TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.list_manual_funding_reviews_v1(
    uuid, uuid, bytea, integer
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.get_manual_funding_review_v1(
    uuid, uuid, uuid, bytea
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.claim_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.confirm_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_finance;

SET LOCAL ROLE schema_owner;

CREATE POLICY rls_finance_funding_audit_definer
ON audit.audit_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
    AND actor_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND target_kind = 'Demand'
    AND target_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND role_code = 'FINANCE_OPERATOR'
    AND purpose_code = 'MANUAL_FUNDING_REVIEW'
    AND action_code IN (
        'START_MANUAL_FUNDING_REVIEW',
        'JOIN_MANUAL_FUNDING_REVIEW',
        'CONFIRM_MANUAL_FUNDING_EVIDENCE'
    )
);

CREATE POLICY rls_finance_funding_outbox_definer
ON infra.outbox_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    )
    AND actor_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND aggregate_type = 'Demand'
    AND aggregate_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND event_type IN (
        'DemandFundingRequested',
        'DemandFundingReviewClaimed',
        'DemandFundingEvidenceConfirmed',
        'DemandFunded'
    )
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
      AND relation.relname IN (
          'manual_funding_review_cases',
          'manual_funding_review_assignments',
          'manual_funding_confirmations',
          'manual_funding_receipts'
      )
      AND (
          relation.relkind <> 'r'
          OR NOT relation.relrowsecurity
          OR NOT relation.relforcerowsecurity
      );
    IF invalid_count <> 0
       OR pg_catalog.has_table_privilege(
            'demand_finance',
            'demand.manual_funding_review_cases',
            'SELECT,INSERT,UPDATE,DELETE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.list_manual_funding_reviews_v1(uuid,uuid,bytea,integer)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.confirm_manual_funding_review_v1(uuid,uuid,uuid,bigint,bytea,text[],uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Finance funding review assertion failed';
    END IF;
END
$assert$;
