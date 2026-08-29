-- Demand10: controlled Finance funding-review resolution for INTERNAL_SANDBOX.
-- This forward-only migration records assignment/finding facts only.  It has
-- no representation of real-money or provider-side execution.

ALTER TABLE demand.manual_funding_review_cases
DROP CONSTRAINT uq_manual_funding_case_demand;

CREATE UNIQUE INDEX uq_manual_funding_case_current_cycle
ON demand.manual_funding_review_cases (organization_id, demand_id)
WHERE status = 'PENDING';

ALTER TABLE demand.manual_funding_review_assignments
DROP CONSTRAINT uq_manual_funding_assignment_actor;

CREATE UNIQUE INDEX uq_manual_funding_assignment_active_actor
ON demand.manual_funding_review_assignments (
    funding_review_id, actor_user_id
)
WHERE status = 'ACTIVE';

CREATE FUNCTION demand.text_array_is_sorted_unique_v1(input_values text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT input_values IS NOT NULL
       AND array_position(input_values, NULL) IS NULL
       AND input_values = ARRAY(
            SELECT value
            FROM unnest(input_values) AS value
            ORDER BY value
       )
       AND cardinality(input_values) = cardinality(ARRAY(
            SELECT DISTINCT value FROM unnest(input_values) AS value
       ))
$function$;
REVOKE ALL ON FUNCTION demand.text_array_is_sorted_unique_v1(text[])
FROM PUBLIC;

ALTER TABLE demand.manual_funding_review_cases
DROP CONSTRAINT ck_manual_funding_case_shape;
ALTER TABLE demand.manual_funding_review_cases
ADD CONSTRAINT ck_manual_funding_case_shape CHECK (
    aggregate_version >= 1
    AND status IN ('PENDING', 'SECURED', 'DISCREPANCY', 'REJECTED')
    AND expires_at > created_at
    AND (
        (status = 'PENDING' AND completed_at IS NULL)
        OR (status <> 'PENDING' AND completed_at >= created_at)
    )
);

ALTER TABLE demand.manual_funding_review_assignments
DROP CONSTRAINT ck_manual_funding_assignment_shape;
ALTER TABLE demand.manual_funding_review_assignments
ADD CONSTRAINT ck_manual_funding_assignment_shape CHECK (
    purpose_code = 'MANUAL_FUNDING_REVIEW'
    AND duty_grant_version >= 1
    AND aggregate_version >= 1
    AND octet_length(conflict_attestation_sha256) = 32
    AND octet_length(authority_marker_sha256) = 32
    AND expires_at > created_at
    AND status IN (
        'ACTIVE', 'COMPLETED', 'REVOKED', 'RELEASED', 'EXPIRED'
    )
    AND (
        (status = 'ACTIVE' AND completed_at IS NULL)
        OR (status <> 'ACTIVE' AND completed_at >= created_at)
    )
);

CREATE TABLE demand.manual_funding_assignment_releases (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    funding_review_id uuid NOT NULL,
    assignment_id uuid NOT NULL UNIQUE,
    actor_user_id uuid NOT NULL,
    reason_code varchar(64) NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    released_at timestamptz NOT NULL,
    CONSTRAINT fk_manual_funding_release_assignment FOREIGN KEY (
        organization_id, demand_id, funding_review_id, assignment_id
    ) REFERENCES demand.manual_funding_review_assignments (
        organization_id, demand_id, funding_review_id, id
    ),
    CONSTRAINT ck_manual_funding_release_shape CHECK (
        reason_code IN ('CONFLICT_DECLARED', 'WORKLOAD_RELEASE')
        AND octet_length(authority_marker_sha256) = 32
    )
);

CREATE TABLE demand.manual_funding_findings (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    funding_review_id uuid NOT NULL UNIQUE,
    assignment_id uuid NOT NULL UNIQUE,
    actor_user_id uuid NOT NULL,
    disposition varchar(16) NOT NULL,
    reason_codes text[] NOT NULL,
    required_field_codes text[] NOT NULL,
    target_sha256 bytea NOT NULL,
    evidence_reference_sha256 bytea NOT NULL,
    authority_marker_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT fk_manual_funding_finding_case FOREIGN KEY (
        organization_id, demand_id, funding_review_id
    ) REFERENCES demand.manual_funding_review_cases (
        organization_id, demand_id, id
    ),
    CONSTRAINT fk_manual_funding_finding_assignment FOREIGN KEY (
        organization_id, demand_id, funding_review_id, assignment_id
    ) REFERENCES demand.manual_funding_review_assignments (
        organization_id, demand_id, funding_review_id, id
    ),
    CONSTRAINT fk_manual_funding_finding_version FOREIGN KEY (
        organization_id, demand_id, demand_version_id
    ) REFERENCES demand.demand_versions (organization_id, demand_id, id),
    CONSTRAINT ck_manual_funding_finding_shape CHECK (
        disposition IN ('DISCREPANCY', 'REJECTED')
        AND cardinality(reason_codes) BETWEEN 1 AND 3
        AND cardinality(required_field_codes) BETWEEN 1 AND 4
        AND demand.text_array_is_sorted_unique_v1(reason_codes)
        AND demand.text_array_is_sorted_unique_v1(required_field_codes)
        AND required_field_codes <@ ARRAY[
            'BUDGET', 'DECLARATIONS', 'RISK', 'SCOPE'
        ]::text[]
        AND (
            (disposition = 'DISCREPANCY' AND reason_codes <@ ARRAY[
                'EVIDENCE_REFERENCE_MISMATCH', 'TARGET_CONTENT_MISMATCH'
            ]::text[])
            OR (disposition = 'REJECTED' AND reason_codes <@ ARRAY[
                'BUDGET_PLAN_UNACCEPTABLE',
                'DECLARATION_CONFLICT',
                'SYNTHETIC_SCOPE_VIOLATION'
            ]::text[])
        )
        AND octet_length(target_sha256) = 32
        AND octet_length(evidence_reference_sha256) = 32
        AND octet_length(authority_marker_sha256) = 32
    )
);

ALTER TABLE demand.manual_funding_assignment_releases
ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_assignment_releases
FORCE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE demand.manual_funding_findings FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE demand.manual_funding_assignment_releases FROM PUBLIC;
REVOKE ALL ON TABLE demand.manual_funding_findings FROM PUBLIC;

CREATE OR REPLACE FUNCTION demand.protect_manual_funding_case_v1()
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
       OR NEW.status NOT IN (
            'PENDING', 'SECURED', 'DISCREPANCY', 'REJECTED'
       )
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (NEW.status = 'PENDING' AND NEW.completed_at IS NOT NULL)
       OR (NEW.status <> 'PENDING' AND NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_manual_funding_case_immutable',
            MESSAGE = 'manual funding case mutation is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION demand.protect_manual_funding_assignment_v1()
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
       OR NEW.status NOT IN (
            'COMPLETED', 'REVOKED', 'RELEASED', 'EXPIRED'
       )
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

CREATE TRIGGER trg_manual_funding_release_immutable
BEFORE UPDATE OR DELETE ON demand.manual_funding_assignment_releases
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

CREATE TRIGGER trg_manual_funding_finding_immutable
BEFORE UPDATE OR DELETE ON demand.manual_funding_findings
FOR EACH ROW EXECUTE FUNCTION demand.reject_immutable_fact_mutation();

ALTER TABLE demand.manual_funding_receipts
DROP CONSTRAINT ck_manual_funding_receipt_identity;
ALTER TABLE demand.manual_funding_receipts
ADD CONSTRAINT ck_manual_funding_receipt_identity CHECK (
    command_name IN (
        'ClaimManualFundingReview',
        'ConfirmManualFundingReview',
        'ReleaseManualFundingReviewAssignment',
        'SubmitManualFundingReviewFinding'
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
        OR (command_name <> 'ClaimManualFundingReview'
            AND expected_demand_revision IS NULL
            AND expected_review_revision >= 1)
    )
    AND retain_until >= created_at
);

ALTER TABLE demand.manual_funding_receipts
DROP CONSTRAINT ck_manual_funding_receipt_shape;
ALTER TABLE demand.manual_funding_receipts
ADD CONSTRAINT ck_manual_funding_receipt_shape CHECK (
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
                'DemandFunded',
                'DemandFundingReviewAssignmentReleased',
                'DemandFundingReviewFindingSubmitted'
            )
            AND completed_at >= created_at)
    )
);

CREATE POLICY rls_finance_funding_assignment_cleanup_definer
ON demand.manual_funding_review_assignments
FOR UPDATE TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_FUNDING_REVIEW'
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_FUNDING_REVIEW'
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND status IN ('EXPIRED', 'REVOKED')
);

CREATE POLICY rls_finance_funding_resolution_root_definer
ON demand.demands
FOR UPDATE TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
);

CREATE POLICY rls_finance_funding_resolution_case_definer
ON demand.manual_funding_review_cases
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
);

CREATE POLICY rls_finance_funding_resolution_assignment_definer
ON demand.manual_funding_review_assignments
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
);

CREATE POLICY rls_finance_funding_resolution_receipt_definer
ON demand.manual_funding_receipts
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
)
WITH CHECK (
    session_user = 'demand_finance'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
);

CREATE POLICY rls_finance_funding_release_definer
ON demand.manual_funding_assignment_releases
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND assignment_id::text
        = NULLIF(current_setting('app.assignment_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '')
        = 'RELEASE_FUNDING_REVIEW_ASSIGNMENT'
)
WITH CHECK (
    session_user = 'demand_finance'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND assignment_id::text
        = NULLIF(current_setting('app.assignment_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '')
        = 'RELEASE_FUNDING_REVIEW_ASSIGNMENT'
);

CREATE POLICY rls_finance_funding_finding_definer
ON demand.manual_funding_findings
FOR ALL TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND assignment_id::text
        = NULLIF(current_setting('app.assignment_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '')
        = 'SUBMIT_FUNDING_REVIEW_FINDING'
)
WITH CHECK (
    session_user = 'demand_finance'
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND funding_review_id::text
        = NULLIF(current_setting('app.funding_review_id', true), '')
    AND assignment_id::text
        = NULLIF(current_setting('app.assignment_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '')
        = 'SUBMIT_FUNDING_REVIEW_FINDING'
);

CREATE POLICY rls_finance_funding_resolution_version_definer
ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_finance'
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
);

CREATE POLICY rls_finance_funding_resolution_key_policy_definer
ON demand.receipt_key_policy
FOR SELECT TO demand_schema_owner
USING (
    singleton_key
    AND session_user = 'demand_finance'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
        'SUBMIT_FUNDING_REVIEW_FINDING'
    )
);

CREATE POLICY rls_demand_owner_finance_findings_definer
ON demand.manual_funding_findings
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'demand_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'DEMAND_OWNER'
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
    )
);

CREATE FUNCTION demand_api.list_manual_funding_reviews_v2(
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
DECLARE
    authority_row record;
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
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN;
    END IF;

    BEGIN
        SELECT * INTO STRICT authority_row
        FROM iam_api.authorize_finance_funding_queue_v1(
            exact_actor_user_id,
            exact_session_id,
            expected_principal_marker_sha256
        );
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

    RETURN QUERY
    SELECT
        root.id,
        root.current_version_id,
        root.aggregate_version,
        review.id,
        CASE WHEN review.id IS NULL THEN 'AVAILABLE' ELSE 'PENDING' END,
        COALESCE(confirmation.total, 0),
        review.aggregate_version,
        COALESCE(own_assignment.visible, false),
        root.expires_at
    FROM demand.demands AS root
    LEFT JOIN demand.manual_funding_review_cases AS review
      ON review.organization_id = root.organization_id
     AND review.demand_id = root.id
     AND review.demand_version_id = root.current_version_id
     AND review.status = 'PENDING'
    LEFT JOIN LATERAL (
        SELECT count(*) AS total
        FROM demand.manual_funding_confirmations AS item
        WHERE item.funding_review_id = review.id
    ) AS confirmation ON true
    LEFT JOIN LATERAL (
        SELECT true AS visible
        FROM demand.manual_funding_review_assignments AS own
        WHERE own.funding_review_id = review.id
          AND own.actor_user_id = exact_actor_user_id
          AND (
              (own.status = 'ACTIVE'
                AND transaction_timestamp() < own.expires_at
                AND own.duty_grant_id = authority_row.duty_grant_id
                AND own.duty_grant_version = authority_row.duty_grant_version)
              OR (own.status = 'COMPLETED' AND EXISTS (
                    SELECT 1
                    FROM demand.manual_funding_confirmations AS confirmed
                    WHERE confirmed.funding_review_id = review.id
                      AND confirmed.actor_user_id = exact_actor_user_id
              ))
          )
        LIMIT 1
    ) AS own_assignment ON true
    LEFT JOIN LATERAL (
        SELECT count(*) AS total
        FROM demand.manual_funding_review_assignments AS seat
        WHERE seat.funding_review_id = review.id
          AND (
              seat.status = 'COMPLETED'
              OR (seat.status = 'ACTIVE'
                  AND transaction_timestamp() < seat.expires_at
                  AND NOT (
                      seat.actor_user_id = exact_actor_user_id
                      AND (seat.duty_grant_id, seat.duty_grant_version)
                          IS DISTINCT FROM (
                              authority_row.duty_grant_id,
                              authority_row.duty_grant_version
                          )
                  ))
          )
    ) AS seat_count ON true
    WHERE (
        (root.status = 'VERIFIED' AND review.id IS NULL)
        OR (root.status = 'FUNDING_PENDING' AND review.id IS NOT NULL)
    )
      AND root.verified_version_id = root.current_version_id
      AND transaction_timestamp() < root.expires_at
      AND (
          review.id IS NULL
          OR COALESCE(own_assignment.visible, false)
          OR (
              confirmation.total < 2
              AND seat_count.total < 2
              AND NOT EXISTS (
                  SELECT 1
                  FROM demand.manual_funding_confirmations AS mine
                  WHERE mine.funding_review_id = review.id
                    AND mine.actor_user_id = exact_actor_user_id
              )
          )
      )
    ORDER BY root.updated_at, root.id
    LIMIT maximum_items;
END
$function$;

CREATE FUNCTION demand_api.get_manual_funding_review_v2(
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
    assignment_status text,
    confirmation_by_me boolean,
    available_actions text[],
    can_confirm boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    authority_row record;
    exact_demand_id uuid;
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
            IS DISTINCT FROM exact_funding_review_id::text THEN
        RETURN;
    END IF;

    SELECT review.demand_id INTO exact_demand_id
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('app.demand_id', exact_demand_id::text, true);

    BEGIN
        SELECT * INTO STRICT authority_row
        FROM iam_api.authorize_finance_funding_queue_v1(
            exact_actor_user_id,
            exact_session_id,
            expected_principal_marker_sha256
        );
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

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
        confirmation.total,
        assignment.status::text,
        COALESCE(confirmation.mine, false),
        CASE WHEN action.can_act THEN ARRAY[
            'CONFIRM', 'RELEASE_ASSIGNMENT', 'SUBMIT_FINDING'
        ]::text[] ELSE ARRAY[]::text[] END,
        action.can_act
    FROM demand.manual_funding_review_cases AS review
    JOIN demand.demands AS root
      ON root.organization_id = review.organization_id
     AND root.id = review.demand_id
    JOIN LATERAL (
        SELECT candidate.*
        FROM demand.manual_funding_review_assignments AS candidate
        WHERE candidate.funding_review_id = review.id
          AND candidate.actor_user_id = exact_actor_user_id
          AND (
              (candidate.status = 'ACTIVE'
                AND transaction_timestamp() < candidate.expires_at
                AND candidate.duty_grant_id = authority_row.duty_grant_id
                AND candidate.duty_grant_version
                    = authority_row.duty_grant_version)
              OR (candidate.status = 'COMPLETED' AND EXISTS (
                    SELECT 1
                    FROM demand.manual_funding_confirmations AS confirmed
                    WHERE confirmed.funding_review_id = review.id
                      AND confirmed.actor_user_id = exact_actor_user_id
              ))
              OR (candidate.status = 'COMPLETED' AND EXISTS (
                    SELECT 1
                    FROM demand.manual_funding_findings AS finding
                    WHERE finding.funding_review_id = review.id
                      AND finding.actor_user_id = exact_actor_user_id
              ))
          )
        ORDER BY (candidate.status = 'ACTIVE') DESC, candidate.created_at DESC
        LIMIT 1
    ) AS assignment ON true
    JOIN LATERAL (
        SELECT
            count(*) AS total,
            bool_or(item.actor_user_id = exact_actor_user_id) AS mine
        FROM demand.manual_funding_confirmations AS item
        WHERE item.funding_review_id = review.id
    ) AS confirmation ON true
    JOIN LATERAL (
        SELECT review.status = 'PENDING'
           AND assignment.status = 'ACTIVE'
           AND transaction_timestamp() < assignment.expires_at
           AND transaction_timestamp() < root.expires_at
           AND confirmation.mine IS NOT TRUE AS can_act
    ) AS action ON true
    WHERE review.id = exact_funding_review_id;
END
$function$;

CREATE FUNCTION demand_api.read_demand_owner_findings_v2(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_operation text,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    finding_id uuid,
    demand_version_id uuid,
    assignment_id uuid,
    decision text,
    reason_codes text[],
    required_field_codes text[],
    reviewed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    resolved_authority_marker_sha256 bytea;
BEGIN
    IF session_user IS DISTINCT FROM 'demand_self'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_organization_id IS NULL
       OR exact_demand_id IS NULL
       OR exact_operation NOT IN (
            'CREATE', 'CREATE_VERSION', 'SUBMIT', 'CANCEL_OWNER'
       )
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'DEMAND_OWNER'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
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

    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT resolved_authority_marker_sha256
        FROM iam_api.resolve_demand_owner_authority_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_organization_id,
            exact_operation,
            exact_demand_id
        ) AS marker;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;
    IF resolved_authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    PERFORM 1
    FROM demand.demands AS root
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id;
    IF NOT FOUND THEN RETURN; END IF;

    RETURN QUERY
    SELECT combined.finding_id,
           combined.demand_version_id,
           combined.assignment_id,
           combined.decision,
           combined.reason_codes,
           combined.required_field_codes,
           combined.reviewed_at
    FROM (
        SELECT
            review.id AS finding_id,
            review.demand_version_id,
            review.assignment_id,
            review.decision::text AS decision,
            review.reason_codes,
            review.required_field_codes,
            review.reviewed_at
        FROM demand.demand_reviews AS review
        WHERE review.organization_id = exact_organization_id
          AND review.demand_id = exact_demand_id
        UNION ALL
        SELECT
            finding.id AS finding_id,
            finding.demand_version_id,
            NULL::uuid AS assignment_id,
            finding.disposition::text AS decision,
            finding.reason_codes,
            finding.required_field_codes,
            finding.created_at AS reviewed_at
        FROM demand.manual_funding_findings AS finding
        WHERE finding.organization_id = exact_organization_id
          AND finding.demand_id = exact_demand_id
    ) AS combined
    ORDER BY combined.reviewed_at, combined.finding_id;
END
$function$;

CREATE FUNCTION demand_api.read_manual_funding_evidence_v2(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_funding_review_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    target_content_sha256 bytea,
    planned_budget_currency text,
    planned_budget_minimum_amount_minor bigint,
    planned_budget_maximum_amount_minor bigint,
    planned_budget_direct_cost_amount_minor bigint,
    sandbox_funds_amount_minor bigint,
    provider_code text,
    payment_operation_code text,
    evidence_kind text,
    legal_effect text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    exact_operation text;
    review_row record;
    assignment_row record;
    authority_row record;
    version_row record;
    receipt_row demand.manual_funding_receipts%ROWTYPE;
    receipt_replayed boolean := false;
    minimum_amount numeric;
    maximum_amount numeric;
    direct_cost_amount numeric;
BEGIN
    exact_operation := NULLIF(current_setting('app.operation', true), '');
    IF session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_funding_review_id IS NULL
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'FINANCE_FUNDING'
       OR exact_operation NOT IN (
            'GET_FUNDING_REVIEW',
            'CLAIM_FUNDING_REVIEW',
            'CONFIRM_FUNDING_REVIEW',
            'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
            'SUBMIT_FUNDING_REVIEW_FINDING'
       )
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.funding_review_id', true), '')
            IS DISTINCT FROM exact_funding_review_id::text
       OR NULLIF(current_setting('app.assignment_id', true), '') IS NULL THEN
        RETURN;
    END IF;

    SELECT
        review.organization_id,
        review.demand_id,
        review.demand_version_id,
        review.evidence_kind,
        review.sandbox_funds_amount_minor,
        review.legal_effect
    INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT
        assignment.id,
        assignment.actor_user_id,
        assignment.duty_grant_id,
        assignment.duty_grant_version,
        assignment.authority_marker_sha256,
        assignment.status,
        assignment.expires_at
    INTO assignment_row
    FROM demand.manual_funding_review_assignments AS assignment
    WHERE assignment.organization_id = review_row.organization_id
      AND assignment.demand_id = review_row.demand_id
      AND assignment.funding_review_id = exact_funding_review_id
      AND assignment.actor_user_id = exact_actor_user_id
      AND assignment.id::text
            = NULLIF(current_setting('app.assignment_id', true), '');
    IF NOT FOUND THEN RETURN; END IF;

    receipt_replayed := COALESCE(
        NULLIF(current_setting('app.receipt_replayed', true), '') = 'true',
        false
    );
    IF receipt_replayed THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.receipt_id::text
                = NULLIF(current_setting('app.receipt_id', true), '')
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.organization_id = review_row.organization_id
          AND receipt.demand_id = review_row.demand_id
          AND receipt.funding_review_id = exact_funding_review_id
          AND receipt.status = 'COMPLETED'
          AND receipt.safe_response_body->>'assignment_id'
                = assignment_row.id::text
          AND receipt.command_name = CASE exact_operation
                WHEN 'CLAIM_FUNDING_REVIEW'
                    THEN 'ClaimManualFundingReview'
                WHEN 'CONFIRM_FUNDING_REVIEW'
                    THEN 'ConfirmManualFundingReview'
                WHEN 'RELEASE_FUNDING_REVIEW_ASSIGNMENT'
                    THEN 'ReleaseManualFundingReviewAssignment'
                WHEN 'SUBMIT_FUNDING_REVIEW_FINDING'
                    THEN 'SubmitManualFundingReviewFinding'
                ELSE ''
              END;
        IF NOT FOUND THEN RETURN; END IF;
    END IF;

    IF exact_operation = 'GET_FUNDING_REVIEW' THEN
        BEGIN
            SELECT * INTO STRICT authority_row
            FROM iam_api.authorize_finance_funding_queue_v1(
                exact_actor_user_id,
                exact_session_id,
                expected_principal_marker_sha256
            );
        EXCEPTION
            WHEN no_data_found OR too_many_rows THEN RETURN;
        END;
        IF assignment_row.status = 'ACTIVE' AND (
            transaction_timestamp() >= assignment_row.expires_at
            OR assignment_row.duty_grant_id <> authority_row.duty_grant_id
            OR assignment_row.duty_grant_version
                <> authority_row.duty_grant_version
        ) THEN RETURN; END IF;
        IF assignment_row.status NOT IN ('ACTIVE', 'COMPLETED') THEN
            RETURN;
        END IF;
        PERFORM set_config(
            'app.organization_id', review_row.organization_id::text, true
        );
        PERFORM set_config('app.demand_id', review_row.demand_id::text, true);
    ELSIF exact_operation IN (
        'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
    ) THEN
        IF NULLIF(current_setting('app.organization_id', true), '')
                IS DISTINCT FROM review_row.organization_id::text
           OR NULLIF(current_setting('app.demand_id', true), '')
                IS DISTINCT FROM review_row.demand_id::text THEN
            RETURN;
        END IF;
        BEGIN
            SELECT * INTO STRICT authority_row
            FROM iam_api.lock_finance_funding_authority_v1(
                exact_actor_user_id,
                exact_session_id,
                review_row.organization_id,
                review_row.demand_id,
                exact_operation,
                expected_principal_marker_sha256
            );
        EXCEPTION
            WHEN no_data_found OR too_many_rows THEN RETURN;
        END;
        IF NOT receipt_replayed AND (
            assignment_row.duty_grant_id <> authority_row.duty_grant_id
            OR assignment_row.duty_grant_version
                <> authority_row.duty_grant_version
            OR (
                exact_operation = 'CLAIM_FUNDING_REVIEW'
                AND assignment_row.authority_marker_sha256
                    <> authority_row.authority_marker_sha256
            )
            OR assignment_row.status NOT IN ('ACTIVE', 'COMPLETED')
        ) THEN
            RETURN;
        END IF;
    ELSE
        IF NULLIF(current_setting('app.organization_id', true), '')
                IS DISTINCT FROM review_row.organization_id::text
           OR NULLIF(current_setting('app.demand_id', true), '')
                IS DISTINCT FROM review_row.demand_id::text THEN
            RETURN;
        END IF;
        BEGIN
            SELECT * INTO STRICT authority_row
            FROM iam_api.lock_finance_funding_authority_v2(
                exact_actor_user_id,
                exact_session_id,
                review_row.organization_id,
                review_row.demand_id,
                exact_funding_review_id,
                assignment_row.id,
                exact_operation,
                expected_principal_marker_sha256
            );
        EXCEPTION
            WHEN no_data_found OR too_many_rows THEN RETURN;
        END;
        IF NOT receipt_replayed AND (
            assignment_row.duty_grant_id <> authority_row.duty_grant_id
            OR assignment_row.duty_grant_version
                <> authority_row.duty_grant_version
        ) THEN
            RETURN;
        END IF;
        IF exact_operation = 'RELEASE_FUNDING_REVIEW_ASSIGNMENT' THEN
            PERFORM 1
            FROM demand.manual_funding_assignment_releases AS release
            WHERE release.assignment_id = assignment_row.id
              AND release.actor_user_id = exact_actor_user_id
              AND (
                  receipt_replayed
                  OR release.authority_marker_sha256
                        = authority_row.authority_marker_sha256
              );
            IF NOT FOUND OR (
                NOT receipt_replayed AND assignment_row.status <> 'RELEASED'
            ) THEN
                RETURN;
            END IF;
        ELSE
            PERFORM 1
            FROM demand.manual_funding_findings AS finding
            WHERE finding.assignment_id = assignment_row.id
              AND finding.actor_user_id = exact_actor_user_id
              AND (
                  receipt_replayed
                  OR finding.authority_marker_sha256
                        = authority_row.authority_marker_sha256
              );
            IF NOT FOUND OR (
                NOT receipt_replayed AND assignment_row.status <> 'COMPLETED'
            ) THEN
                RETURN;
            END IF;
        END IF;
    END IF;

    SELECT version.content, version.content_sha256
    INTO version_row
    FROM demand.demand_versions AS version
    WHERE version.organization_id = review_row.organization_id
      AND version.demand_id = review_row.demand_id
      AND version.id = review_row.demand_version_id;
    IF NOT FOUND
       OR octet_length(version_row.content_sha256) <> 32
       OR jsonb_typeof(version_row.content->'budget')
            IS DISTINCT FROM 'object'
       OR (
            SELECT array_agg(budget_key.key ORDER BY budget_key.key)
            FROM jsonb_object_keys(
                version_row.content->'budget'
            ) AS budget_key(key)
       ) IS DISTINCT FROM ARRAY[
            'currency',
            'direct_cost_amount_minor',
            'maximum_amount_minor',
            'minimum_amount_minor'
       ]::text[]
       OR version_row.content#>>'{budget,currency}' IS DISTINCT FROM 'CNY'
       OR jsonb_typeof(
            version_row.content#>'{budget,minimum_amount_minor}'
       ) IS DISTINCT FROM 'number'
       OR jsonb_typeof(
            version_row.content#>'{budget,maximum_amount_minor}'
       ) IS DISTINCT FROM 'number'
       OR jsonb_typeof(
            version_row.content#>'{budget,direct_cost_amount_minor}'
       ) IS DISTINCT FROM 'number'
       OR version_row.content#>>'{budget,minimum_amount_minor}'
            !~ '^(0|[1-9][0-9]{0,15})$'
       OR version_row.content#>>'{budget,maximum_amount_minor}'
            !~ '^(0|[1-9][0-9]{0,15})$'
       OR version_row.content#>>'{budget,direct_cost_amount_minor}'
            !~ '^(0|[1-9][0-9]{0,15})$' THEN
        RETURN;
    END IF;

    minimum_amount := (
        version_row.content#>>'{budget,minimum_amount_minor}'
    )::numeric;
    maximum_amount := (
        version_row.content#>>'{budget,maximum_amount_minor}'
    )::numeric;
    direct_cost_amount := (
        version_row.content#>>'{budget,direct_cost_amount_minor}'
    )::numeric;
    IF minimum_amount > maximum_amount
       OR minimum_amount > 9007199254740991
       OR maximum_amount > 9007199254740991
       OR direct_cost_amount > 9007199254740991
       OR review_row.evidence_kind
            <> 'INTERNAL_SANDBOX_ZERO_FUNDS_V1'
       OR review_row.sandbox_funds_amount_minor <> 0
       OR review_row.legal_effect <> 'NO_REAL_FUNDS_OR_PAYMENT' THEN
        RETURN;
    END IF;

    RETURN QUERY SELECT
        version_row.content_sha256,
        'CNY'::text,
        minimum_amount::bigint,
        maximum_amount::bigint,
        direct_cost_amount::bigint,
        review_row.sandbox_funds_amount_minor,
        'NONE'::text,
        'NONE'::text,
        review_row.evidence_kind::text,
        review_row.legal_effect::text;
END
$function$;

CREATE FUNCTION demand_api.claim_manual_funding_review_v2(
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
    assignment_status text,
    confirmation_by_me boolean,
    available_actions text[],
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
    expired_assignment_count integer := 0;
    stale_own_count integer := 0;
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

    PERFORM pg_advisory_xact_lock(
        hashtextextended(exact_demand_id::text, 104729)
    );
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

    PERFORM set_config(
        'app.organization_id', root_row.organization_id::text, true
    );
    BEGIN
        SELECT * INTO STRICT authority_row
        FROM iam_api.lock_finance_funding_authority_v1(
            exact_actor_user_id,
            exact_session_id,
            root_row.organization_id,
            exact_demand_id,
            'CLAIM_FUNDING_REVIEW',
            expected_principal_marker_sha256
        );
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

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
    FOR UPDATE;
    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = 'ClaimManualFundingReview'
          AND receipt.command_version = 1
          AND receipt.idempotency_key_digest_key_id
                = exact_idempotency_key_digest_key_id
          AND receipt.idempotency_key_digest = exact_idempotency_key_digest
        FOR UPDATE;
    END IF;
    IF FOUND THEN
        IF receipt_row.principal_id <> exact_actor_user_id
           OR receipt_row.command_name <> 'ClaimManualFundingReview'
           OR receipt_row.command_version <> 1
           OR receipt_row.idempotency_key_digest_key_id
                <> exact_idempotency_key_digest_key_id
           OR receipt_row.idempotency_key_digest
                <> exact_idempotency_key_digest
           OR receipt_row.canonicalization_version
                <> 'demand-command-json-v1'
           OR receipt_row.organization_id
                IS DISTINCT FROM root_row.organization_id
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
        PERFORM set_config(
            'app.funding_review_id', receipt_row.funding_review_id::text, true
        );
        PERFORM set_config(
            'app.assignment_id',
            receipt_row.safe_response_body->>'assignment_id',
            true
        );
        PERFORM set_config('app.receipt_replayed', 'true', true);
        PERFORM set_config('app.receipt_id', receipt_row.receipt_id::text, true);
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
            receipt_row.safe_response_body->>'assignment_status',
            (receipt_row.safe_response_body->>'confirmation_by_me')::boolean,
            ARRAY(
                SELECT jsonb_array_elements_text(
                    receipt_row.safe_response_body->'available_actions'
                )
            ),
            (receipt_row.safe_response_body->>'can_confirm')::boolean,
            true;
        RETURN;
    END IF;

    SELECT * INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.organization_id = root_row.organization_id
      AND review.demand_id = exact_demand_id
      AND review.status = 'PENDING'
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
           OR review_row.demand_version_id <> root_row.current_version_id
           OR now_at >= root_row.expires_at THEN
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
        case_expires := root_row.expires_at;
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
            new_funding_review_id::text || '|' || encode(target_digest, 'hex'),
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
        SELECT * INTO STRICT review_row
        FROM demand.manual_funding_review_cases AS review
        WHERE review.id = new_funding_review_id;
    END IF;

    PERFORM set_config('app.funding_review_id', review_row.id::text, true);

    UPDATE demand.manual_funding_review_assignments AS assignment
    SET status = 'EXPIRED',
        aggregate_version = aggregate_version + 1,
        completed_at = now_at
    WHERE assignment.funding_review_id = review_row.id
      AND assignment.status = 'ACTIVE'
      AND assignment.expires_at <= now_at;
    GET DIAGNOSTICS expired_assignment_count = ROW_COUNT;

    UPDATE demand.manual_funding_review_assignments AS assignment
    SET status = 'REVOKED',
        aggregate_version = aggregate_version + 1,
        completed_at = now_at
    WHERE assignment.funding_review_id = review_row.id
      AND assignment.actor_user_id = exact_actor_user_id
      AND assignment.status = 'ACTIVE'
      AND (assignment.duty_grant_id, assignment.duty_grant_version)
            IS DISTINCT FROM (
          authority_row.duty_grant_id, authority_row.duty_grant_version
      );
    GET DIAGNOSTICS stale_own_count = ROW_COUNT;

    IF EXISTS (
        SELECT 1 FROM demand.manual_funding_confirmations AS confirmation
        WHERE confirmation.funding_review_id = review_row.id
          AND confirmation.actor_user_id = exact_actor_user_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'finance_funding_confirmation_duplicate',
            MESSAGE = 'Finance funding operator already confirmed';
    END IF;
    IF EXISTS (
        SELECT 1 FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.funding_review_id = review_row.id
          AND assignment.actor_user_id = exact_actor_user_id
          AND assignment.status = 'ACTIVE'
    ) OR (
        SELECT count(*)
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.funding_review_id = review_row.id
          AND assignment.status IN ('ACTIVE', 'COMPLETED')
    ) >= 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'finance_funding_already_assigned',
            MESSAGE = 'Finance funding review has no available seat';
    END IF;

    SELECT count(*) INTO confirmation_total
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
    );

    assignment_expires := LEAST(
        root_row.expires_at,
        now_at + interval '30 minutes',
        COALESCE(authority_row.duty_expires_at, now_at + interval '30 minutes')
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
    PERFORM set_config('app.assignment_id', new_assignment_id::text, true);

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
            'expired_assignment_count', expired_assignment_count,
            'stale_own_assignment_revoked', stale_own_count = 1,
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
            'assignment_status', 'ACTIVE',
            'confirmation_by_me', false,
            'available_actions', jsonb_build_array(
                'CONFIRM', 'RELEASE_ASSIGNMENT', 'SUBMIT_FINDING'
            ),
            'can_confirm', true
        ),
        response_entity_tag = result_etag,
        result_event_type = result_event,
        completed_at = now_at
    WHERE receipt_id = new_receipt_id;

    RETURN QUERY SELECT
        review_row.id,
        review_row.demand_id,
        review_row.demand_version_id,
        'PENDING'::text,
        next_review_revision,
        new_assignment_id,
        assignment_expires,
        review_row.target_sha256,
        review_row.evidence_reference_sha256,
        confirmation_total,
        'ACTIVE'::text,
        false,
        ARRAY['CONFIRM', 'RELEASE_ASSIGNMENT', 'SUBMIT_FINDING']::text[],
        true,
        false;
END
$function$;

CREATE FUNCTION demand_api.confirm_manual_funding_review_v2(
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
    assignment_status text,
    confirmation_by_me boolean,
    available_actions text[],
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
    root_row demand.demands%ROWTYPE;
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
       OR exact_funding_review_id IS NULL
       OR exact_funding_review_id = zero_uuid
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
    WHERE review.id = exact_funding_review_id;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(review_row.demand_id::text, 104729)
    );
    SELECT * INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config(
        'app.organization_id', review_row.organization_id::text, true
    );
    PERFORM set_config('app.demand_id', review_row.demand_id::text, true);

    BEGIN
        SELECT * INTO STRICT authority_row
        FROM iam_api.lock_finance_funding_authority_v1(
            exact_actor_user_id,
            exact_session_id,
            review_row.organization_id,
            review_row.demand_id,
            'CONFIRM_FUNDING_REVIEW',
            expected_principal_marker_sha256
        );
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

    SELECT * INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = review_row.organization_id
      AND root.id = review_row.demand_id
    FOR UPDATE;
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
    FOR UPDATE;
    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = 'ConfirmManualFundingReview'
          AND receipt.command_version = 1
          AND receipt.idempotency_key_digest_key_id
                = exact_idempotency_key_digest_key_id
          AND receipt.idempotency_key_digest = exact_idempotency_key_digest
        FOR UPDATE;
    END IF;
    IF FOUND THEN
        IF receipt_row.principal_id <> exact_actor_user_id
           OR receipt_row.command_name <> 'ConfirmManualFundingReview'
           OR receipt_row.command_version <> 1
           OR receipt_row.idempotency_key_digest_key_id
                <> exact_idempotency_key_digest_key_id
           OR receipt_row.idempotency_key_digest
                <> exact_idempotency_key_digest
           OR receipt_row.canonicalization_version
                <> 'demand-command-json-v1'
           OR receipt_row.organization_id
                IS DISTINCT FROM review_row.organization_id
           OR receipt_row.demand_id
                IS DISTINCT FROM review_row.demand_id
           OR receipt_row.funding_review_id <> exact_funding_review_id
           OR receipt_row.expected_review_revision
                IS DISTINCT FROM expected_review_revision
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
        PERFORM set_config(
            'app.assignment_id',
            receipt_row.safe_response_body->>'assignment_id',
            true
        );
        PERFORM set_config('app.receipt_replayed', 'true', true);
        PERFORM set_config('app.receipt_id', receipt_row.receipt_id::text, true);
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
            receipt_row.safe_response_body->>'assignment_status',
            (receipt_row.safe_response_body->>'confirmation_by_me')::boolean,
            ARRAY(
                SELECT jsonb_array_elements_text(
                    receipt_row.safe_response_body->'available_actions'
                )
            ),
            (receipt_row.safe_response_body->>'can_confirm')::boolean,
            true;
        RETURN;
    END IF;

    SELECT * INTO assignment_row
    FROM demand.manual_funding_review_assignments AS assignment
    WHERE assignment.funding_review_id = review_row.id
      AND assignment.actor_user_id = exact_actor_user_id
      AND assignment.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('app.assignment_id', assignment_row.id::text, true);

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
       OR now_at >= root_row.expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_state_conflict',
            MESSAGE = 'Finance funding review cannot be confirmed';
    END IF;
    IF now_at >= assignment_row.expires_at
       OR assignment_row.duty_grant_id <> authority_row.duty_grant_id
       OR assignment_row.duty_grant_version
            <> authority_row.duty_grant_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_assignment_expired',
            MESSAGE = 'Finance funding assignment is unavailable';
    END IF;
    IF EXISTS (
        SELECT 1 FROM demand.manual_funding_confirmations AS confirmation
        WHERE confirmation.funding_review_id = review_row.id
          AND confirmation.actor_user_id = exact_actor_user_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'finance_funding_confirmation_duplicate',
            MESSAGE = 'Finance funding operator already confirmed';
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
        exact_payload_hash_key_id, 'demand-command-json-v1', exact_payload_hash,
        expected_review_revision, 'IN_PROGRESS', now_at + interval '7 days',
        now_at
    );

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
    WHERE id = assignment_row.id
      AND actor_user_id = exact_actor_user_id;

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
        SET status = 'SECURED',
            aggregate_version = next_review_revision,
            completed_at = now_at
        WHERE id = review_row.id;
        UPDATE demand.demands
        SET status = 'FUNDED',
            aggregate_version = next_demand_revision,
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
            'assignment_status', 'COMPLETED',
            'confirmation_by_me', true,
            'available_actions', '[]'::jsonb,
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
        'COMPLETED'::text,
        true,
        ARRAY[]::text[],
        false,
        false;
END
$function$;

CREATE FUNCTION demand_api.release_manual_funding_review_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_funding_review_id uuid,
    expected_review_revision bigint,
    expected_principal_marker_sha256 bytea,
    exact_reason_code text,
    new_release_id uuid,
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
    assignment_status text,
    confirmation_by_me boolean,
    available_actions text[],
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
    root_row demand.demands%ROWTYPE;
    assignment_row demand.manual_funding_review_assignments%ROWTYPE;
    authority_row record;
    receipt_row demand.manual_funding_receipts%ROWTYPE;
    confirmation_total bigint;
    next_review_revision bigint;
    next_demand_revision bigint;
    result_etag text;
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_funding_review_id IS NULL
       OR exact_funding_review_id = zero_uuid
       OR expected_review_revision IS NULL OR expected_review_revision < 1
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR exact_reason_code NOT IN (
            'CONFLICT_DECLARED', 'WORKLOAD_RELEASE'
       )
       OR new_release_id IS NULL OR new_release_id = zero_uuid
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
            IS DISTINCT FROM 'RELEASE_FUNDING_REVIEW_ASSIGNMENT'
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
    WHERE review.id = exact_funding_review_id;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(review_row.demand_id::text, 104729)
    );
    SELECT * INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config(
        'app.organization_id', review_row.organization_id::text, true
    );
    PERFORM set_config('app.demand_id', review_row.demand_id::text, true);

    SELECT * INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = review_row.organization_id
      AND root.id = review_row.demand_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO receipt_row
    FROM demand.manual_funding_receipts AS receipt
    WHERE receipt.receipt_id = new_receipt_id
    FOR UPDATE;
    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.principal_id = exact_actor_user_id
          AND receipt.command_name
                = 'ReleaseManualFundingReviewAssignment'
          AND receipt.command_version = 1
          AND receipt.idempotency_key_digest_key_id
                = exact_idempotency_key_digest_key_id
          AND receipt.idempotency_key_digest = exact_idempotency_key_digest
        FOR UPDATE;
    END IF;
    IF FOUND THEN
        SELECT * INTO assignment_row
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.id::text
            = receipt_row.safe_response_body->>'assignment_id'
          AND assignment.funding_review_id = review_row.id
          AND assignment.actor_user_id = exact_actor_user_id;
    ELSE
        SELECT * INTO assignment_row
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.funding_review_id = review_row.id
          AND assignment.actor_user_id = exact_actor_user_id
          AND assignment.status = 'ACTIVE'
        FOR UPDATE;
    END IF;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('app.assignment_id', assignment_row.id::text, true);

    BEGIN
        SELECT * INTO STRICT authority_row
        FROM iam_api.lock_finance_funding_authority_v2(
            exact_actor_user_id,
            exact_session_id,
            review_row.organization_id,
            review_row.demand_id,
            review_row.id,
            assignment_row.id,
            'RELEASE_FUNDING_REVIEW_ASSIGNMENT',
            expected_principal_marker_sha256
        );
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

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

    IF receipt_row.receipt_id IS NOT NULL THEN
        IF receipt_row.principal_id <> exact_actor_user_id
           OR receipt_row.command_name
                <> 'ReleaseManualFundingReviewAssignment'
           OR receipt_row.command_version <> 1
           OR receipt_row.idempotency_key_digest_key_id
                <> exact_idempotency_key_digest_key_id
           OR receipt_row.idempotency_key_digest
                <> exact_idempotency_key_digest
           OR receipt_row.canonicalization_version
                <> 'demand-command-json-v1'
           OR receipt_row.organization_id
                IS DISTINCT FROM review_row.organization_id
           OR receipt_row.demand_id
                IS DISTINCT FROM review_row.demand_id
           OR receipt_row.funding_review_id <> exact_funding_review_id
           OR receipt_row.expected_review_revision
                IS DISTINCT FROM expected_review_revision
           OR receipt_row.payload_hash_key_id <> exact_payload_hash_key_id
           OR receipt_row.payload_hash <> exact_payload_hash
           OR receipt_row.safe_response_body->>'assignment_id'
                <> assignment_row.id::text THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'finance_funding_idempotency_reused',
                MESSAGE = 'Finance funding release idempotency conflict';
        END IF;
        IF receipt_row.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'finance_funding_receipt_incomplete',
                MESSAGE = 'Finance funding release receipt is incomplete';
        END IF;
        PERFORM set_config('app.receipt_replayed', 'true', true);
        PERFORM set_config('app.receipt_id', receipt_row.receipt_id::text, true);
        RETURN QUERY SELECT
            receipt_row.funding_review_id,
            receipt_row.demand_id,
            (receipt_row.safe_response_body->>'demand_version_id')::uuid,
            receipt_row.safe_response_body->>'status',
            (receipt_row.safe_response_body->>'review_revision')::bigint,
            assignment_row.id,
            (receipt_row.safe_response_body->>'assignment_expires_at')::timestamptz,
            decode(receipt_row.safe_response_body->>'target_sha256', 'hex'),
            decode(
                receipt_row.safe_response_body->>'evidence_reference_sha256',
                'hex'
            ),
            (receipt_row.safe_response_body->>'confirmation_count')::bigint,
            receipt_row.safe_response_body->>'assignment_status',
            (receipt_row.safe_response_body->>'confirmation_by_me')::boolean,
            ARRAY[]::text[],
            false,
            true;
        RETURN;
    END IF;

    IF review_row.aggregate_version <> expected_review_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            CONSTRAINT = 'finance_funding_precondition_failed',
            MESSAGE = 'Finance funding release precondition failed';
    END IF;
    IF review_row.status <> 'PENDING'
       OR root_row.status <> 'FUNDING_PENDING'
       OR root_row.current_version_id <> review_row.demand_version_id
       OR now_at >= root_row.expires_at
       OR assignment_row.status <> 'ACTIVE'
       OR now_at >= assignment_row.expires_at
       OR assignment_row.duty_grant_id <> authority_row.duty_grant_id
       OR assignment_row.duty_grant_version
            <> authority_row.duty_grant_version
       OR EXISTS (
            SELECT 1 FROM demand.manual_funding_confirmations AS confirmation
            WHERE confirmation.assignment_id = assignment_row.id
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_assignment_not_releasable',
            MESSAGE = 'Finance funding assignment cannot be released';
    END IF;

    INSERT INTO demand.manual_funding_receipts (
        receipt_id, principal_id, organization_id, demand_id,
        funding_review_id, command_name, command_version,
        idempotency_key_digest_key_id, idempotency_key_digest,
        payload_hash_key_id, canonicalization_version, payload_hash,
        expected_review_revision, status, retain_until, created_at
    ) VALUES (
        new_receipt_id, exact_actor_user_id, review_row.organization_id,
        review_row.demand_id, review_row.id,
        'ReleaseManualFundingReviewAssignment', 1,
        exact_idempotency_key_digest_key_id, exact_idempotency_key_digest,
        exact_payload_hash_key_id, 'demand-command-json-v1', exact_payload_hash,
        expected_review_revision, 'IN_PROGRESS', now_at + interval '7 days',
        now_at
    );

    INSERT INTO demand.manual_funding_assignment_releases (
        id, organization_id, demand_id, funding_review_id, assignment_id,
        actor_user_id, reason_code, authority_marker_sha256, released_at
    ) VALUES (
        new_release_id, assignment_row.organization_id,
        assignment_row.demand_id, assignment_row.funding_review_id,
        assignment_row.id, assignment_row.actor_user_id, exact_reason_code,
        authority_row.authority_marker_sha256, now_at
    );
    UPDATE demand.manual_funding_review_assignments
    SET status = 'RELEASED',
        aggregate_version = aggregate_version + 1,
        completed_at = now_at
    WHERE id = assignment_row.id
      AND actor_user_id = exact_actor_user_id;

    SELECT count(*) INTO confirmation_total
    FROM demand.manual_funding_confirmations AS confirmation
    WHERE confirmation.funding_review_id = review_row.id;
    next_review_revision := review_row.aggregate_version + 1;
    next_demand_revision := root_row.aggregate_version + 1;
    UPDATE demand.manual_funding_review_cases
    SET aggregate_version = next_review_revision
    WHERE id = review_row.id;
    UPDATE demand.demands
    SET aggregate_version = next_demand_revision,
        updated_at = now_at
    WHERE id = review_row.demand_id;

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id,
        before_status, after_status, before_version, after_version,
        role_code, purpose_code, reason_code, auth_strength_code,
        result_code, command_id, correlation_id, causation_id, trace_id,
        safe_attributes
    ) VALUES (
        new_audit_event_id, now_at, 'USER', exact_actor_user_id, NULL,
        'RELEASE_MANUAL_FUNDING_REVIEW_ASSIGNMENT', 'Demand',
        review_row.demand_id, review_row.organization_id,
        root_row.status, 'FUNDING_PENDING', root_row.aggregate_version,
        next_demand_revision, 'FINANCE_OPERATOR',
        'MANUAL_FUNDING_REVIEW', exact_reason_code, NULL, 'SUCCEEDED',
        new_receipt_id, exact_correlation_id, exact_causation_id,
        exact_trace_id,
        jsonb_build_object(
            'funding_review_id', review_row.id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'assignment_status', 'RELEASED',
            'synthetic', true
        )
    );
    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at, aggregate_type,
        aggregate_id, aggregate_version, actor_kind, actor_id,
        original_actor_id, correlation_id, causation_id, trace_id,
        organization_id, payload, delivery_status, attempt_count,
        available_at, created_at
    ) VALUES (
        new_outbox_event_id, 'DemandFundingReviewAssignmentReleased', 1,
        now_at, 'Demand', review_row.demand_id, next_demand_revision,
        'USER', exact_actor_user_id, NULL, exact_correlation_id,
        exact_causation_id, exact_trace_id, review_row.organization_id,
        jsonb_build_object(
            'demand_id', review_row.demand_id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'funding_requirement_id', review_row.id::text,
            'reason_code', exact_reason_code,
            'status', 'FUNDING_PENDING'
        ),
        'PENDING', 0, now_at, now_at
    );

    result_etag := '"funding-review-' || next_review_revision::text || '"';
    UPDATE demand.manual_funding_receipts
    SET status = 'COMPLETED',
        safe_response_body = jsonb_build_object(
            'demand_version_id', review_row.demand_version_id::text,
            'status', 'PENDING',
            'review_revision', next_review_revision,
            'assignment_id', assignment_row.id::text,
            'assignment_expires_at',
                to_char(assignment_row.expires_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'target_sha256', encode(review_row.target_sha256, 'hex'),
            'evidence_reference_sha256',
                encode(review_row.evidence_reference_sha256, 'hex'),
            'confirmation_count', confirmation_total,
            'assignment_status', 'RELEASED',
            'confirmation_by_me', false,
            'available_actions', '[]'::jsonb,
            'can_confirm', false
        ),
        response_entity_tag = result_etag,
        result_event_type = 'DemandFundingReviewAssignmentReleased',
        completed_at = now_at
    WHERE receipt_id = new_receipt_id;

    RETURN QUERY SELECT
        review_row.id, review_row.demand_id, review_row.demand_version_id,
        'PENDING'::text, next_review_revision, assignment_row.id,
        assignment_row.expires_at, review_row.target_sha256,
        review_row.evidence_reference_sha256, confirmation_total,
        'RELEASED'::text, false, ARRAY[]::text[], false, false;
END
$function$;

CREATE FUNCTION demand_api.submit_manual_funding_review_finding_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_funding_review_id uuid,
    expected_review_revision bigint,
    expected_principal_marker_sha256 bytea,
    exact_disposition text,
    exact_reason_codes text[],
    exact_required_field_codes text[],
    new_finding_id uuid,
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
    assignment_status text,
    confirmation_by_me boolean,
    available_actions text[],
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
    root_row demand.demands%ROWTYPE;
    assignment_row demand.manual_funding_review_assignments%ROWTYPE;
    authority_row record;
    receipt_row demand.manual_funding_receipts%ROWTYPE;
    confirmation_total bigint;
    revoked_peer_count integer := 0;
    next_review_revision bigint;
    next_demand_revision bigint;
    next_demand_status text;
    result_etag text;
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_funding_review_id IS NULL
       OR exact_funding_review_id = zero_uuid
       OR expected_review_revision IS NULL OR expected_review_revision < 1
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR exact_disposition NOT IN ('DISCREPANCY', 'REJECTED')
       OR NOT demand.text_array_is_sorted_unique_v1(exact_reason_codes)
       OR NOT demand.text_array_is_sorted_unique_v1(
            exact_required_field_codes
       )
       OR cardinality(exact_reason_codes) NOT BETWEEN 1 AND 3
       OR cardinality(exact_required_field_codes) NOT BETWEEN 1 AND 4
       OR exact_required_field_codes <@ ARRAY[
            'BUDGET', 'DECLARATIONS', 'RISK', 'SCOPE'
       ]::text[] IS NOT TRUE
       OR (
            exact_disposition = 'DISCREPANCY'
            AND exact_reason_codes <@ ARRAY[
                'EVIDENCE_REFERENCE_MISMATCH',
                'TARGET_CONTENT_MISMATCH'
            ]::text[] IS NOT TRUE
       )
       OR (
            exact_disposition = 'REJECTED'
            AND exact_reason_codes <@ ARRAY[
                'BUDGET_PLAN_UNACCEPTABLE',
                'DECLARATION_CONFLICT',
                'SYNTHETIC_SCOPE_VIOLATION'
            ]::text[] IS NOT TRUE
       )
       OR new_finding_id IS NULL OR new_finding_id = zero_uuid
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
            IS DISTINCT FROM 'SUBMIT_FUNDING_REVIEW_FINDING'
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
    WHERE review.id = exact_funding_review_id;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(review_row.demand_id::text, 104729)
    );
    SELECT * INTO review_row
    FROM demand.manual_funding_review_cases AS review
    WHERE review.id = exact_funding_review_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config(
        'app.organization_id', review_row.organization_id::text, true
    );
    PERFORM set_config('app.demand_id', review_row.demand_id::text, true);

    SELECT * INTO root_row
    FROM demand.demands AS root
    WHERE root.organization_id = review_row.organization_id
      AND root.id = review_row.demand_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO receipt_row
    FROM demand.manual_funding_receipts AS receipt
    WHERE receipt.receipt_id = new_receipt_id
    FOR UPDATE;
    IF NOT FOUND THEN
        SELECT * INTO receipt_row
        FROM demand.manual_funding_receipts AS receipt
        WHERE receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = 'SubmitManualFundingReviewFinding'
          AND receipt.command_version = 1
          AND receipt.idempotency_key_digest_key_id
                = exact_idempotency_key_digest_key_id
          AND receipt.idempotency_key_digest = exact_idempotency_key_digest
        FOR UPDATE;
    END IF;
    IF FOUND THEN
        SELECT * INTO assignment_row
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.id::text
            = receipt_row.safe_response_body->>'assignment_id'
          AND assignment.funding_review_id = review_row.id
          AND assignment.actor_user_id = exact_actor_user_id;
    ELSE
        SELECT * INTO assignment_row
        FROM demand.manual_funding_review_assignments AS assignment
        WHERE assignment.funding_review_id = review_row.id
          AND assignment.actor_user_id = exact_actor_user_id
          AND assignment.status = 'ACTIVE'
        FOR UPDATE;
    END IF;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('app.assignment_id', assignment_row.id::text, true);

    BEGIN
        SELECT * INTO STRICT authority_row
        FROM iam_api.lock_finance_funding_authority_v2(
            exact_actor_user_id,
            exact_session_id,
            review_row.organization_id,
            review_row.demand_id,
            review_row.id,
            assignment_row.id,
            'SUBMIT_FUNDING_REVIEW_FINDING',
            expected_principal_marker_sha256
        );
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;

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

    IF receipt_row.receipt_id IS NOT NULL THEN
        IF receipt_row.principal_id <> exact_actor_user_id
           OR receipt_row.command_name
                <> 'SubmitManualFundingReviewFinding'
           OR receipt_row.command_version <> 1
           OR receipt_row.idempotency_key_digest_key_id
                <> exact_idempotency_key_digest_key_id
           OR receipt_row.idempotency_key_digest
                <> exact_idempotency_key_digest
           OR receipt_row.canonicalization_version
                <> 'demand-command-json-v1'
           OR receipt_row.organization_id
                IS DISTINCT FROM review_row.organization_id
           OR receipt_row.demand_id
                IS DISTINCT FROM review_row.demand_id
           OR receipt_row.funding_review_id <> exact_funding_review_id
           OR receipt_row.expected_review_revision
                IS DISTINCT FROM expected_review_revision
           OR receipt_row.payload_hash_key_id <> exact_payload_hash_key_id
           OR receipt_row.payload_hash <> exact_payload_hash
           OR receipt_row.safe_response_body->>'assignment_id'
                <> assignment_row.id::text THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'finance_funding_idempotency_reused',
                MESSAGE = 'Finance funding finding idempotency conflict';
        END IF;
        IF receipt_row.status <> 'COMPLETED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'finance_funding_receipt_incomplete',
                MESSAGE = 'Finance funding finding receipt is incomplete';
        END IF;
        PERFORM set_config('app.receipt_replayed', 'true', true);
        PERFORM set_config('app.receipt_id', receipt_row.receipt_id::text, true);
        RETURN QUERY SELECT
            receipt_row.funding_review_id,
            receipt_row.demand_id,
            (receipt_row.safe_response_body->>'demand_version_id')::uuid,
            receipt_row.safe_response_body->>'status',
            (receipt_row.safe_response_body->>'review_revision')::bigint,
            assignment_row.id,
            (receipt_row.safe_response_body->>'assignment_expires_at')::timestamptz,
            decode(receipt_row.safe_response_body->>'target_sha256', 'hex'),
            decode(
                receipt_row.safe_response_body->>'evidence_reference_sha256',
                'hex'
            ),
            (receipt_row.safe_response_body->>'confirmation_count')::bigint,
            'COMPLETED'::text,
            false,
            ARRAY[]::text[],
            false,
            true;
        RETURN;
    END IF;

    IF review_row.aggregate_version <> expected_review_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            CONSTRAINT = 'finance_funding_precondition_failed',
            MESSAGE = 'Finance funding finding precondition failed';
    END IF;
    IF review_row.status <> 'PENDING'
       OR root_row.status <> 'FUNDING_PENDING'
       OR root_row.current_version_id <> review_row.demand_version_id
       OR now_at >= root_row.expires_at
       OR assignment_row.status <> 'ACTIVE'
       OR now_at >= assignment_row.expires_at
       OR assignment_row.duty_grant_id <> authority_row.duty_grant_id
       OR assignment_row.duty_grant_version
            <> authority_row.duty_grant_version
       OR EXISTS (
            SELECT 1 FROM demand.manual_funding_confirmations AS confirmation
            WHERE confirmation.assignment_id = assignment_row.id
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_finding_not_submittable',
            MESSAGE = 'Finance funding finding cannot be submitted';
    END IF;

    INSERT INTO demand.manual_funding_receipts (
        receipt_id, principal_id, organization_id, demand_id,
        funding_review_id, command_name, command_version,
        idempotency_key_digest_key_id, idempotency_key_digest,
        payload_hash_key_id, canonicalization_version, payload_hash,
        expected_review_revision, status, retain_until, created_at
    ) VALUES (
        new_receipt_id, exact_actor_user_id, review_row.organization_id,
        review_row.demand_id, review_row.id,
        'SubmitManualFundingReviewFinding', 1,
        exact_idempotency_key_digest_key_id, exact_idempotency_key_digest,
        exact_payload_hash_key_id, 'demand-command-json-v1', exact_payload_hash,
        expected_review_revision, 'IN_PROGRESS', now_at + interval '7 days',
        now_at
    );

    INSERT INTO demand.manual_funding_findings (
        id, organization_id, demand_id, demand_version_id,
        funding_review_id, assignment_id, actor_user_id, disposition,
        reason_codes, required_field_codes, target_sha256,
        evidence_reference_sha256, authority_marker_sha256, created_at
    ) VALUES (
        new_finding_id, assignment_row.organization_id,
        assignment_row.demand_id, review_row.demand_version_id,
        assignment_row.funding_review_id, assignment_row.id,
        assignment_row.actor_user_id, exact_disposition,
        exact_reason_codes, exact_required_field_codes,
        review_row.target_sha256, review_row.evidence_reference_sha256,
        authority_row.authority_marker_sha256, now_at
    );
    UPDATE demand.manual_funding_review_assignments
    SET status = 'COMPLETED',
        aggregate_version = aggregate_version + 1,
        completed_at = now_at
    WHERE id = assignment_row.id
      AND actor_user_id = exact_actor_user_id;
    UPDATE demand.manual_funding_review_assignments AS assignment
    SET status = 'REVOKED',
        aggregate_version = aggregate_version + 1,
        completed_at = now_at
    WHERE assignment.funding_review_id = review_row.id
      AND assignment.id <> assignment_row.id
      AND assignment.status = 'ACTIVE';
    GET DIAGNOSTICS revoked_peer_count = ROW_COUNT;

    SELECT count(*) INTO confirmation_total
    FROM demand.manual_funding_confirmations AS confirmation
    WHERE confirmation.funding_review_id = review_row.id;
    IF confirmation_total NOT IN (0, 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'finance_funding_state_conflict',
            MESSAGE = 'Finance funding finding confirmation count is invalid';
    END IF;

    next_review_revision := review_row.aggregate_version + 1;
    next_demand_revision := root_row.aggregate_version + 1;
    next_demand_status := CASE
        WHEN exact_disposition = 'DISCREPANCY' THEN 'VERIFIED'
        ELSE 'NEEDS_CHANGES'
    END;
    UPDATE demand.manual_funding_review_cases
    SET status = exact_disposition,
        aggregate_version = next_review_revision,
        completed_at = now_at
    WHERE id = review_row.id;
    IF exact_disposition = 'DISCREPANCY' THEN
        UPDATE demand.demands
        SET status = 'VERIFIED',
            aggregate_version = next_demand_revision,
            updated_at = now_at
        WHERE id = review_row.demand_id;
    ELSE
        -- current_review_id is intentionally preserved so the previous
        -- operations-review context remains available to the Demand Owner.
        UPDATE demand.demands
        SET status = 'NEEDS_CHANGES',
            aggregate_version = next_demand_revision,
            verified_version_id = NULL,
            updated_at = now_at
        WHERE id = review_row.demand_id;
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
        'SUBMIT_MANUAL_FUNDING_REVIEW_FINDING', 'Demand',
        review_row.demand_id, review_row.organization_id,
        root_row.status, next_demand_status, root_row.aggregate_version,
        next_demand_revision, 'FINANCE_OPERATOR',
        'MANUAL_FUNDING_REVIEW', exact_reason_codes[1], NULL, 'SUCCEEDED',
        new_receipt_id, exact_correlation_id, exact_causation_id,
        exact_trace_id,
        jsonb_build_object(
            'funding_review_id', review_row.id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'disposition', exact_disposition,
            'reason_codes', exact_reason_codes,
            'required_field_codes', exact_required_field_codes,
            'revoked_peer_assignment_count', revoked_peer_count,
            'synthetic', true
        )
    );
    INSERT INTO infra.outbox_events (
        event_id, event_type, schema_version, occurred_at, aggregate_type,
        aggregate_id, aggregate_version, actor_kind, actor_id,
        original_actor_id, correlation_id, causation_id, trace_id,
        organization_id, payload, delivery_status, attempt_count,
        available_at, created_at
    ) VALUES (
        new_outbox_event_id, 'DemandFundingReviewFindingSubmitted', 1,
        now_at, 'Demand', review_row.demand_id, next_demand_revision,
        'USER', exact_actor_user_id, NULL, exact_correlation_id,
        exact_causation_id, exact_trace_id, review_row.organization_id,
        jsonb_build_object(
            'demand_id', review_row.demand_id::text,
            'demand_version_id', review_row.demand_version_id::text,
            'funding_requirement_id', review_row.id::text,
            'disposition', exact_disposition,
            'reason_codes', exact_reason_codes,
            'required_field_codes', exact_required_field_codes,
            'revoked_peer_assignment_count', revoked_peer_count,
            'status', next_demand_status
        ),
        'PENDING', 0, now_at, now_at
    );

    result_etag := '"funding-review-' || next_review_revision::text || '"';
    UPDATE demand.manual_funding_receipts
    SET status = 'COMPLETED',
        safe_response_body = jsonb_build_object(
            'demand_version_id', review_row.demand_version_id::text,
            'status', exact_disposition,
            'review_revision', next_review_revision,
            'assignment_id', assignment_row.id::text,
            'assignment_expires_at',
                to_char(assignment_row.expires_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'target_sha256', encode(review_row.target_sha256, 'hex'),
            'evidence_reference_sha256',
                encode(review_row.evidence_reference_sha256, 'hex'),
            'confirmation_count', confirmation_total,
            'assignment_status', 'COMPLETED',
            'confirmation_by_me', false,
            'available_actions', '[]'::jsonb,
            'can_confirm', false
        ),
        response_entity_tag = result_etag,
        result_event_type = 'DemandFundingReviewFindingSubmitted',
        completed_at = now_at
    WHERE receipt_id = new_receipt_id;

    RETURN QUERY SELECT
        review_row.id, review_row.demand_id, review_row.demand_version_id,
        exact_disposition, next_review_revision, assignment_row.id,
        assignment_row.expires_at, review_row.target_sha256,
        review_row.evidence_reference_sha256, confirmation_total,
        'COMPLETED'::text, false, ARRAY[]::text[], false, false;
END
$function$;

ALTER FUNCTION demand_api.list_manual_funding_reviews_v2(
    uuid, uuid, bytea, integer
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.get_manual_funding_review_v2(
    uuid, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.read_demand_owner_findings_v2(
    uuid, uuid, uuid, uuid, text, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.read_manual_funding_evidence_v2(
    uuid, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.claim_manual_funding_review_v2(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.confirm_manual_funding_review_v2(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.release_manual_funding_review_assignment_v1(
    uuid, uuid, uuid, bigint, bytea, text, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.submit_manual_funding_review_finding_v1(
    uuid, uuid, uuid, bigint, bytea, text, text[], text[], uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid
) OWNER TO demand_schema_owner;

REVOKE ALL ON FUNCTION demand_api.list_manual_funding_reviews_v2(
    uuid, uuid, bytea, integer
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.get_manual_funding_review_v2(
    uuid, uuid, uuid, bytea
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.read_manual_funding_evidence_v2(
    uuid, uuid, uuid, bytea
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.claim_manual_funding_review_v2(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.confirm_manual_funding_review_v2(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.release_manual_funding_review_assignment_v1(
    uuid, uuid, uuid, bigint, bytea, text, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.submit_manual_funding_review_finding_v1(
    uuid, uuid, uuid, bigint, bytea, text, text[], text[], uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC, demand_self, demand_review;
REVOKE ALL ON FUNCTION demand_api.read_demand_owner_findings_v2(
    uuid, uuid, uuid, uuid, text, bytea
) FROM PUBLIC, demand_review, demand_finance;

-- Preserve v1 objects for migration-ledger forensics, but remove head10
-- runtime access to their single-cycle and pre-release semantics.
REVOKE EXECUTE ON FUNCTION demand_api.list_manual_funding_reviews_v1(
    uuid, uuid, bytea, integer
) FROM demand_finance;
REVOKE EXECUTE ON FUNCTION demand_api.get_manual_funding_review_v1(
    uuid, uuid, uuid, bytea
) FROM demand_finance;
REVOKE EXECUTE ON FUNCTION demand_api.claim_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) FROM demand_finance;
REVOKE EXECUTE ON FUNCTION demand_api.confirm_manual_funding_review_v1(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM demand_finance;
REVOKE EXECUTE ON FUNCTION demand_api.read_manual_funding_evidence_v1(
    uuid, uuid, uuid, bytea
) FROM demand_finance;
REVOKE EXECUTE ON FUNCTION demand_api.read_demand_owner_findings_v1(
    uuid, uuid, uuid, uuid, text, bytea
) FROM demand_self;

GRANT EXECUTE ON FUNCTION demand_api.list_manual_funding_reviews_v2(
    uuid, uuid, bytea, integer
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.get_manual_funding_review_v2(
    uuid, uuid, uuid, bytea
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.read_manual_funding_evidence_v2(
    uuid, uuid, uuid, bytea
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.claim_manual_funding_review_v2(
    uuid, uuid, uuid, bigint, bigint, bytea, uuid, uuid, uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid, text, text, bigint
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.confirm_manual_funding_review_v2(
    uuid, uuid, uuid, bigint, bytea, text[], uuid, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.release_manual_funding_review_assignment_v1(
    uuid, uuid, uuid, bigint, bytea, text, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.submit_manual_funding_review_finding_v1(
    uuid, uuid, uuid, bigint, bytea, text, text[], text[], uuid, uuid,
    text, bytea, text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_finance;
GRANT EXECUTE ON FUNCTION demand_api.read_demand_owner_findings_v2(
    uuid, uuid, uuid, uuid, text, bytea
) TO demand_self;

SET LOCAL ROLE schema_owner;

CREATE POLICY rls_finance_funding_resolution_audit_definer
ON audit.audit_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND actor_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND target_kind = 'Demand'
    AND target_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND role_code = 'FINANCE_OPERATOR'
    AND purpose_code = 'MANUAL_FUNDING_REVIEW'
    AND (
        (NULLIF(current_setting('app.operation', true), '')
            = 'RELEASE_FUNDING_REVIEW_ASSIGNMENT'
         AND action_code = 'RELEASE_MANUAL_FUNDING_REVIEW_ASSIGNMENT')
        OR
        (NULLIF(current_setting('app.operation', true), '')
            = 'SUBMIT_FUNDING_REVIEW_FINDING'
         AND action_code = 'SUBMIT_MANUAL_FUNDING_REVIEW_FINDING')
    )
);

CREATE POLICY rls_finance_funding_resolution_outbox_definer
ON infra.outbox_events
FOR INSERT TO demand_schema_owner
WITH CHECK (
    session_user = 'demand_finance'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND actor_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND aggregate_type = 'Demand'
    AND aggregate_id::text
        = NULLIF(current_setting('app.demand_id', true), '')
    AND (
        (NULLIF(current_setting('app.operation', true), '')
            = 'RELEASE_FUNDING_REVIEW_ASSIGNMENT'
         AND event_type = 'DemandFundingReviewAssignmentReleased')
        OR
        (NULLIF(current_setting('app.operation', true), '')
            = 'SUBMIT_FUNDING_REVIEW_FINDING'
         AND event_type = 'DemandFundingReviewFindingSubmitted')
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
          'manual_funding_receipts',
          'manual_funding_assignment_releases',
          'manual_funding_findings'
      )
      AND (
          relation.relkind <> 'r'
          OR NOT relation.relrowsecurity
          OR NOT relation.relforcerowsecurity
      );
    IF invalid_count <> 0
       OR pg_catalog.has_table_privilege(
            'demand_finance',
            'demand.manual_funding_findings',
            'SELECT,INSERT,UPDATE,DELETE'
       )
       OR pg_catalog.has_table_privilege(
            'demand_self',
            'demand.manual_funding_findings',
            'SELECT,INSERT,UPDATE,DELETE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.release_manual_funding_review_assignment_v1(uuid,uuid,uuid,bigint,bytea,text,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.submit_manual_funding_review_finding_v1(uuid,uuid,uuid,bigint,bytea,text,text[],text[],uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.read_demand_owner_findings_v2(uuid,uuid,uuid,uuid,text,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.list_manual_funding_reviews_v1(uuid,uuid,bytea,integer)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.get_manual_funding_review_v1(uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.claim_manual_funding_review_v1(uuid,uuid,uuid,bigint,bigint,bytea,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,text,text,bigint)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.confirm_manual_funding_review_v1(uuid,uuid,uuid,bigint,bytea,text[],uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_finance',
            'demand_api.read_manual_funding_evidence_v1(uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_self',
            'demand_api.read_demand_owner_findings_v1(uuid,uuid,uuid,uuid,text,bytea)',
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
            WHERE procedure.oid IN (
                pg_catalog.to_regprocedure('demand_api.list_manual_funding_reviews_v2(uuid,uuid,bytea,integer)'),
                pg_catalog.to_regprocedure('demand_api.get_manual_funding_review_v2(uuid,uuid,uuid,bytea)'),
                pg_catalog.to_regprocedure('demand_api.read_manual_funding_evidence_v2(uuid,uuid,uuid,bytea)'),
                pg_catalog.to_regprocedure('demand_api.claim_manual_funding_review_v2(uuid,uuid,uuid,bigint,bigint,bytea,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,text,text,bigint)'),
                pg_catalog.to_regprocedure('demand_api.confirm_manual_funding_review_v2(uuid,uuid,uuid,bigint,bytea,text[],uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)'),
                pg_catalog.to_regprocedure('demand_api.release_manual_funding_review_assignment_v1(uuid,uuid,uuid,bigint,bytea,text,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)'),
                pg_catalog.to_regprocedure('demand_api.submit_manual_funding_review_finding_v1(uuid,uuid,uuid,bigint,bytea,text,text[],text[],uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)'),
                pg_catalog.to_regprocedure('demand_api.read_demand_owner_findings_v2(uuid,uuid,uuid,uuid,text,bytea)')
            )
              AND privilege.grantee = 0
              AND privilege.privilege_type = 'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand10 Finance funding resolution assertion failed';
    END IF;
END
$assert$;
