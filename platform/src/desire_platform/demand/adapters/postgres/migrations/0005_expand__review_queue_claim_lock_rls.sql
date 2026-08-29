-- Permit the fixed review-claim definer to lock exactly one Demand graph.
-- PostgreSQL row-locking SELECTs evaluate UPDATE RLS in addition to SELECT
-- RLS. 0003 intentionally supplied only queue-read policies for these rows.

CREATE POLICY rls_review_queue_root_lock_definer
ON demand.demands
FOR UPDATE TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_REVIEW'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_REVIEW'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
);

CREATE POLICY rls_review_queue_submission_lock_definer
ON demand.demand_submissions
FOR UPDATE TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_REVIEW'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_REVIEW'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
);

CREATE POLICY rls_review_queue_version_lock_definer
ON demand.demand_versions
FOR UPDATE TO demand_schema_owner
USING (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_REVIEW'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
)
WITH CHECK (
    session_user = 'demand_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'DEMAND_REVIEW'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_REVIEW'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
    AND organization_id::text = NULLIF(
        current_setting('app.organization_id', true), ''
    )
    AND demand_id::text = NULLIF(
        current_setting('app.demand_id', true), ''
    )
);

DO $assert$
DECLARE
    policy_count integer;
BEGIN
    SELECT count(*) INTO policy_count
    FROM pg_catalog.pg_policies AS policy
    WHERE policy.schemaname = 'demand'
      AND policy.policyname IN (
          'rls_review_queue_root_lock_definer',
          'rls_review_queue_submission_lock_definer',
          'rls_review_queue_version_lock_definer'
      )
      AND policy.cmd = 'UPDATE'
      AND policy.roles = ARRAY['demand_schema_owner']::name[];

    IF policy_count <> 3 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand review queue claim-lock RLS assertion failed';
    END IF;
END
$assert$;
