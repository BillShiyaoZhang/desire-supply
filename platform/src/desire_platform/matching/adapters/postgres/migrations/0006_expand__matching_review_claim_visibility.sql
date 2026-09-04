-- Make the existing fixed reviewer-claim procedure see and lock its queue.
-- Matching1-5 remain byte exact. Runtime roles retain no direct table access.
-- Lock policies reject every new row image; claim still derives its target,
-- validates exact IAM reviewer authority, and returns only safe_assignment.

CREATE POLICY rls_matching_review_claim_attempt_lock_v1
ON matching.matching_attempts
FOR UPDATE TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REVIEW'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND status = 'OPEN'
)
WITH CHECK (false);

CREATE POLICY rls_matching_review_claim_run_lock_v1
ON matching.match_runs
FOR UPDATE TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REVIEW'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND status IN ('COMPLETED', 'FAILED')
    AND superseded_by_run_id IS NULL
)
WITH CHECK (false);

CREATE POLICY rls_matching_review_claim_result_v1
ON matching.match_run_results
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_review'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_REVIEW_CLAIM'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLAIM_MATCHING_REVIEW'
    AND COALESCE(current_setting('app.organization_id', true), '') = ''
    AND EXISTS (
        SELECT 1
        FROM matching.matching_attempts AS attempt
        JOIN matching.match_runs AS run
          ON run.id = attempt.current_match_run_id
         AND run.attempt_id = attempt.id
         AND run.organization_id = attempt.organization_id
        WHERE attempt.id = match_run_results.attempt_id
          AND attempt.organization_id = match_run_results.organization_id
          AND run.id = match_run_results.match_run_id
          AND attempt.status = 'OPEN'
          AND run.status = 'COMPLETED'
          AND run.superseded_by_run_id IS NULL
    )
);
