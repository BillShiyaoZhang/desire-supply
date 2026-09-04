-- Completion validates the immutable USER receipt that authorized this exact
-- selection. Its operation differs from the coordinator's current operation.
-- Read only that linked receipt; do not grant runtime table access or updates.
CREATE POLICY rls_matching_completion_intent_receipt_definer_v1
ON matching.command_receipts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_coordinator'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'MATCHING_COORDINATOR'
    AND NULLIF(current_setting('app.operation', true), '') = 'COMPLETE_SELECTION'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND principal_kind = 'USER'
    AND status = 'COMPLETED'
    AND target_kind = 'Selection'
    AND target_id = NULLIF(current_setting('app.selection_id', true), '')::uuid
    AND EXISTS (
        SELECT 1 FROM matching.selections AS selection
        WHERE selection.id = command_receipts.target_id
          AND selection.organization_id = command_receipts.organization_id
          AND selection.coordinator_workload_id = NULLIF(
              current_setting('app.workload_id', true), ''
          )::uuid
          AND selection.coordinator_authority_marker_sha256 = pg_catalog.decode(
              NULLIF(current_setting('app.authority_marker_sha256', true), ''), 'hex'
          )
          AND (
              (
                  command_receipts.operation = 'CHOOSE_CREATOR'
                  AND EXISTS (
                      SELECT 1 FROM matching.selection_intents AS intent
                      WHERE intent.selection_id = selection.id
                        AND intent.organization_id = selection.organization_id
                        AND intent.receipt_id = command_receipts.id
                        AND intent.actor_user_id = command_receipts.principal_id
                        AND intent.candidate_selector_authority_marker_sha256
                            = command_receipts.principal_authority_marker_sha256
                  )
              )
              OR (
                  command_receipts.operation = 'CLOSE_SELECTION'
                  AND EXISTS (
                      SELECT 1 FROM matching.selection_close_intents AS intent
                      WHERE intent.selection_id = selection.id
                        AND intent.organization_id = selection.organization_id
                        AND intent.receipt_id = command_receipts.id
                        AND intent.actor_user_id = command_receipts.principal_id
                        AND intent.candidate_selector_authority_marker_sha256
                            = command_receipts.principal_authority_marker_sha256
                  )
              )
          )
    )
);
