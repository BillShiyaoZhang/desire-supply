-- Fixed, role-bound Matching creator and candidate-selector runtime programs.

CREATE SCHEMA matching_api AUTHORIZATION matching_schema_owner;
REVOKE ALL ON SCHEMA matching_api FROM PUBLIC;
GRANT USAGE ON SCHEMA matching_api TO matching_creator, matching_selector;

CREATE TABLE matching.selection_intents (
    id uuid PRIMARY KEY,
    receipt_id uuid NOT NULL UNIQUE,
    command_id uuid NOT NULL UNIQUE,
    organization_id uuid NOT NULL,
    selection_id uuid NOT NULL UNIQUE,
    attempt_id uuid NOT NULL,
    match_run_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    candidate_selector_assignment_id uuid NOT NULL,
    candidate_selector_assignment_version bigint NOT NULL,
    candidate_selector_authority_marker_sha256 bytea NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    matching_request_id uuid NOT NULL,
    matching_request_version bigint NOT NULL,
    funding_id uuid NOT NULL,
    matching_rule_bundle_id uuid NOT NULL,
    input_set_sha256 bytea NOT NULL,
    ordered_result_sha256 bytea NOT NULL,
    candidate_result_sha256 bytea NOT NULL,
    current_invitation_set_sha256 bytea NOT NULL,
    selection_basis_code varchar(64) NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_hash bytea NOT NULL,
    status varchar(16) NOT NULL,
    invitation_status varchar(16) NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT uq_matching_intent_selection_reference UNIQUE (
        selection_id, id
    ),
    CONSTRAINT fk_matching_intent_receipt FOREIGN KEY (receipt_id)
        REFERENCES matching.command_receipts (id),
    CONSTRAINT fk_matching_intent_selection FOREIGN KEY (
        organization_id, selection_id
    ) REFERENCES matching.selections (organization_id, id),
    CONSTRAINT fk_matching_intent_attempt FOREIGN KEY (
        organization_id, attempt_id
    ) REFERENCES matching.matching_attempts (organization_id, id),
    CONSTRAINT fk_matching_intent_run FOREIGN KEY (
        attempt_id, match_run_id
    ) REFERENCES matching.match_runs (attempt_id, id),
    CONSTRAINT fk_matching_intent_invitation FOREIGN KEY (
        attempt_id, invitation_id, invitation_status
    ) REFERENCES matching.invitations (attempt_id, id, status)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_matching_intent_assignment FOREIGN KEY (
        selection_id, candidate_selector_assignment_id
    ) REFERENCES matching.candidate_selector_assignments (selection_id, id),
    CONSTRAINT ck_matching_intent_status CHECK (status = 'READY'),
    CONSTRAINT ck_matching_intent_shape CHECK (
        invitation_status = 'ACCEPTED'
        AND candidate_selector_assignment_version >= 1
        AND matching_request_version >= 1
        AND octet_length(candidate_selector_authority_marker_sha256) = 32
        AND octet_length(input_set_sha256) = 32
        AND octet_length(ordered_result_sha256) = 32
        AND octet_length(candidate_result_sha256) = 32
        AND octet_length(current_invitation_set_sha256) = 32
        AND octet_length(payload_hash) = 32
        AND length(selection_basis_code) BETWEEN 2 AND 64
    )
);

CREATE TRIGGER trg_matching_selection_intent_immutable
BEFORE UPDATE OR DELETE ON matching.selection_intents
FOR EACH ROW EXECUTE FUNCTION matching.reject_immutable_fact_mutation();

ALTER TABLE matching.selection_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE matching.selection_intents FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_matching_intent_definer
ON matching.selection_intents
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_selector', 'matching_coordinator')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'CANDIDATE_SELECTOR', 'MATCHING_COORDINATOR'
    )
)
WITH CHECK (
    session_user = 'matching_selector'
    AND actor_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND candidate_selector_assignment_id = NULLIF(
        current_setting('app.selector_assignment_id', true), ''
    )::uuid
    AND candidate_selector_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CHOOSE_CREATOR'
);

CREATE POLICY rls_matching_intent_creator_definer
ON matching.selection_intents
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_creator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'WITHDRAW_INVITATION'
);

CREATE POLICY rls_matching_attempt_runtime_definer
ON matching.matching_attempts
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_creator', 'matching_selector')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
)
WITH CHECK (
    session_user = 'matching_selector'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(current_setting('app.attempt_id', true), '')::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLOSE_SELECTION'
);

CREATE POLICY rls_matching_attempt_discovery_definer
ON matching.matching_attempts
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_selector'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND (
        NULLIF(current_setting('app.operation', true), '')
            = 'LIST_SELECTOR_ATTEMPTS'
        AND demand_id = NULLIF(
            current_setting('app.demand_id', true), ''
        )::uuid
        OR
        NULLIF(current_setting('app.operation', true), '')
            = 'READ_SELECTION_BY_ATTEMPT'
        AND id = NULLIF(
            current_setting('app.attempt_id', true), ''
        )::uuid
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND EXISTS (
        SELECT 1
        FROM matching.selections AS selection
        JOIN matching.candidate_selector_assignments AS assignment
          ON assignment.selection_id=selection.id
        WHERE selection.attempt_id=matching_attempts.id
          AND assignment.assignee_user_id=NULLIF(
              current_setting('app.actor_user_id', true), ''
          )::uuid
          AND assignment.authority_marker_sha256=pg_catalog.decode(
              NULLIF(
                  current_setting('app.authority_marker_sha256', true), ''
              ),'hex'
          )
          AND assignment.status='ACTIVE'
          AND assignment.expires_at>transaction_timestamp()
    )
);

CREATE POLICY rls_matching_run_runtime_definer
ON matching.match_runs
FOR SELECT TO matching_schema_owner
USING (
    session_user IN ('matching_creator', 'matching_selector')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND attempt_id = NULLIF(
        current_setting('app.attempt_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
);

CREATE POLICY rls_matching_invitation_runtime_definer
ON matching.invitations
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_creator', 'matching_selector')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND (
        attempt_id = NULLIF(
            current_setting('app.attempt_id', true), ''
        )::uuid
        OR (
            id = NULLIF(
                current_setting('app.invitation_id', true), ''
            )::uuid
            AND creator_user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
            )::uuid
            AND creator_authority_marker_sha256 = pg_catalog.decode(
                NULLIF(
                    current_setting('app.authority_marker_sha256', true), ''
                ),
                'hex'
            )
        )
    )
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
)
WITH CHECK (
    session_user = 'matching_creator'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND creator_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
    AND status IN ('ACCEPTED', 'DECLINED', 'WITHDRAWN')
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
);

CREATE POLICY rls_matching_candidate_runtime_definer
ON matching.match_candidates
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_selector'
    AND attempt_id = NULLIF(
        current_setting('app.attempt_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CHOOSE_CREATOR'
);

CREATE POLICY rls_matching_snapshot_runtime_definer
ON matching.invitation_disclosure_snapshots
FOR SELECT TO matching_schema_owner
USING (
    session_user IN ('matching_creator', 'matching_selector')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND attempt_id = NULLIF(
        current_setting('app.attempt_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
);

CREATE POLICY rls_matching_response_runtime_definer
ON matching.invitation_responses
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_creator'
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
)
WITH CHECK (
    session_user = 'matching_creator'
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
);

CREATE POLICY rls_matching_withdrawal_runtime_definer
ON matching.invitation_withdrawals
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_creator'
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
)
WITH CHECK (
    session_user = 'matching_creator'
    AND creator_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND invitation_id = NULLIF(
        current_setting('app.invitation_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'MATCHING_CREATOR'
);

CREATE POLICY rls_matching_selection_runtime_definer
ON matching.selections
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_creator', 'matching_selector')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
)
WITH CHECK (
    session_user IN ('matching_creator', 'matching_selector')
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
);

CREATE POLICY rls_matching_selection_discovery_definer
ON matching.selections
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_selector'
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'LIST_SELECTOR_ATTEMPTS','READ_SELECTION_BY_ATTEMPT'
    )
    AND EXISTS (
        SELECT 1
        FROM matching.candidate_selector_assignments AS assignment
        WHERE assignment.selection_id=selections.id
          AND assignment.assignee_user_id=NULLIF(
              current_setting('app.actor_user_id', true), ''
          )::uuid
          AND assignment.organization_id=selections.organization_id
          AND assignment.authority_marker_sha256=pg_catalog.decode(
              NULLIF(
                  current_setting('app.authority_marker_sha256', true), ''
              ),'hex'
          )
          AND assignment.status='ACTIVE'
          AND assignment.expires_at>transaction_timestamp()
    )
);

CREATE POLICY rls_matching_selector_assignment_runtime_definer
ON matching.candidate_selector_assignments
FOR ALL TO matching_schema_owner
USING (
    session_user = 'matching_selector'
    AND id = NULLIF(
        current_setting('app.selector_assignment_id', true), ''
    )::uuid
    AND assignee_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
)
WITH CHECK (
    session_user = 'matching_selector'
    AND id = NULLIF(
        current_setting('app.selector_assignment_id', true), ''
    )::uuid
    AND assignee_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND selection_id = NULLIF(
        current_setting('app.selection_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CLOSE_SELECTION'
);

CREATE POLICY rls_matching_selector_assignment_discovery_definer
ON matching.candidate_selector_assignments
FOR SELECT TO matching_schema_owner
USING (
    session_user = 'matching_selector'
    AND assignee_user_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'CANDIDATE_SELECTOR'
    AND (
        NULLIF(current_setting('app.operation', true), '') IN (
            'LIST_SELECTOR_ATTEMPTS','READ_SELECTION_BY_ATTEMPT'
        )
        AND status='ACTIVE'
        AND expires_at>transaction_timestamp()
        OR
        NULLIF(current_setting('app.operation', true), '')
            = 'READ_SELECTION_BY_ID'
        AND (
            status='ACTIVE' AND expires_at>transaction_timestamp()
            OR status='COMPLETED'
        )
    )
);

CREATE POLICY rls_matching_receipt_runtime_definer
ON matching.command_receipts
FOR ALL TO matching_schema_owner
USING (
    session_user IN ('matching_creator', 'matching_selector')
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND operation = NULLIF(
        current_setting('app.operation', true), ''
    )
    AND principal_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
)
WITH CHECK (
    session_user IN ('matching_creator', 'matching_selector')
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND operation = NULLIF(
        current_setting('app.operation', true), ''
    )
    AND principal_authority_marker_sha256 = pg_catalog.decode(
        NULLIF(current_setting('app.authority_marker_sha256', true), ''),
        'hex'
    )
);

SET LOCAL ROLE schema_owner;

GRANT USAGE ON SCHEMA audit, infra TO matching_schema_owner;
GRANT INSERT ON audit.audit_events TO matching_schema_owner;
GRANT INSERT ON infra.outbox_events TO matching_schema_owner;

CREATE POLICY rls_matching_runtime_audit_definer
ON audit.audit_events
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user IN ('matching_creator', 'matching_selector')
    AND actor_kind = 'USER'
    AND actor_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND command_id = NULLIF(
        current_setting('app.command_id', true), ''
    )::uuid
    AND causation_id = command_id
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND target_kind IN ('Invitation', 'Selection')
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
);

CREATE POLICY rls_matching_runtime_outbox_definer
ON infra.outbox_events
FOR INSERT TO matching_schema_owner
WITH CHECK (
    session_user IN ('matching_creator', 'matching_selector')
    AND actor_kind = 'USER'
    AND actor_id = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )::uuid
    AND causation_id = NULLIF(
        current_setting('app.command_id', true), ''
    )::uuid
    AND organization_id = NULLIF(
        current_setting('app.organization_id', true), ''
    )::uuid
    AND aggregate_type IN ('Invitation', 'Selection', 'MatchingAttempt')
    AND NULLIF(current_setting('app.scope_kind', true), '') IN (
        'MATCHING_CREATOR', 'CANDIDATE_SELECTOR'
    )
);

SET LOCAL ROLE matching_schema_owner;

CREATE FUNCTION matching.selection_invitation_set_sha256_v1(
    exact_attempt_id uuid,
    exact_run_id uuid
)
RETURNS bytea
LANGUAGE plpgsql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    invitation_items text;
    canonical_value text;
BEGIN
    SELECT COALESCE(
        string_agg(
            '{"aggregate_version":' || item.aggregate_version::text
            || ',"invitation_id":"' || item.id::text
            || '","snapshot_sha256":"' || encode(item.snapshot_sha256, 'hex')
            || '","status":"' || item.status || '"}',
            ',' ORDER BY item.id::text
        ),
        ''
    )
    INTO invitation_items
    FROM matching.invitations AS item
    WHERE item.attempt_id = exact_attempt_id
      AND item.match_run_id = exact_run_id
      AND item.status <> 'CREATED';

    canonical_value := '{"attempt_id":"' || exact_attempt_id::text
        || '","canonicalization_version":"selection-invitation-set-json-v1"'
        || ',"invitations":[' || invitation_items || ']'
        || ',"run_id":"' || exact_run_id::text
        || '","schema_version":1}';
    RETURN pg_catalog.sha256(pg_catalog.convert_to(canonical_value, 'UTF8'));
END
$function$;

CREATE FUNCTION matching.recipient_invitation_projection_v1(
    exact_invitation_id uuid
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
    SELECT jsonb_build_object(
        'invitation_id', invitation.id::text,
        'status', invitation.status,
        'aggregate_version', invitation.aggregate_version,
        'updated_at', invitation.updated_at,
        'expires_at', invitation.expires_at,
        'snapshot_sha256', encode(invitation.snapshot_sha256, 'hex'),
        'response_status', CASE
            WHEN invitation.status IN ('ACCEPTED', 'DECLINED', 'WITHDRAWN')
            THEN invitation.status ELSE NULL END,
        'disclosure', snapshot.snapshot
    )
    FROM matching.invitations AS invitation
    JOIN matching.invitation_disclosure_snapshots AS snapshot
      ON snapshot.id = invitation.disclosure_snapshot_id
     AND snapshot.invitation_id = invitation.id
     AND snapshot.snapshot_sha256 = invitation.snapshot_sha256
    WHERE invitation.id = exact_invitation_id
$function$;

CREATE FUNCTION matching.selection_projection_v1(
    exact_selection_id uuid,
    exact_assignment_id uuid,
    exact_assignment_version bigint
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
    SELECT jsonb_build_object(
        'selection_id', selection.id::text,
        'attempt_id', selection.attempt_id::text,
        'candidate_selector_assignment_id', exact_assignment_id::text,
        'candidate_selector_assignment_version', exact_assignment_version,
        'status', selection.status,
        'aggregate_version', selection.aggregate_version,
        'updated_at', selection.updated_at,
        'current_invitation_set_sha256',
            encode(selection.current_invitation_set_sha256, 'hex'),
        'chosen_invitation_id', selection.chosen_invitation_id::text,
        'accepted_invitations', COALESCE((
            SELECT jsonb_agg(
                jsonb_build_object(
                    'invitation_id', invitation.id::text,
                    'creator_display_handle', 'creator_'
                        || substr(replace(invitation.creator_user_id::text, '-', ''), 1, 16),
                    'profile_id', invitation.profile_id::text,
                    'profile_version_id', invitation.profile_version_id::text,
                    'accepted_at', invitation.responded_at,
                    'capability_summary', 'Published creator profile '
                        || substr(replace(invitation.profile_id::text, '-', ''), 1, 16)
                ) ORDER BY invitation.id
            )
            FROM matching.invitations AS invitation
            WHERE invitation.attempt_id = selection.attempt_id
              AND invitation.match_run_id = selection.match_run_id
              AND invitation.status = 'ACCEPTED'
        ), '[]'::jsonb)
    )
    FROM matching.selections AS selection
    WHERE selection.id = exact_selection_id
$function$;

REVOKE ALL ON FUNCTION matching.selection_invitation_set_sha256_v1(uuid, uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.recipient_invitation_projection_v1(uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.selection_projection_v1(uuid, uuid, bigint)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching.recipient_invitation_projection_v1(uuid)
TO matching_creator;
GRANT EXECUTE ON FUNCTION matching.selection_projection_v1(uuid, uuid, bigint)
TO matching_selector;

CREATE FUNCTION matching.claim_command_receipt_v1(
    exact_receipt_id uuid,
    exact_actor_user_id uuid,
    exact_organization_id uuid,
    exact_operation text,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_authority_marker_sha256 bytea,
    exact_canonical_path text,
    exact_target_kind text,
    exact_target_id uuid,
    exact_if_match_version bigint
)
RETURNS TABLE (safe_response jsonb, replayed boolean, claimed boolean)
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    existing matching.command_receipts%ROWTYPE;
BEGIN
    SELECT receipt.*
    INTO existing
    FROM matching.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.organization_id = exact_organization_id
      AND receipt.operation = exact_operation
      AND receipt.command_version = 1
      AND receipt.identity_key_id = exact_identity_key_id
      AND receipt.identity_digest = exact_identity_digest
    FOR UPDATE;

    IF FOUND THEN
        IF existing.payload_hash_key_id IS DISTINCT FROM exact_payload_hash_key_id
           OR existing.payload_hash IS DISTINCT FROM exact_payload_hash
           OR existing.principal_authority_marker_sha256
                IS DISTINCT FROM exact_authority_marker_sha256
           OR existing.canonical_path IS DISTINCT FROM exact_canonical_path
           OR existing.target_kind IS DISTINCT FROM exact_target_kind
           OR existing.target_id IS DISTINCT FROM exact_target_id
           OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001',
                MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.safe_response_body IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001',
                MESSAGE = 'SERVICE_UNAVAILABLE';
        END IF;
        RETURN QUERY SELECT existing.safe_response_body, true, false;
        RETURN;
    END IF;

    INSERT INTO matching.command_receipts (
        id,principal_kind,principal_id,organization_id,operation,
        command_version,canonicalization_version,identity_key_id,
        identity_digest,payload_hash_key_id,payload_hash,
        principal_authority_marker_sha256,http_method,canonical_path,
        target_kind,target_id,parent_kind,parent_id,if_match_version,status,
        response_http_status,response_schema_name,response_schema_version,
        response_entity_tag,safe_response_body,target_version,result_status,
        event_types,retain_until,created_at,completed_at
    ) VALUES (
        exact_receipt_id,'USER',exact_actor_user_id,exact_organization_id,
        exact_operation,1,'matching-command-json-v1',exact_identity_key_id,
        exact_identity_digest,exact_payload_hash_key_id,exact_payload_hash,
        exact_authority_marker_sha256,'POST',exact_canonical_path,
        exact_target_kind,exact_target_id,NULL,NULL,exact_if_match_version,
        'IN_PROGRESS',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
        transaction_timestamp()+interval '30 days',transaction_timestamp(),NULL
    ) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        SELECT receipt.*
        INTO existing
        FROM matching.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.organization_id = exact_organization_id
          AND receipt.operation = exact_operation
          AND receipt.command_version = 1
          AND receipt.identity_key_id = exact_identity_key_id
          AND receipt.identity_digest = exact_identity_digest
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001', MESSAGE = 'SERVICE_UNAVAILABLE';
        END IF;
        IF existing.payload_hash_key_id IS DISTINCT FROM exact_payload_hash_key_id
           OR existing.payload_hash IS DISTINCT FROM exact_payload_hash
           OR existing.principal_authority_marker_sha256
                IS DISTINCT FROM exact_authority_marker_sha256
           OR existing.canonical_path IS DISTINCT FROM exact_canonical_path
           OR existing.target_kind IS DISTINCT FROM exact_target_kind
           OR existing.target_id IS DISTINCT FROM exact_target_id
           OR existing.if_match_version IS DISTINCT FROM exact_if_match_version
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001', MESSAGE = 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.safe_response_body IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P0001', MESSAGE = 'SERVICE_UNAVAILABLE';
        END IF;
        RETURN QUERY SELECT existing.safe_response_body, true, false;
        RETURN;
    END IF;
    RETURN QUERY SELECT NULL::jsonb, false, true;
END
$function$;

CREATE FUNCTION matching.complete_command_receipt_v1(
    exact_receipt_id uuid,
    exact_safe_response jsonb,
    exact_target_version bigint,
    exact_result_status text,
    exact_event_types text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
BEGIN
    UPDATE matching.command_receipts
    SET status='COMPLETED',
        response_http_status=200,
        response_schema_name='MatchingCommandResult',
        response_schema_version=1,
        response_entity_tag='"v' || exact_target_version::text || '"',
        safe_response_body=exact_safe_response,
        target_version=exact_target_version,
        result_status=exact_result_status,
        event_types=exact_event_types,
        completed_at=transaction_timestamp()
    WHERE id=exact_receipt_id AND status='IN_PROGRESS';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
END
$function$;

CREATE FUNCTION matching.record_audit_v1(
    exact_event_id uuid,
    exact_actor_user_id uuid,
    exact_action_code text,
    exact_target_kind text,
    exact_target_id uuid,
    exact_organization_id uuid,
    exact_before_status text,
    exact_after_status text,
    exact_before_version bigint,
    exact_after_version bigint,
    exact_reason_code text,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_safe_attributes jsonb
)
RETURNS void
LANGUAGE sql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, audit
AS $function$
    INSERT INTO audit.audit_events (
        event_id,occurred_at,actor_kind,actor_id,original_actor_id,
        action_code,target_kind,target_id,organization_id,before_status,
        after_status,before_version,after_version,role_code,purpose_code,
        reason_code,auth_strength_code,result_code,command_id,correlation_id,
        causation_id,trace_id,safe_attributes
    ) VALUES (
        exact_event_id,transaction_timestamp(),'USER',exact_actor_user_id,NULL,
        exact_action_code,exact_target_kind,exact_target_id,
        exact_organization_id,exact_before_status,exact_after_status,
        exact_before_version,exact_after_version,NULL,NULL,exact_reason_code,
        NULL,'SUCCEEDED',exact_command_id,exact_correlation_id,
        exact_command_id,exact_trace_id,exact_safe_attributes
    )
$function$;

CREATE FUNCTION matching.record_outbox_v1(
    exact_event_id uuid,
    exact_event_type text,
    exact_aggregate_type text,
    exact_aggregate_id uuid,
    exact_aggregate_version bigint,
    exact_actor_user_id uuid,
    exact_organization_id uuid,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_payload jsonb
)
RETURNS void
LANGUAGE sql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, infra
AS $function$
    INSERT INTO infra.outbox_events (
        event_id,event_type,schema_version,occurred_at,aggregate_type,
        aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,
        correlation_id,causation_id,trace_id,organization_id,payload,
        delivery_status,attempt_count,available_at,lease_owner,lease_until,
        published_at,last_error_code,created_at
    ) VALUES (
        exact_event_id,exact_event_type,1,transaction_timestamp(),
        exact_aggregate_type,exact_aggregate_id,exact_aggregate_version,
        'USER',exact_actor_user_id,NULL,exact_correlation_id,exact_command_id,
        exact_trace_id,exact_organization_id,exact_payload,'PENDING',0,
        transaction_timestamp(),NULL,NULL,NULL,NULL,transaction_timestamp()
    )
$function$;

REVOKE ALL ON FUNCTION matching.claim_command_receipt_v1(
    uuid,uuid,uuid,text,text,bytea,text,bytea,bytea,text,text,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.complete_command_receipt_v1(
    uuid,jsonb,bigint,text,text[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.record_audit_v1(
    uuid,uuid,text,text,uuid,uuid,text,text,bigint,bigint,text,uuid,uuid,uuid,jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION matching.record_outbox_v1(
    uuid,text,text,uuid,bigint,uuid,uuid,uuid,uuid,uuid,jsonb
) FROM PUBLIC;

CREATE FUNCTION matching_api.execute_creator_invitation_v1(
    exact_operation text,
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_invitation_id uuid,
    expected_invitation_version bigint,
    expected_snapshot_sha256 bytea,
    exact_reason_code text,
    exact_restricted_note text,
    expected_authority_marker_sha256 bytea,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_fact_id uuid,
    exact_audit_event_id uuid,
    exact_invitation_event_id uuid,
    exact_selection_event_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    target matching.invitations%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    new_invitation_status text;
    invitation_event_type text;
    new_invitation_version bigint;
    new_selection_version bigint;
    new_set_sha256 bytea;
    response_body jsonb;
    receipt_row record;
    canonical_path text;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_creator'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_operation NOT IN (
            'ACCEPT_INVITATION','DECLINE_INVITATION','WITHDRAW_INVITATION'
       )
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_invitation_id IS NULL
       OR expected_invitation_version < 1
       OR octet_length(expected_snapshot_sha256) <> 32
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR exact_restricted_note IS NOT NULL
            AND (length(exact_restricted_note) > 500
                OR exact_restricted_note ~ '[[:cntrl:]]')
       OR (exact_operation='ACCEPT_INVITATION'
            AND (exact_reason_code IS NOT NULL
                OR exact_restricted_note IS NOT NULL))
       OR (exact_operation IN ('DECLINE_INVITATION','WITHDRAW_INVITATION')
            AND (exact_reason_code IS NULL
                OR exact_reason_code !~ '^[A-Z][A-Z0-9_]{1,63}$'))
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'MATCHING_CREATOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.invitation_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_invitation_id::text
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.selection_id', true), '') <> ''
       OR COALESCE(current_setting('app.demand_id', true), '') <> ''
       OR COALESCE(
            current_setting('app.selector_assignment_id', true), ''
       ) <> ''
    THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    canonical_path := '/v1/me/matching-invitations/'
        || exact_invitation_id::text || CASE exact_operation
            WHEN 'ACCEPT_INVITATION' THEN '/accept'
            WHEN 'DECLINE_INVITATION' THEN '/decline'
            ELSE '/withdraw' END;
    SELECT * INTO STRICT receipt_row
    FROM matching.claim_command_receipt_v1(
        exact_receipt_id,exact_actor_user_id,exact_organization_id,
        exact_operation,exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        expected_authority_marker_sha256,canonical_path,'Invitation',
        exact_invitation_id,expected_invitation_version
    );
    IF receipt_row.replayed THEN
        RETURN QUERY SELECT receipt_row.safe_response, true;
        RETURN;
    END IF;

    SELECT invitation.* INTO target
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',target.attempt_id::text,true);

    SELECT attempt.* INTO attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=target.attempt_id
    FOR SHARE;
    IF NOT FOUND OR attempt_row.selection_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM set_config('app.selection_id',attempt_row.selection_id::text,true);

    SELECT selection.* INTO selection_row
    FROM matching.selections AS selection
    WHERE selection.id=attempt_row.selection_id
    FOR UPDATE;
    IF NOT FOUND OR selection_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING
            ERRCODE='P0001', MESSAGE=CASE
                WHEN exact_operation='WITHDRAW_INVITATION'
                THEN 'INVITATION_ALREADY_SELECTED'
                ELSE 'INVALID_STATE_TRANSITION' END;
    END IF;

    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=target.attempt_id
      AND invitation.match_run_id=target.match_run_id
    ORDER BY invitation.id
    FOR UPDATE;
    SELECT invitation.* INTO target
    FROM matching.invitations AS invitation
    WHERE invitation.id=exact_invitation_id;

    IF target.aggregate_version <> expected_invitation_version
       OR target.snapshot_sha256 IS DISTINCT FROM expected_snapshot_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;
    IF target.organization_id <> exact_organization_id
       OR target.creator_user_id <> exact_actor_user_id
       OR target.creator_authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;

    IF exact_operation IN ('ACCEPT_INVITATION','DECLINE_INVITATION') THEN
        IF target.status <> 'SENT'
           OR target.expires_at <= transaction_timestamp() THEN
            RAISE EXCEPTION USING
                ERRCODE='P0001', MESSAGE='INVALID_STATE_TRANSITION';
        END IF;
        new_invitation_status := CASE exact_operation
            WHEN 'ACCEPT_INVITATION' THEN 'ACCEPTED' ELSE 'DECLINED' END;
        invitation_event_type := CASE exact_operation
            WHEN 'ACCEPT_INVITATION' THEN 'InvitationAccepted'
            ELSE 'InvitationDeclined' END;
        INSERT INTO matching.invitation_responses (
            id,invitation_id,creator_user_id,response_kind,snapshot_sha256,
            reason_code,restricted_note,responded_at
        ) VALUES (
            exact_fact_id,target.id,target.creator_user_id,
            new_invitation_status,target.snapshot_sha256,exact_reason_code,
            exact_restricted_note,transaction_timestamp()
        );
    ELSE
        IF target.status <> 'ACCEPTED' THEN
            RAISE EXCEPTION USING
                ERRCODE='P0001', MESSAGE='INVALID_STATE_TRANSITION';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM matching.invitation_responses AS response
            WHERE response.invitation_id=target.id
              AND response.response_kind='ACCEPTED'
        ) OR EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE='P0001', MESSAGE='INVITATION_ALREADY_SELECTED';
        END IF;
        new_invitation_status := 'WITHDRAWN';
        invitation_event_type := 'InvitationWithdrawn';
        INSERT INTO matching.invitation_withdrawals (
            id,invitation_id,creator_user_id,snapshot_sha256,reason_code,
            restricted_note,withdrawn_at
        ) VALUES (
            exact_fact_id,target.id,target.creator_user_id,
            target.snapshot_sha256,exact_reason_code,exact_restricted_note,
            transaction_timestamp()
        );
    END IF;

    new_invitation_version := target.aggregate_version+1;
    UPDATE matching.invitations
    SET status=new_invitation_status,
        aggregate_version=new_invitation_version,
        responded_at=transaction_timestamp(),
        updated_at=transaction_timestamp()
    WHERE id=target.id;

    new_set_sha256 := matching.selection_invitation_set_sha256_v1(
        target.attempt_id,target.match_run_id
    );
    IF new_set_sha256 IS NULL
       OR new_set_sha256=selection_row.current_invitation_set_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    new_selection_version := selection_row.aggregate_version+1;
    UPDATE matching.selections
    SET aggregate_version=new_selection_version,
        current_invitation_set_sha256=new_set_sha256,
        updated_at=transaction_timestamp()
    WHERE id=selection_row.id;

    PERFORM matching.record_audit_v1(
        exact_audit_event_id,exact_actor_user_id,exact_operation,
        'Invitation',target.id,exact_organization_id,target.status,
        new_invitation_status,target.aggregate_version,new_invitation_version,
        exact_reason_code,exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object('selection_id',selection_row.id::text,
            'selection_version',new_selection_version)
    );
    PERFORM matching.record_outbox_v1(
        exact_invitation_event_id,invitation_event_type,'Invitation',target.id,
        new_invitation_version,exact_actor_user_id,exact_organization_id,
        exact_command_id,exact_correlation_id,exact_trace_id,
        jsonb_build_object(
            'invitation_id',target.id::text,'attempt_id',target.attempt_id::text,
            'run_id',target.match_run_id::text,
            'creator_user_id',target.creator_user_id::text,
            'profile_version_id',target.profile_version_id::text,
            'snapshot_sha256',encode(target.snapshot_sha256,'hex'),
            'status',new_invitation_status,'expires_at',target.expires_at,
            'reason_code',exact_reason_code)
    );
    PERFORM matching.record_outbox_v1(
        exact_selection_event_id,'SelectionInvitationSetChanged','Selection',
        selection_row.id,new_selection_version,exact_actor_user_id,
        exact_organization_id,exact_command_id,exact_correlation_id,
        exact_trace_id,jsonb_build_object(
            'selection_id',selection_row.id::text,
            'attempt_id',selection_row.attempt_id::text,'status','OPEN',
            'current_invitation_set_sha256',encode(new_set_sha256,'hex'),
            'chosen_invitation_id',NULL,'selection_basis_code',NULL,
            'reason_code',NULL)
    );

    response_body := matching.recipient_invitation_projection_v1(target.id);
    IF response_body IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM matching.complete_command_receipt_v1(
        exact_receipt_id,response_body,new_invitation_version,
        new_invitation_status,ARRAY[
            invitation_event_type,'SelectionInvitationSetChanged'
        ]::text[]
    );
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.execute_creator_invitation_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,text,text,bytea,uuid,uuid,uuid,
    uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.execute_creator_invitation_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,text,text,bytea,uuid,uuid,uuid,
    uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) TO matching_creator;

CREATE FUNCTION matching_api.execute_candidate_selection_v1(
    exact_operation text,
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_selection_id uuid,
    expected_selection_version bigint,
    expected_invitation_set_sha256 bytea,
    exact_selector_assignment_id uuid,
    expected_selector_assignment_version bigint,
    expected_authority_marker_sha256 bytea,
    exact_invitation_id uuid,
    exact_selection_basis_code text,
    exact_reason_code text,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_intent_id uuid,
    exact_audit_event_id uuid,
    exact_primary_event_id uuid,
    exact_secondary_event_id uuid,
    exact_identity_key_id text,
    exact_identity_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    exact_correlation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (safe_response jsonb, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    assignment_row matching.candidate_selector_assignments%ROWTYPE;
    selection_row matching.selections%ROWTYPE;
    attempt_row matching.matching_attempts%ROWTYPE;
    run_row matching.match_runs%ROWTYPE;
    invitation_row matching.invitations%ROWTYPE;
    candidate_row matching.match_candidates%ROWTYPE;
    authoritative_set_sha256 bytea;
    response_body jsonb;
    receipt_row record;
    canonical_path text;
    new_selection_version bigint;
    new_attempt_version bigint;
    response_assignment_version bigint;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_selector'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_operation NOT IN ('CHOOSE_CREATOR','CLOSE_SELECTION')
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_selection_id IS NULL
       OR exact_selector_assignment_id IS NULL
       OR expected_selection_version < 1
       OR expected_selector_assignment_version < 1
       OR octet_length(expected_invitation_set_sha256) <> 32
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR octet_length(exact_identity_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_identity_key_id = exact_payload_hash_key_id
       OR (exact_operation='CHOOSE_CREATOR' AND (
            exact_invitation_id IS NULL OR exact_intent_id IS NULL
            OR exact_secondary_event_id IS NOT NULL
            OR exact_selection_basis_code IS NULL
            OR exact_selection_basis_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
            OR exact_reason_code IS NOT NULL
       ))
       OR (exact_operation='CLOSE_SELECTION' AND (
            exact_invitation_id IS NOT NULL OR exact_intent_id IS NOT NULL
            OR exact_secondary_event_id IS NULL
            OR exact_selection_basis_code IS NOT NULL
            OR exact_reason_code IS NULL
            OR exact_reason_code !~ '^[A-Z][A-Z0-9_]{1,63}$'
       ))
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text
       OR NULLIF(current_setting('app.selector_assignment_id', true), '')
            IS DISTINCT FROM exact_selector_assignment_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_selection_id::text
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.invitation_id', true), '') <> ''
       OR COALESCE(current_setting('app.demand_id', true), '') <> ''
    THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='ACCESS_DENIED';
    END IF;

    canonical_path := '/v1/organizations/' || exact_organization_id::text
        || '/selections/' || exact_selection_id::text || CASE exact_operation
            WHEN 'CHOOSE_CREATOR' THEN '/choose' ELSE '/close' END;
    SELECT * INTO STRICT receipt_row
    FROM matching.claim_command_receipt_v1(
        exact_receipt_id,exact_actor_user_id,exact_organization_id,
        exact_operation,exact_identity_key_id,exact_identity_digest,
        exact_payload_hash_key_id,exact_payload_hash,
        expected_authority_marker_sha256,canonical_path,'Selection',
        exact_selection_id,expected_selection_version
    );
    IF receipt_row.replayed THEN
        RETURN QUERY SELECT receipt_row.safe_response, true;
        RETURN;
    END IF;

    SELECT assignment.* INTO assignment_row
    FROM matching.candidate_selector_assignments AS assignment
    WHERE assignment.id=exact_selector_assignment_id
    FOR UPDATE;
    IF NOT FOUND
       OR assignment_row.assignment_version
            <> expected_selector_assignment_version
       OR assignment_row.status <> 'ACTIVE'
       OR assignment_row.expires_at <= transaction_timestamp()
       OR assignment_row.assignee_user_id <> exact_actor_user_id
       OR assignment_row.organization_id <> exact_organization_id
       OR assignment_row.selection_id <> exact_selection_id
       OR assignment_row.authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE='P0001', MESSAGE='SELECTOR_ASSIGNMENT_REQUIRED';
    END IF;

    SELECT selection.* INTO selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    PERFORM set_config('app.attempt_id',selection_row.attempt_id::text,true);
    PERFORM set_config(
        'app.invitation_id',COALESCE(exact_invitation_id::text,''),true
    );

    SELECT attempt.* INTO attempt_row
    FROM matching.matching_attempts AS attempt
    WHERE attempt.id=selection_row.attempt_id
    FOR UPDATE;
    SELECT selection.* INTO selection_row
    FROM matching.selections AS selection
    WHERE selection.id=exact_selection_id
    FOR UPDATE;
    IF NOT FOUND
       OR selection_row.status <> 'OPEN'
       OR attempt_row.status <> 'OPEN' THEN
        RAISE EXCEPTION USING
            ERRCODE='P0001', MESSAGE='INVALID_STATE_TRANSITION';
    END IF;
    IF assignment_row.demand_id <> attempt_row.demand_id
       OR selection_row.organization_id <> attempt_row.organization_id
       OR selection_row.attempt_id <> attempt_row.id THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='RESOURCE_NOT_FOUND';
    END IF;
    IF selection_row.aggregate_version <> expected_selection_version
       OR selection_row.current_invitation_set_sha256
            IS DISTINCT FROM expected_invitation_set_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
    END IF;

    SELECT run.* INTO run_row
    FROM matching.match_runs AS run
    WHERE run.id=attempt_row.current_match_run_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    PERFORM invitation.id
    FROM matching.invitations AS invitation
    WHERE invitation.attempt_id=attempt_row.id
      AND invitation.match_run_id=attempt_row.current_match_run_id
    ORDER BY invitation.id
    FOR UPDATE;
    authoritative_set_sha256 := matching.selection_invitation_set_sha256_v1(
        attempt_row.id,attempt_row.current_match_run_id
    );
    IF authoritative_set_sha256 IS NULL
       OR authoritative_set_sha256
            IS DISTINCT FROM selection_row.current_invitation_set_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;

    IF exact_operation='CHOOSE_CREATOR' THEN
        SELECT invitation.* INTO invitation_row
        FROM matching.invitations AS invitation
        WHERE invitation.id=exact_invitation_id;
        IF NOT FOUND
           OR invitation_row.attempt_id <> attempt_row.id
           OR invitation_row.match_run_id <> attempt_row.current_match_run_id
           OR invitation_row.status <> 'ACCEPTED'
           OR run_row.status <> 'COMPLETED'
           OR run_row.superseded_by_run_id IS NOT NULL
           OR run_row.input_set_sha256 IS NULL
           OR run_row.ordered_result_sha256 IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
        END IF;
        IF EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
        ) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PRECONDITION_FAILED';
        END IF;
        SELECT candidate.* INTO candidate_row
        FROM matching.match_candidates AS candidate
        WHERE candidate.match_run_id=run_row.id
          AND candidate.creator_user_id=invitation_row.creator_user_id;
        IF NOT FOUND
           OR candidate_row.eligibility <> 'ELIGIBLE'
           OR candidate_row.profile_id <> invitation_row.profile_id
           OR candidate_row.profile_version_id
                <> invitation_row.profile_version_id THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
        END IF;

        INSERT INTO matching.selection_intents (
            id,receipt_id,command_id,organization_id,selection_id,attempt_id,
            match_run_id,invitation_id,actor_user_id,
            candidate_selector_assignment_id,
            candidate_selector_assignment_version,
            candidate_selector_authority_marker_sha256,demand_id,
            demand_version_id,matching_request_id,matching_request_version,
            funding_id,matching_rule_bundle_id,input_set_sha256,
            ordered_result_sha256,candidate_result_sha256,
            current_invitation_set_sha256,selection_basis_code,
            payload_hash_key_id,payload_hash,status,recorded_at,
            invitation_status
        ) VALUES (
            exact_intent_id,exact_receipt_id,exact_command_id,
            exact_organization_id,selection_row.id,attempt_row.id,run_row.id,
            invitation_row.id,exact_actor_user_id,assignment_row.id,
            assignment_row.assignment_version,assignment_row.authority_marker_sha256,
            attempt_row.demand_id,attempt_row.demand_version_id,
            attempt_row.matching_request_id,attempt_row.matching_request_version,
            attempt_row.funding_id,run_row.matching_rule_bundle_id,
            run_row.input_set_sha256,run_row.ordered_result_sha256,
            candidate_row.candidate_result_sha256,
            selection_row.current_invitation_set_sha256,
            exact_selection_basis_code,exact_payload_hash_key_id,
            exact_payload_hash,'READY',transaction_timestamp(),'ACCEPTED'
        );
        PERFORM matching.record_audit_v1(
            exact_audit_event_id,exact_actor_user_id,'CHOOSE_CREATOR',
            'Selection',selection_row.id,exact_organization_id,
            selection_row.status,selection_row.status,
            selection_row.aggregate_version,selection_row.aggregate_version,
            NULL,exact_command_id,exact_correlation_id,exact_trace_id,
            jsonb_build_object('intent_id',exact_intent_id::text,
                'invitation_id',invitation_row.id::text,
                'candidate_selector_assignment_id',assignment_row.id::text)
        );
        PERFORM matching.record_outbox_v1(
            exact_primary_event_id,'SelectionIntentRecorded','Selection',
            selection_row.id,selection_row.aggregate_version,
            exact_actor_user_id,exact_organization_id,exact_command_id,
            exact_correlation_id,exact_trace_id,jsonb_build_object(
                'selection_id',selection_row.id::text,
                'attempt_id',selection_row.attempt_id::text,'status','OPEN',
                'current_invitation_set_sha256',
                    encode(selection_row.current_invitation_set_sha256,'hex'),
                'chosen_invitation_id',invitation_row.id::text,
                'selection_basis_code',exact_selection_basis_code,
                'reason_code',NULL)
        );
        response_body := matching.selection_projection_v1(
            selection_row.id,assignment_row.id,assignment_row.assignment_version
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,selection_row.aggregate_version,
            selection_row.status,ARRAY['SelectionIntentRecorded']::text[]
        );
    ELSE
        IF EXISTS (
            SELECT 1 FROM matching.selection_intents AS intent
            WHERE intent.selection_id=selection_row.id
        ) OR EXISTS (
            SELECT 1 FROM matching.invitations AS invitation
            WHERE invitation.attempt_id=attempt_row.id
              AND invitation.match_run_id=attempt_row.current_match_run_id
              AND invitation.status IN ('CREATED','SENT')
        ) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SELECTION_NOT_READY';
        END IF;
        new_selection_version := selection_row.aggregate_version+1;
        new_attempt_version := attempt_row.aggregate_version+1;
        response_assignment_version := assignment_row.assignment_version+1;
        UPDATE matching.selections
        SET status='CLOSED_NO_SELECTION',
            aggregate_version=new_selection_version,
            reason_code=exact_reason_code,
            decision_actor_id=exact_actor_user_id,
            updated_at=transaction_timestamp()
        WHERE id=selection_row.id;
        UPDATE matching.matching_attempts
        SET status='CLOSED_NO_SELECTION',aggregate_version=new_attempt_version,
            updated_at=transaction_timestamp(),terminal_at=transaction_timestamp()
        WHERE id=attempt_row.id;
        UPDATE matching.candidate_selector_assignments
        SET status='COMPLETED',
            assignment_version=response_assignment_version,
            completed_at=transaction_timestamp()
        WHERE id=assignment_row.id;
        PERFORM matching.record_audit_v1(
            exact_audit_event_id,exact_actor_user_id,'CLOSE_SELECTION',
            'Selection',selection_row.id,exact_organization_id,
            selection_row.status,'CLOSED_NO_SELECTION',
            selection_row.aggregate_version,new_selection_version,
            exact_reason_code,exact_command_id,exact_correlation_id,
            exact_trace_id,jsonb_build_object(
                'attempt_id',attempt_row.id::text,
                'attempt_version',new_attempt_version,
                'candidate_selector_assignment_id',assignment_row.id::text,
                'candidate_selector_assignment_version',
                    response_assignment_version)
        );
        PERFORM matching.record_outbox_v1(
            exact_primary_event_id,'SelectionClosedWithoutChoice','Selection',
            selection_row.id,new_selection_version,exact_actor_user_id,
            exact_organization_id,exact_command_id,exact_correlation_id,
            exact_trace_id,jsonb_build_object(
                'selection_id',selection_row.id::text,
                'attempt_id',selection_row.attempt_id::text,
                'status','CLOSED_NO_SELECTION',
                'current_invitation_set_sha256',
                    encode(selection_row.current_invitation_set_sha256,'hex'),
                'chosen_invitation_id',NULL,'selection_basis_code',NULL,
                'reason_code',exact_reason_code)
        );
        PERFORM matching.record_outbox_v1(
            exact_secondary_event_id,'MatchingAttemptClosedWithoutSelection',
            'MatchingAttempt',attempt_row.id,new_attempt_version,
            exact_actor_user_id,exact_organization_id,exact_command_id,
            exact_correlation_id,exact_trace_id,jsonb_build_object(
                'attempt_id',attempt_row.id::text,
                'demand_id',attempt_row.demand_id::text,
                'demand_version_id',attempt_row.demand_version_id::text,
                'matching_request_id',attempt_row.matching_request_id::text,
                'attempt_no',attempt_row.attempt_no,
                'status','CLOSED_NO_SELECTION','reason_code',NULL,
                'selection_id',selection_row.id::text,
                'chosen_invitation_id',NULL)
        );
        response_body := matching.selection_projection_v1(
            selection_row.id,assignment_row.id,response_assignment_version
        );
        PERFORM matching.complete_command_receipt_v1(
            exact_receipt_id,response_body,new_selection_version,
            'CLOSED_NO_SELECTION',ARRAY[
                'SelectionClosedWithoutChoice',
                'MatchingAttemptClosedWithoutSelection'
            ]::text[]
        );
    END IF;
    IF response_body IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END IF;
    RETURN QUERY SELECT response_body,false;
END
$function$;

REVOKE ALL ON FUNCTION matching_api.execute_candidate_selection_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,text,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.execute_candidate_selection_v1(
    text,uuid,uuid,uuid,uuid,bigint,bytea,uuid,bigint,bytea,uuid,text,text,
    uuid,uuid,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid
) TO matching_selector;

CREATE FUNCTION matching_api.list_candidate_selector_attempts_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    expected_authority_marker_sha256 bytea,
    maximum_items integer,
    cursor_updated_at timestamptz,
    cursor_attempt_id uuid
)
RETURNS TABLE (
    attempt_id uuid,
    demand_id uuid,
    attempt_no integer,
    status text,
    aggregate_version bigint,
    updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
BEGIN
    IF session_user IS DISTINCT FROM 'matching_selector'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_demand_id IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR maximum_items NOT BETWEEN 1 AND 101
       OR (cursor_updated_at IS NULL) <> (cursor_attempt_id IS NULL)
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'LIST_SELECTOR_ATTEMPTS'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.selection_id', true), '') <> ''
       OR COALESCE(current_setting('app.invitation_id', true), '') <> ''
       OR COALESCE(
            current_setting('app.selector_assignment_id', true), ''
       ) <> ''
       OR COALESCE(current_setting('app.command_id', true), '') <> ''
       OR COALESCE(current_setting('app.target_id', true), '') <> ''
       THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT attempt.id,attempt.demand_id,attempt.attempt_no,attempt.status::text,
        attempt.aggregate_version,attempt.updated_at
    FROM matching.matching_attempts AS attempt
    JOIN matching.selections AS selection ON selection.attempt_id=attempt.id
    JOIN matching.candidate_selector_assignments AS assignment
      ON assignment.selection_id=selection.id
    WHERE attempt.organization_id=exact_organization_id
      AND attempt.demand_id=exact_demand_id
      AND assignment.assignee_user_id=exact_actor_user_id
      AND assignment.organization_id=exact_organization_id
      AND assignment.demand_id=exact_demand_id
      AND assignment.authority_marker_sha256
            =expected_authority_marker_sha256
      AND assignment.status='ACTIVE'
      AND assignment.expires_at>transaction_timestamp()
      AND (cursor_updated_at IS NULL
        OR (attempt.updated_at,attempt.id)<(cursor_updated_at,cursor_attempt_id))
    ORDER BY attempt.updated_at DESC,attempt.id DESC
    LIMIT maximum_items;
END
$function$;

CREATE FUNCTION matching_api.read_candidate_selector_selection_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_attempt_id uuid,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (safe_projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    resolved_selection_id uuid;
    resolved_assignment_id uuid;
    resolved_assignment_version bigint;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_selector'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_attempt_id IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'READ_SELECTION_BY_ATTEMPT'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.attempt_id', true), '')
            IS DISTINCT FROM exact_attempt_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR COALESCE(current_setting('app.demand_id', true), '') <> ''
       OR COALESCE(current_setting('app.invitation_id', true), '') <> ''
       OR COALESCE(current_setting('app.selection_id', true), '') <> ''
       OR COALESCE(
            current_setting('app.selector_assignment_id', true), ''
       ) <> ''
       OR COALESCE(current_setting('app.command_id', true), '') <> ''
       OR COALESCE(current_setting('app.target_id', true), '') <> '' THEN
        RETURN;
    END IF;

    BEGIN
        SELECT selection.id,assignment.id,assignment.assignment_version
        INTO STRICT resolved_selection_id,resolved_assignment_id,
            resolved_assignment_version
        FROM matching.matching_attempts AS attempt
        JOIN matching.selections AS selection ON selection.attempt_id=attempt.id
        JOIN matching.candidate_selector_assignments AS assignment
          ON assignment.selection_id=selection.id
        WHERE attempt.id=exact_attempt_id
          AND attempt.organization_id=exact_organization_id
          AND assignment.assignee_user_id=exact_actor_user_id
          AND assignment.organization_id=exact_organization_id
          AND assignment.authority_marker_sha256
                =expected_authority_marker_sha256
          AND assignment.status='ACTIVE'
          AND assignment.expires_at>transaction_timestamp();
    EXCEPTION WHEN no_data_found THEN
        RETURN;
    WHEN too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END;

    RETURN QUERY SELECT matching.selection_projection_v1(
        resolved_selection_id,resolved_assignment_id,
        resolved_assignment_version
    );
END
$function$;

CREATE FUNCTION matching_api.read_candidate_selector_selection_by_id_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_selection_id uuid,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (safe_projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, matching
AS $function$
DECLARE
    resolved_attempt_id uuid;
    resolved_assignment_id uuid;
    resolved_assignment_version bigint;
BEGIN
    IF session_user IS DISTINCT FROM 'matching_selector'
       OR current_user IS DISTINCT FROM 'matching_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_session_id IS NULL
       OR exact_organization_id IS NULL OR exact_selection_id IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'CANDIDATE_SELECTOR'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'READ_SELECTION_BY_ID'
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.selection_id', true), '')
            IS DISTINCT FROM exact_selection_id::text
       OR NULLIF(current_setting('app.authority_marker_sha256', true), '')
            IS DISTINCT FROM encode(expected_authority_marker_sha256,'hex')
       OR COALESCE(current_setting('app.demand_id', true), '') <> ''
       OR COALESCE(current_setting('app.attempt_id', true), '') <> ''
       OR COALESCE(current_setting('app.invitation_id', true), '') <> ''
       OR COALESCE(
            current_setting('app.selector_assignment_id', true), ''
       ) <> ''
       OR COALESCE(current_setting('app.command_id', true), '') <> ''
       OR COALESCE(current_setting('app.target_id', true), '') <> '' THEN
        RETURN;
    END IF;

    BEGIN
        SELECT selection.attempt_id,assignment.id,
            assignment.assignment_version
        INTO STRICT resolved_attempt_id,resolved_assignment_id,
            resolved_assignment_version
        FROM matching.selections AS selection
        JOIN matching.candidate_selector_assignments AS assignment
          ON assignment.selection_id=selection.id
        WHERE selection.id=exact_selection_id
          AND selection.organization_id=exact_organization_id
          AND assignment.assignee_user_id=exact_actor_user_id
          AND assignment.organization_id=exact_organization_id
          AND assignment.authority_marker_sha256
                =expected_authority_marker_sha256
          AND (
              assignment.status='ACTIVE'
              AND assignment.expires_at>transaction_timestamp()
              OR assignment.status='COMPLETED'
          );
    EXCEPTION WHEN no_data_found THEN
        RETURN;
    WHEN too_many_rows THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SERVICE_UNAVAILABLE';
    END;

    PERFORM set_config('app.attempt_id',resolved_attempt_id::text,true);
    PERFORM set_config(
        'app.selector_assignment_id',resolved_assignment_id::text,true
    );
    RETURN QUERY SELECT matching.selection_projection_v1(
        exact_selection_id,resolved_assignment_id,
        resolved_assignment_version
    );
END
$function$;

REVOKE ALL ON FUNCTION matching_api.list_candidate_selector_attempts_v1(
    uuid,uuid,uuid,uuid,bytea,integer,timestamptz,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.list_candidate_selector_attempts_v1(
    uuid,uuid,uuid,uuid,bytea,integer,timestamptz,uuid
) TO matching_selector;
REVOKE ALL ON FUNCTION matching_api.read_candidate_selector_selection_v1(
    uuid,uuid,uuid,uuid,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.read_candidate_selector_selection_v1(
    uuid,uuid,uuid,uuid,bytea
) TO matching_selector;
REVOKE ALL ON FUNCTION
matching_api.read_candidate_selector_selection_by_id_v1(
    uuid,uuid,uuid,uuid,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
matching_api.read_candidate_selector_selection_by_id_v1(
    uuid,uuid,uuid,uuid,bytea
) TO matching_selector;

DO $assert$
DECLARE
    unsafe_function_count integer;
BEGIN
    SELECT count(*) INTO unsafe_function_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='matching_api'
      AND (
        procedure.prosecdef IS NOT TRUE
        OR procedure.proowner <> (
            SELECT oid FROM pg_catalog.pg_roles
            WHERE rolname='matching_schema_owner'
        )
        OR procedure.proconfig IS NULL
        OR NOT ('search_path=pg_catalog, matching'=ANY(procedure.proconfig))
      );
    IF unsafe_function_count <> 0 THEN
        RAISE EXCEPTION 'Matching runtime function contract drift';
    END IF;
END
$assert$;
