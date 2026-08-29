-- Close two production-only IAM0034 contract gaps without changing history.
-- Runtime callers move to v2 entry points; the reviewed v1 programs remain
-- private implementation details for the narrow wrappers below.

CREATE FUNCTION iam_api.rfc3339_utc_v1(exact_value timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.to_char(
        exact_value AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    )
$function$;

REVOKE ALL ON FUNCTION iam_api.rfc3339_utc_v1(timestamptz) FROM PUBLIC;

-- Persist the same contract-valid Issue payload that the v2 command returns.
-- The trigger is deliberately limited to the one IAM event/payload timestamp
-- whose JSON representation was previously emitted with a +00:00 suffix.
CREATE FUNCTION infra.normalize_access_invitation_issued_timestamp_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam_api
AS $function$
BEGIN
    IF NEW.event_type = 'AccessInvitationIssued'
       AND NEW.schema_version = 1
       AND NEW.aggregate_type = 'AccessInvitation' THEN
        IF jsonb_typeof(NEW.payload->'expires_at') IS DISTINCT FROM 'string' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_access_invitation_issued_timestamp_v1',
                MESSAGE = 'AccessInvitationIssued expires_at is invalid';
        END IF;
        NEW.payload := jsonb_set(
            NEW.payload,
            '{expires_at}',
            to_jsonb(iam_api.rfc3339_utc_v1(
                (NEW.payload->>'expires_at')::timestamptz
            )),
            false
        );
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN invalid_datetime_format OR datetime_field_overflow THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_access_invitation_issued_timestamp_v1',
            MESSAGE = 'AccessInvitationIssued expires_at is invalid';
END
$function$;

REVOKE ALL ON FUNCTION
infra.normalize_access_invitation_issued_timestamp_v1() FROM PUBLIC;

CREATE TRIGGER trg_access_invitation_issued_timestamp_v1
BEFORE INSERT ON infra.outbox_events
FOR EACH ROW EXECUTE FUNCTION
infra.normalize_access_invitation_issued_timestamp_v1();

-- The IAM0034 write program is intentionally not copied. This v2 boundary
-- delegates the entire transaction to v1, then canonicalizes only the event
-- timestamps before the caller's closed contract validator sees the result.
CREATE FUNCTION iam_api.execute_organization_admin_v2(
    exact_operation text,
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_target_id uuid,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_original_actor_id uuid,
    exact_expected_version bigint,
    exact_idempotency_key_digest bytea,
    exact_idempotency_key_digest_key_id text,
    exact_payload_hash bytea,
    exact_payload_hash_key_id text,
    exact_retain_until timestamptz,
    new_audit_event_id uuid,
    new_outbox_event_id uuid,
    new_secondary_outbox_event_id uuid,
    new_recipient_contact_id uuid,
    exact_recipient_binding_digest bytea,
    exact_recipient_binding_digest_key_id text,
    exact_masked_recipient_label text,
    exact_invitation_expires_at timestamptz,
    exact_invitation_token_nonce bytea,
    exact_invitation_token_key_id text,
    exact_invitation_token_format_version text,
    exact_target_role_or_reason_code text,
    exact_resume_hold_action text,
    exact_resume_hold_target_type text,
    exact_resume_hold_target_id uuid,
    exact_resume_hold_target_version bigint,
    exact_resume_hold_organization_id uuid,
    exact_resume_hold_policy_version text,
    exact_resume_hold_evaluated_at timestamptz,
    exact_resume_hold_valid_until timestamptz,
    exact_resume_hold_snapshot_digest bytea,
    exact_idempotency_candidate_key_ids text[],
    exact_idempotency_candidate_digests bytea[],
    exact_payload_candidate_key_ids text[],
    exact_payload_candidate_digests bytea[],
    exact_issue_hold_action text,
    exact_issue_hold_target_type text,
    exact_issue_hold_target_id uuid,
    exact_issue_hold_target_version bigint,
    exact_issue_hold_organization_id uuid,
    exact_issue_hold_policy_version text,
    exact_issue_hold_evaluated_at timestamptz,
    exact_issue_hold_valid_until timestamptz,
    exact_issue_hold_snapshot_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam_api
AS $function$
DECLARE
    result jsonb;
BEGIN
    result := iam_api.execute_organization_admin_v1(
        exact_operation,
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        exact_target_id,
        exact_command_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id,
        exact_original_actor_id,
        exact_expected_version,
        exact_idempotency_key_digest,
        exact_idempotency_key_digest_key_id,
        exact_payload_hash,
        exact_payload_hash_key_id,
        exact_retain_until,
        new_audit_event_id,
        new_outbox_event_id,
        new_secondary_outbox_event_id,
        new_recipient_contact_id,
        exact_recipient_binding_digest,
        exact_recipient_binding_digest_key_id,
        exact_masked_recipient_label,
        exact_invitation_expires_at,
        exact_invitation_token_nonce,
        exact_invitation_token_key_id,
        exact_invitation_token_format_version,
        exact_target_role_or_reason_code,
        exact_resume_hold_action,
        exact_resume_hold_target_type,
        exact_resume_hold_target_id,
        exact_resume_hold_target_version,
        exact_resume_hold_organization_id,
        exact_resume_hold_policy_version,
        exact_resume_hold_evaluated_at,
        exact_resume_hold_valid_until,
        exact_resume_hold_snapshot_digest,
        exact_idempotency_candidate_key_ids,
        exact_idempotency_candidate_digests,
        exact_payload_candidate_key_ids,
        exact_payload_candidate_digests,
        exact_issue_hold_action,
        exact_issue_hold_target_type,
        exact_issue_hold_target_id,
        exact_issue_hold_target_version,
        exact_issue_hold_organization_id,
        exact_issue_hold_policy_version,
        exact_issue_hold_evaluated_at,
        exact_issue_hold_valid_until,
        exact_issue_hold_snapshot_digest
    );

    IF jsonb_typeof(result->'outbox_event') = 'object' THEN
        result := jsonb_set(
            result,
            '{outbox_event,occurred_at}',
            to_jsonb(iam_api.rfc3339_utc_v1(
                (result#>>'{outbox_event,occurred_at}')::timestamptz
            )),
            false
        );
        IF result#>>'{outbox_event,event_type}' = 'AccessInvitationIssued' THEN
            result := jsonb_set(
                result,
                '{outbox_event,payload,expires_at}',
                to_jsonb(iam_api.rfc3339_utc_v1(
                    (result#>>'{outbox_event,payload,expires_at}')::timestamptz
                )),
                false
            );
        END IF;
    END IF;

    IF jsonb_typeof(result->'secondary_outbox_event') = 'object' THEN
        result := jsonb_set(
            result,
            '{secondary_outbox_event,occurred_at}',
            to_jsonb(iam_api.rfc3339_utc_v1(
                (result#>>'{secondary_outbox_event,occurred_at}')::timestamptz
            )),
            false
        );
    END IF;

    RETURN result;
END
$function$;

-- IAM0034 already proves the full session/invitation/current-bundle graph.
-- Its only bad output is the missing-document set: a durable acceptance is
-- identified by User + document + content hash, not by the publishing bundle.
CREATE FUNCTION iam_api.resolve_accept_access_invitation_scope_v2(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_invitation_id uuid,
    exact_policy_bundle_id uuid,
    exact_selection jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    result jsonb;
    missing_documents jsonb;
BEGIN
    result := iam_api.resolve_accept_access_invitation_scope_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_invitation_id,
        exact_policy_bundle_id,
        exact_selection
    );
    IF result->>'decision_code' IS DISTINCT FROM 'AUTHORIZED' THEN
        RETURN result;
    END IF;

    SELECT COALESCE(
        jsonb_agg(member.document_id::text ORDER BY member.position),
        '[]'::jsonb
    )
    INTO missing_documents
    FROM iam.policy_bundle_documents AS member
    JOIN iam.policy_documents AS document ON document.id = member.document_id
    WHERE member.bundle_id = exact_policy_bundle_id
      AND member.required
      AND document.legal_effect IN (
          'NOTICE_ACKNOWLEDGEMENT', 'CONTRACT_ACCEPTANCE'
      )
      AND NOT EXISTS (
          SELECT 1
          FROM iam.policy_acceptances AS accepted
          WHERE accepted.user_id = exact_actor_user_id
            AND accepted.document_id = document.id
            AND accepted.content_sha256 = document.content_sha256
      );

    RETURN jsonb_set(
        result,
        '{missing_policy_document_ids}',
        missing_documents,
        false
    );
END
$function$;

REVOKE ALL ON FUNCTION iam_api.execute_organization_admin_v1(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea
) FROM iam_app;
REVOKE ALL ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v1(
    uuid,uuid,uuid,uuid,jsonb
) FROM iam_onboarding;

REVOKE ALL ON FUNCTION iam_api.execute_organization_admin_v2(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.execute_organization_admin_v2(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea
) TO iam_app;

REVOKE ALL ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v2(
    uuid,uuid,uuid,uuid,jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.resolve_accept_access_invitation_scope_v2(
    uuid,uuid,uuid,uuid,jsonb
) TO iam_onboarding;
