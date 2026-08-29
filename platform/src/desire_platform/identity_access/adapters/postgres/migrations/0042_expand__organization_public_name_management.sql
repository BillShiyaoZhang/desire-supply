-- Add the narrow ORG_ADMIN public-name correction command without widening
-- direct table authority.  The public v3 ABI is the reviewed v2 ABI plus one
-- final, exact public-name value.

CREATE FUNCTION iam.organization_public_name_is_canonical_v1(
    exact_value text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT exact_value IS NOT NULL
       AND char_length(exact_value) BETWEEN 1 AND 160
       AND exact_value IS NFC NORMALIZED
       AND exact_value = btrim(
            exact_value,
            U&'\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006'
            || U&'\2007\2008\2009\200A\2028\2029\202F\205F\3000'
       )
       AND NOT EXISTS (
            SELECT 1
            FROM generate_series(1, char_length(exact_value)) AS slot(position)
            CROSS JOIN LATERAL (
                SELECT ascii(substr(exact_value, slot.position, 1)) AS value
            ) AS codepoint
            WHERE codepoint.value BETWEEN 0 AND 31
               OR codepoint.value BETWEEN 127 AND 159
               OR codepoint.value = 173
               OR codepoint.value BETWEEN 1536 AND 1541
               OR codepoint.value = 1564
               OR codepoint.value = 1757
               OR codepoint.value = 1807
               OR codepoint.value BETWEEN 2192 AND 2193
               OR codepoint.value = 2274
               OR codepoint.value = 6158
               OR codepoint.value BETWEEN 8203 AND 8207
               OR codepoint.value BETWEEN 8234 AND 8238
               OR codepoint.value BETWEEN 8288 AND 8292
               OR codepoint.value BETWEEN 8294 AND 8303
               OR codepoint.value = 65279
               OR codepoint.value BETWEEN 65529 AND 65531
               OR codepoint.value = 69821
               OR codepoint.value = 69837
               OR codepoint.value BETWEEN 78896 AND 78911
               OR codepoint.value BETWEEN 113824 AND 113827
               OR codepoint.value BETWEEN 119155 AND 119162
               OR codepoint.value = 917505
               OR codepoint.value BETWEEN 917536 AND 917631
       )
$function$;

ALTER FUNCTION iam.organization_public_name_is_canonical_v1(text)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.organization_public_name_is_canonical_v1(text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.organization_public_name_is_canonical_v1(text)
TO iam_app, iam_onboarding, iam_system;

ALTER TABLE iam.organizations
DROP CONSTRAINT ck_organization_public_name;
ALTER TABLE iam.organizations
ADD CONSTRAINT ck_organization_public_name CHECK (
    iam.organization_public_name_is_canonical_v1(public_name::text)
);

-- One current digest may identify at most one command in the six-command
-- ORG_ADMIN family.  Retained-key candidates are also resolved by v3 below,
-- because a raw key has a different digest after a key rotation.
DO $migration$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.command_version = 1
          AND receipt.command_name IN (
              'IssueAccessInvitation','RevokeAccessInvitation',
              'SuspendMembership','ResumeMembership','RevokeMembership',
              'UpdateOrganizationPublicName'
          )
        GROUP BY receipt.principal_kind, receipt.principal_id,
                 receipt.idempotency_key_digest_key_id,
                 receipt.idempotency_key_digest
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'uq_org_admin_raw_idempotency_key_v1',
            MESSAGE = 'IAM42 ORG_ADMIN idempotency baseline is ambiguous';
    END IF;
END
$migration$;

CREATE UNIQUE INDEX uq_org_admin_raw_idempotency_key_v1
ON infra.command_receipts (
    principal_kind,
    principal_id,
    idempotency_key_digest_key_id,
    idempotency_key_digest
)
WHERE principal_kind = 'USER'
  AND command_version = 1
  AND command_name IN (
      'IssueAccessInvitation','RevokeAccessInvitation',
      'SuspendMembership','ResumeMembership','RevokeMembership',
      'UpdateOrganizationPublicName'
  );

ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_organization_public_name_response CHECK (
    command_name <> 'UpdateOrganizationPublicName'
    OR (
        command_version = 1
        AND principal_kind = 'USER'
        AND target_kind = 'Organization'
        AND http_method = 'POST'
        AND if_match_version >= 1
        AND canonical_path = '/v1/organizations/' || target_id::text
            || '/public-name'
        AND reconstruction_metadata IS NULL
        AND current_user_entity_tag IS NULL
        AND (
            (
                status = 'IN_PROGRESS'
                AND response_http_status IS NULL
                AND response_schema_name IS NULL
                AND response_entity_tag IS NULL
            )
            OR (
                status = 'COMPLETED'
                AND response_schema_version = 1
                AND response_http_status = 200
                AND response_schema_name = 'OrganizationSummaryDto'
                AND response_entity_tag ~ '^"v[1-9][0-9]*"$'
                AND safe_response_body->>'organization_id' = target_id::text
                AND safe_response_body->>'entity_tag' = response_entity_tag
                AND safe_response_body->>'aggregate_version'
                    ~ '^[1-9][0-9]*$'
                AND iam.organization_public_name_is_canonical_v1(
                    safe_response_body->>'public_name'
                )
                AND safe_response_body->>'type' IN (
                    'BUSINESS','NONPROFIT','COMMUNITY','CREATOR_TEAM'
                )
                AND safe_response_body->>'status' IN (
                    'PENDING_ADMIN','ACTIVE','SUSPENDED','CLOSED'
                )
            )
        )
    )
);

CREATE FUNCTION iam_api.execute_organization_admin_v3(
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
    exact_issue_hold_snapshot_digest bytea,
    exact_public_name text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    server_now timestamptz := transaction_timestamp();
    old_operations constant text[] := ARRAY[
        'IssueAccessInvitation','RevokeAccessInvitation',
        'SuspendMembership','ResumeMembership','RevokeMembership'
    ];
    all_operations constant text[] := ARRAY[
        'IssueAccessInvitation','RevokeAccessInvitation',
        'SuspendMembership','ResumeMembership','RevokeMembership',
        'UpdateOrganizationPublicName'
    ];
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
    existing infra.command_receipts%ROWTYPE;
    organization_row iam.organizations%ROWTYPE;
    actor_session iam.sessions%ROWTYPE;
    receipt_count integer;
    decision text;
    result jsonb;
    before_version bigint;
    after_version bigint;
    entity_tag text;
    safe_response jsonb;
    event_payload jsonb;
    outbox_event jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR exact_operation <> ALL(all_operations)
       OR exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR exact_organization_id IS NULL
       OR exact_target_id IS NULL
       OR exact_command_id IS NULL
       OR exact_correlation_id IS NULL
       OR exact_causation_id IS DISTINCT FROM exact_command_id
       OR exact_trace_id IS NULL
       OR exact_expected_version < 1
       OR cardinality(exact_idempotency_candidate_key_ids) NOT BETWEEN 1 AND 4
       OR cardinality(exact_idempotency_candidate_digests)
            <> cardinality(exact_idempotency_candidate_key_ids)
       OR cardinality(exact_payload_candidate_key_ids) NOT BETWEEN 1 AND 16
       OR cardinality(exact_payload_candidate_digests)
            <> cardinality(exact_payload_candidate_key_ids)
       OR exact_idempotency_candidate_key_ids[1]
            IS DISTINCT FROM exact_idempotency_key_digest_key_id
       OR exact_idempotency_candidate_digests[1]
            IS DISTINCT FROM exact_idempotency_key_digest
       OR exact_payload_candidate_key_ids[1]
            IS DISTINCT FROM exact_payload_hash_key_id
       OR exact_payload_candidate_digests[1]
            IS DISTINCT FROM exact_payload_hash
       OR NOT iam.text_array_is_unique_nonnull(
            exact_idempotency_candidate_key_ids
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_idempotency_candidate_digests) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_candidate_key_ids) AS item(value)
            WHERE item.value IS NULL OR item.value = ''
       )
       OR EXISTS (
            SELECT 1
            FROM unnest(exact_payload_candidate_digests) AS item(value)
            WHERE octet_length(item.value) <> 32
       )
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'ORGANIZATION_ADMIN'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.target_id', true), '')
            IS DISTINCT FROM exact_target_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.expected_version', true), '')
            IS DISTINCT FROM exact_expected_version::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_organization_admin_v3_exact_context',
            MESSAGE = 'organization administration v3 context is invalid';
    END IF;

    IF exact_operation = ANY(old_operations) THEN
        IF exact_public_name IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_organization_admin_v3_public_name',
                MESSAGE = 'organization administration v3 public name is invalid';
        END IF;

        -- Prove current authority before consulting the cross-operation key
        -- family, so a caller cannot use this boundary as a receipt oracle.
        decision := iam_api.organization_admin_authority_decision_v1(
            exact_actor_user_id, exact_session_id, exact_organization_id, true
        );
        IF decision <> 'AUTHORIZED' THEN
            RETURN jsonb_build_object('decision_code',decision);
        END IF;

        SELECT count(*) INTO receipt_count
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = ANY(all_operations)
          AND receipt.command_version = 1
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_candidate_digests, 1
              ) AS slot(index)
              WHERE exact_idempotency_candidate_key_ids[slot.index]
                        = receipt.idempotency_key_digest_key_id
                AND exact_idempotency_candidate_digests[slot.index]
                        = receipt.idempotency_key_digest
          );
        IF receipt_count > 1 THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        ELSIF receipt_count = 1 THEN
            SELECT receipt.* INTO existing
            FROM infra.command_receipts AS receipt
            WHERE receipt.principal_kind = 'USER'
              AND receipt.principal_id = exact_actor_user_id
              AND receipt.command_name = ANY(all_operations)
              AND receipt.command_version = 1
              AND EXISTS (
                  SELECT 1
                  FROM generate_subscripts(
                      exact_idempotency_candidate_digests, 1
                  ) AS slot(index)
                  WHERE exact_idempotency_candidate_key_ids[slot.index]
                            = receipt.idempotency_key_digest_key_id
                    AND exact_idempotency_candidate_digests[slot.index]
                            = receipt.idempotency_key_digest
              )
            ORDER BY receipt.id
            LIMIT 1;
            IF existing.command_name <> exact_operation THEN
                RETURN jsonb_build_object(
                    'decision_code','IDEMPOTENCY_KEY_REUSED'
                );
            END IF;
        END IF;

        result := iam_api.execute_organization_admin_v2(
            exact_operation, exact_actor_user_id, exact_session_id,
            exact_organization_id, exact_target_id, exact_command_id,
            exact_correlation_id, exact_causation_id, exact_trace_id,
            exact_original_actor_id, exact_expected_version,
            exact_idempotency_key_digest,
            exact_idempotency_key_digest_key_id, exact_payload_hash,
            exact_payload_hash_key_id, exact_retain_until,
            new_audit_event_id, new_outbox_event_id,
            new_secondary_outbox_event_id, new_recipient_contact_id,
            exact_recipient_binding_digest,
            exact_recipient_binding_digest_key_id,
            exact_masked_recipient_label, exact_invitation_expires_at,
            exact_invitation_token_nonce, exact_invitation_token_key_id,
            exact_invitation_token_format_version,
            exact_target_role_or_reason_code, exact_resume_hold_action,
            exact_resume_hold_target_type, exact_resume_hold_target_id,
            exact_resume_hold_target_version,
            exact_resume_hold_organization_id,
            exact_resume_hold_policy_version,
            exact_resume_hold_evaluated_at, exact_resume_hold_valid_until,
            exact_resume_hold_snapshot_digest,
            exact_idempotency_candidate_key_ids,
            exact_idempotency_candidate_digests,
            exact_payload_candidate_key_ids,
            exact_payload_candidate_digests, exact_issue_hold_action,
            exact_issue_hold_target_type, exact_issue_hold_target_id,
            exact_issue_hold_target_version,
            exact_issue_hold_organization_id,
            exact_issue_hold_policy_version,
            exact_issue_hold_evaluated_at, exact_issue_hold_valid_until,
            exact_issue_hold_snapshot_digest
        );

        -- A concurrent command in the enlarged family may have won the new
        -- unique index while v2 returned its closed retry signal.
        IF result->>'decision_code' = 'SERVICE_UNAVAILABLE' THEN
            SELECT count(*) INTO receipt_count
            FROM infra.command_receipts AS receipt
            WHERE receipt.principal_kind = 'USER'
              AND receipt.principal_id = exact_actor_user_id
              AND receipt.command_name = ANY(all_operations)
              AND receipt.command_version = 1
              AND EXISTS (
                  SELECT 1
                  FROM generate_subscripts(
                      exact_idempotency_candidate_digests, 1
                  ) AS slot(index)
                  WHERE exact_idempotency_candidate_key_ids[slot.index]
                            = receipt.idempotency_key_digest_key_id
                    AND exact_idempotency_candidate_digests[slot.index]
                            = receipt.idempotency_key_digest
              );
            IF receipt_count = 1 THEN
                SELECT receipt.* INTO existing
                FROM infra.command_receipts AS receipt
                WHERE receipt.principal_kind = 'USER'
                  AND receipt.principal_id = exact_actor_user_id
                  AND receipt.command_name = ANY(all_operations)
                  AND receipt.command_version = 1
                  AND EXISTS (
                      SELECT 1
                      FROM generate_subscripts(
                          exact_idempotency_candidate_digests, 1
                      ) AS slot(index)
                      WHERE exact_idempotency_candidate_key_ids[slot.index]
                                = receipt.idempotency_key_digest_key_id
                        AND exact_idempotency_candidate_digests[slot.index]
                                = receipt.idempotency_key_digest
                  )
                ORDER BY receipt.id
                LIMIT 1;
                IF existing.command_name <> exact_operation THEN
                    RETURN jsonb_build_object(
                        'decision_code','IDEMPOTENCY_KEY_REUSED'
                    );
                END IF;
            END IF;
        END IF;
        RETURN result;
    END IF;

    -- New command: every field owned by the old five operations is closed.
    IF exact_target_id <> exact_organization_id
       OR NOT iam.organization_public_name_is_canonical_v1(exact_public_name)
       OR exact_target_role_or_reason_code <> 'PUBLIC_NAME_CORRECTION'
       OR new_secondary_outbox_event_id IS NOT NULL
       OR new_recipient_contact_id IS NOT NULL
       OR exact_recipient_binding_digest IS NOT NULL
       OR exact_recipient_binding_digest_key_id IS NOT NULL
       OR exact_masked_recipient_label IS NOT NULL
       OR exact_invitation_expires_at IS NOT NULL
       OR exact_invitation_token_nonce IS NOT NULL
       OR exact_invitation_token_key_id IS NOT NULL
       OR exact_invitation_token_format_version IS NOT NULL
       OR exact_resume_hold_action IS NOT NULL
       OR exact_resume_hold_target_type IS NOT NULL
       OR exact_resume_hold_target_id IS NOT NULL
       OR exact_resume_hold_target_version IS NOT NULL
       OR exact_resume_hold_organization_id IS NOT NULL
       OR exact_resume_hold_policy_version IS NOT NULL
       OR exact_resume_hold_evaluated_at IS NOT NULL
       OR exact_resume_hold_valid_until IS NOT NULL
       OR exact_resume_hold_snapshot_digest IS NOT NULL
       OR exact_issue_hold_action IS NOT NULL
       OR exact_issue_hold_target_type IS NOT NULL
       OR exact_issue_hold_target_id IS NOT NULL
       OR exact_issue_hold_target_version IS NOT NULL
       OR exact_issue_hold_organization_id IS NOT NULL
       OR exact_issue_hold_policy_version IS NOT NULL
       OR exact_issue_hold_evaluated_at IS NOT NULL
       OR exact_issue_hold_valid_until IS NOT NULL
       OR exact_issue_hold_snapshot_digest IS NOT NULL
       OR new_audit_event_id IS NULL
       OR new_outbox_event_id IS NULL
       OR new_audit_event_id IN (exact_command_id,new_outbox_event_id)
       OR new_outbox_event_id = exact_command_id
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR exact_retain_until <= server_now THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key
    FOR UPDATE;
    IF NOT FOUND
       OR key_policy.active_canonicalization_version
            <> 'restricted-canonical-json-v1'
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_idempotency_candidate_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_idempotency_key_ids) AS item(value)
          )
       OR (
            SELECT array_agg(DISTINCT item.value ORDER BY item.value)
            FROM unnest(exact_payload_candidate_key_ids) AS item(value)
          ) IS DISTINCT FROM (
            SELECT array_agg(item.value::text ORDER BY item.value::text)
            FROM unnest(key_policy.retained_payload_hash_key_ids) AS item(value)
          ) THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    -- Match v1's organization write lock order to avoid introducing a new
    -- deadlock edge with the original five commands.
    SELECT * INTO organization_row
    FROM iam.organizations
    WHERE id = exact_organization_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('decision_code','RESOURCE_NOT_FOUND');
    END IF;
    PERFORM id FROM iam.memberships
    WHERE organization_id = exact_organization_id
    ORDER BY id FOR UPDATE;
    PERFORM id FROM iam.membership_role_grants
    WHERE organization_id = exact_organization_id
    ORDER BY id FOR UPDATE;
    SELECT * INTO actor_session
    FROM iam.sessions
    WHERE id = exact_session_id AND user_id = exact_actor_user_id
    FOR UPDATE;
    PERFORM id FROM iam.session_families
    WHERE id = actor_session.family_id AND user_id = exact_actor_user_id
    FOR UPDATE;
    PERFORM id FROM iam.users
    WHERE id = exact_actor_user_id
    FOR UPDATE;
    decision := iam_api.organization_admin_authority_decision_v1(
        exact_actor_user_id, exact_session_id, exact_organization_id, true
    );
    IF decision <> 'AUTHORIZED' THEN
        RETURN jsonb_build_object('decision_code',decision);
    END IF;

    SELECT count(*) INTO receipt_count
    FROM infra.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.command_name = ANY(all_operations)
      AND receipt.command_version = 1
      AND EXISTS (
          SELECT 1
          FROM generate_subscripts(
              exact_idempotency_candidate_digests, 1
          ) AS slot(index)
          WHERE exact_idempotency_candidate_key_ids[slot.index]
                    = receipt.idempotency_key_digest_key_id
            AND exact_idempotency_candidate_digests[slot.index]
                    = receipt.idempotency_key_digest
      );
    IF receipt_count > 1 THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    ELSIF receipt_count = 1 THEN
        SELECT receipt.* INTO existing
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.command_name = ANY(all_operations)
          AND receipt.command_version = 1
          AND EXISTS (
              SELECT 1
              FROM generate_subscripts(
                  exact_idempotency_candidate_digests, 1
              ) AS slot(index)
              WHERE exact_idempotency_candidate_key_ids[slot.index]
                        = receipt.idempotency_key_digest_key_id
                AND exact_idempotency_candidate_digests[slot.index]
                        = receipt.idempotency_key_digest
          )
        ORDER BY receipt.id
        LIMIT 1
        FOR UPDATE;
        IF existing.command_name <> exact_operation
           OR existing.if_match_version <> exact_expected_version
           OR NOT EXISTS (
                SELECT 1
                FROM generate_subscripts(
                    exact_payload_candidate_digests, 1
                ) AS slot(index)
                WHERE exact_payload_candidate_key_ids[slot.index]
                          = existing.payload_hash_key_id
                  AND exact_payload_candidate_digests[slot.index]
                          = existing.payload_hash
           ) THEN
            RETURN jsonb_build_object(
                'decision_code','IDEMPOTENCY_KEY_REUSED'
            );
        END IF;
        IF existing.status = 'IN_PROGRESS' THEN
            RETURN jsonb_build_object('decision_code','COMMAND_IN_PROGRESS');
        END IF;
        IF existing.status <> 'COMPLETED'
           OR existing.retain_until <= server_now
           OR existing.target_kind <> 'Organization'
           OR existing.target_id <> exact_organization_id
           OR existing.http_method <> 'POST'
           OR existing.canonical_path <> '/v1/organizations/'
                || exact_organization_id::text || '/public-name'
           OR existing.response_schema_version <> 1
           OR existing.response_schema_name <> 'OrganizationSummaryDto'
           OR existing.response_http_status <> 200
           OR existing.reconstruction_metadata IS NOT NULL
           OR existing.safe_response_body IS NULL
           OR existing.safe_response_body->>'organization_id'
                <> exact_organization_id::text
           OR existing.safe_response_body->>'entity_tag'
                <> existing.response_entity_tag THEN
            RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
        END IF;
        RETURN jsonb_build_object(
            'decision_code','AUTHORIZED','replayed',true,
            'safe_response',existing.safe_response_body,
            'response_entity_tag',existing.response_entity_tag,
            'outbox_event',NULL,
            'capability_reconstruction',NULL
        );
    END IF;

    IF exact_idempotency_key_digest_key_id
            <> key_policy.active_idempotency_key_id
       OR exact_payload_hash_key_id <> key_policy.active_payload_hash_key_id THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
    END IF;

    IF organization_row.aggregate_version <> exact_expected_version THEN
        RETURN jsonb_build_object(
            'decision_code','PRECONDITION_FAILED',
            'current_entity_tag',
            '"v' || organization_row.aggregate_version::text || '"'
        );
    END IF;
    IF organization_row.public_name = exact_public_name THEN
        RETURN jsonb_build_object(
            'decision_code','INVALID_STATE_TRANSITION'
        );
    END IF;

    before_version := organization_row.aggregate_version;
    after_version := before_version + 1;
    entity_tag := '"v' || after_version::text || '"';
    UPDATE iam.organizations
    SET public_name = exact_public_name,
        aggregate_version = after_version,
        updated_at = server_now
    WHERE id = exact_organization_id;

    safe_response := jsonb_build_object(
        'organization_id',exact_organization_id::text,
        'public_name',exact_public_name,
        'type',organization_row.organization_type,
        'status',organization_row.status,
        'aggregate_version',after_version,
        'entity_tag',entity_tag
    );
    event_payload := jsonb_build_object(
        'organization_id',exact_organization_id::text
    );

    INSERT INTO infra.command_receipts (
        id,principal_kind,principal_id,command_name,command_version,
        idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,
        payload_hash_key_id,canonicalization_version,target_kind,target_id,
        http_method,canonical_path,if_match_version,status,
        response_schema_version,safe_response_body,reconstruction_metadata,
        created_at,retain_until,completed_at,response_http_status,
        response_schema_name,response_entity_tag,current_user_entity_tag
    ) VALUES (
        exact_command_id,'USER',exact_actor_user_id,exact_operation,1,
        exact_idempotency_key_digest,exact_idempotency_key_digest_key_id,
        exact_payload_hash,exact_payload_hash_key_id,
        'restricted-canonical-json-v1','Organization',
        exact_organization_id,'POST','/v1/organizations/'
            || exact_organization_id::text || '/public-name',
        exact_expected_version,'IN_PROGRESS',NULL,NULL,NULL,
        server_now,exact_retain_until,NULL,NULL,NULL,NULL,NULL
    );

    INSERT INTO audit.audit_events (
        event_id,occurred_at,actor_kind,actor_id,original_actor_id,
        action_code,target_kind,target_id,organization_id,before_status,
        after_status,before_version,after_version,role_code,purpose_code,
        reason_code,auth_strength_code,result_code,command_id,correlation_id,
        causation_id,trace_id,safe_attributes
    ) VALUES (
        new_audit_event_id,server_now,'USER',exact_actor_user_id,
        exact_original_actor_id,exact_operation,'Organization',
        exact_organization_id,exact_organization_id,
        organization_row.status,organization_row.status,before_version,
        after_version,NULL,NULL,'PUBLIC_NAME_CORRECTION',
        actor_session.acr_code,'SUCCEEDED',exact_command_id,
        exact_correlation_id,exact_causation_id,exact_trace_id,'{}'::jsonb
    );

    outbox_event := jsonb_build_object(
        'event_id',new_outbox_event_id::text,
        'event_type','OrganizationPublicNameChanged',
        'schema_version',1,
        'occurred_at',iam_api.rfc3339_utc_v1(server_now),
        'aggregate_type','Organization',
        'aggregate_id',exact_organization_id::text,
        'aggregate_version',after_version,
        'actor_kind','USER','actor_id',exact_actor_user_id::text,
        'original_actor_id',exact_original_actor_id,
        'correlation_id',exact_correlation_id::text,
        'causation_id',exact_causation_id::text,
        'trace_id',exact_trace_id::text,
        'organization_id',exact_organization_id::text,
        'payload',event_payload
    );
    INSERT INTO infra.outbox_events (
        event_id,event_type,schema_version,occurred_at,aggregate_type,
        aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,
        correlation_id,causation_id,trace_id,organization_id,payload,
        delivery_status,attempt_count,available_at,lease_owner,lease_until,
        published_at,last_error_code,created_at
    ) VALUES (
        new_outbox_event_id,'OrganizationPublicNameChanged',1,server_now,
        'Organization',exact_organization_id,after_version,'USER',
        exact_actor_user_id,exact_original_actor_id,exact_correlation_id,
        exact_causation_id,exact_trace_id,exact_organization_id,event_payload,
        'PENDING',0,server_now,NULL,NULL,NULL,NULL,server_now
    );

    UPDATE infra.command_receipts
    SET status='COMPLETED',response_schema_version=1,
        safe_response_body=safe_response,reconstruction_metadata=NULL,
        completed_at=server_now,response_http_status=200,
        response_schema_name='OrganizationSummaryDto',
        response_entity_tag=entity_tag,current_user_entity_tag=NULL
    WHERE id=exact_command_id;

    RETURN jsonb_build_object(
        'decision_code','AUTHORIZED','replayed',false,
        'safe_response',safe_response,
        'response_entity_tag',entity_tag,
        'outbox_event',outbox_event,
        'secondary_outbox_event',NULL,
        'capability_reconstruction',NULL
    );
EXCEPTION
    WHEN unique_violation THEN
        RETURN jsonb_build_object('decision_code','SERVICE_UNAVAILABLE');
END
$function$;

ALTER FUNCTION iam_api.execute_organization_admin_v3(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea,text
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.execute_organization_admin_v3(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea,text
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION iam_api.execute_organization_admin_v2(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea
) FROM iam_app;
GRANT EXECUTE ON FUNCTION iam_api.execute_organization_admin_v3(
    text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,
    bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,
    bytea,text,text,text,text,text,uuid,bigint,uuid,text,timestamptz,
    timestamptz,bytea,text[],bytea[],text[],bytea[],text,text,uuid,
    bigint,uuid,text,timestamptz,timestamptz,bytea,text
) TO iam_app;

-- Bootstrap v5 verifies historical default public names.  v6 preserves that
-- reviewed graph proof while making the compatibility substitution private,
-- same-version, and transaction-local; the legal current name is restored
-- before any result leaves this program.
CREATE FUNCTION iam.enforce_organization_transition_v2()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    -- Keep the bootstrap-only helper in a separately compiled branch.  The
    -- ordinary invoker roles must never need EXECUTE on that private helper
    -- merely to run the shared organization transition trigger.
    IF session_user = 'iam_sandbox_bootstrap'
       AND current_user = 'schema_owner' THEN
        IF iam.internal_sandbox_bootstrap_context_v1()
           AND NULLIF(current_setting(
                'app.bootstrap_public_name_compat', true
           ), '') = 'IAM42'
           AND NEW.public_name IS DISTINCT FROM OLD.public_name
           AND (to_jsonb(NEW) - 'public_name')
                IS NOT DISTINCT FROM (to_jsonb(OLD) - 'public_name')
           AND iam.organization_public_name_is_canonical_v1(NEW.public_name) THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'PENDING_ADMIN'
            AND NEW.status NOT IN ('ACTIVE', 'CLOSED'))
       OR (OLD.status = 'ACTIVE'
            AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
       OR (OLD.status = 'SUSPENDED'
            AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'CLOSED'))
       OR (OLD.status = 'CLOSED' AND NEW.status <> 'CLOSED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_organization_state_transition',
            MESSAGE = 'invalid organization state transition';
    END IF;
    RETURN NEW;
END
$function$;

ALTER FUNCTION iam.enforce_organization_transition_v2()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.enforce_organization_transition_v2() FROM PUBLIC;
DROP TRIGGER trg_organization_state_transition ON iam.organizations;
CREATE TRIGGER trg_organization_state_transition
BEFORE UPDATE ON iam.organizations
FOR EACH ROW EXECUTE FUNCTION iam.enforce_organization_transition_v2();

CREATE FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v6(
    exact_action text,
    exact_canonical_manifest bytea,
    exact_manifest_sha256 bytea,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_system_actor_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_bootstrap_id uuid
)
RETURNS TABLE(outcome text, revision integer, account_count integer)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    manifest_document jsonb;
    saved_names jsonb := '[]'::jsonb;
    base_outcome text;
    base_revision integer;
    base_account_count integer;
BEGIN
    IF exact_action NOT IN ('APPLY', 'VERIFY', 'REVOKE_ACCESS')
       OR exact_canonical_manifest IS NULL
       OR octet_length(exact_canonical_manifest) NOT BETWEEN 1 AND 131072
       OR exact_manifest_sha256 IS NULL
       OR octet_length(exact_manifest_sha256) <> 32
       OR sha256(exact_canonical_manifest) <> exact_manifest_sha256
       OR exact_command_id IS NULL OR exact_command_id = zero_uuid
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_audit_event_id IS NULL OR exact_audit_event_id = zero_uuid
       OR exact_system_actor_id IS NULL OR exact_system_actor_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_bootstrap_id IS NULL OR exact_bootstrap_id = zero_uuid
       OR session_user IS DISTINCT FROM 'iam_sandbox_bootstrap'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.internal_sandbox_bootstrap_context_v1()
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_action
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.manifest_sha256', true), '')
            IS DISTINCT FROM encode(exact_manifest_sha256, 'hex')
       OR NULLIF(current_setting(
            'app.bootstrap_role_isolation_transition', true
       ), '') IS NOT NULL
       OR NULLIF(current_setting(
            'app.bootstrap_public_name_compat', true
       ), '') IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_internal_sandbox_identity_bootstrap_v6_invocation',
            MESSAGE = 'internal sandbox identity bootstrap v6 invocation invalid';
    END IF;

    BEGIN
        manifest_document := convert_from(
            exact_canonical_manifest, 'UTF8'
        )::jsonb;
        IF NOT iam.internal_sandbox_manifest_v5_valid(
            manifest_document, exact_bootstrap_id
        ) THEN
            RAISE EXCEPTION 'closed manifest rejected';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_identity_bootstrap_v6_manifest',
            MESSAGE = 'internal sandbox identity bootstrap v6 manifest invalid';
    END;

    -- Serialize before the compatibility writes, then let v5 take the same
    -- transaction lock reentrantly.
    PERFORM pg_advisory_xact_lock(1229016369, 36);
    WITH desired_names AS (
        SELECT
            (item.value#>>'{demand_owner_grant,organization_id}')::uuid
                AS organization_id,
            'Sandbox Organization ' || (item.value->>'account_code')
                AS default_name
        FROM jsonb_array_elements(
            manifest_document->'accounts'
        ) AS item(value)
        WHERE jsonb_typeof(item.value->'demand_owner_grant') = 'object'
        UNION ALL
        SELECT
            iam.internal_sandbox_derived_uuid_v2(
                'org-admin-bootstrap-organization',
                (item.value#>>'{organization_grant,membership_id}')::uuid
            ),
            'Sandbox Organization ' || (item.value->>'account_code')
        FROM jsonb_array_elements(
            manifest_document->'accounts'
        ) AS item(value)
        WHERE item.value->>'account_code' = 'org_admin_01'
          AND jsonb_typeof(item.value->'organization_grant') = 'object'
    )
    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'organization_id',organization.id::text,
                'public_name',organization.public_name,
                'default_name',desired.default_name
            )
            ORDER BY organization.id
        ),
        '[]'::jsonb
    ) INTO saved_names
    FROM desired_names AS desired
    JOIN iam.organizations AS organization
      ON organization.id = desired.organization_id;

    PERFORM set_config('app.bootstrap_public_name_compat', 'IAM42', true);
    UPDATE iam.organizations AS organization
    SET public_name = item.value->>'default_name'
    FROM jsonb_array_elements(saved_names) AS item(value)
    WHERE organization.id = (item.value->>'organization_id')::uuid
      AND organization.public_name IS DISTINCT FROM
            item.value->>'default_name';

    SELECT base.outcome, base.revision, base.account_count
    INTO base_outcome, base_revision, base_account_count
    FROM iam_api.manage_internal_sandbox_identity_bootstrap_v5(
        exact_action, exact_canonical_manifest, exact_manifest_sha256,
        exact_command_id, exact_receipt_id, exact_audit_event_id,
        exact_system_actor_id, exact_correlation_id, exact_trace_id,
        exact_bootstrap_id
    ) AS base;

    UPDATE iam.organizations AS organization
    SET public_name = item.value->>'public_name'
    FROM jsonb_array_elements(saved_names) AS item(value)
    WHERE organization.id = (item.value->>'organization_id')::uuid
      AND organization.public_name IS DISTINCT FROM
            item.value->>'public_name';

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(saved_names) AS item(value)
        LEFT JOIN iam.organizations AS organization
          ON organization.id = (item.value->>'organization_id')::uuid
        WHERE organization.id IS NULL
           OR organization.public_name IS DISTINCT FROM
                item.value->>'public_name'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_identity_bootstrap_v6_restore',
            MESSAGE = 'internal sandbox public names were not restored';
    END IF;

    PERFORM set_config('app.bootstrap_public_name_compat', '', true);
    IF base_revision <> (manifest_document->>'revision')::integer
       OR base_account_count <> 10
       OR base_outcome NOT IN (
            'APPLIED','ROTATED','REPLAYED','VERIFIED',
            'REVOKED','ALREADY_REVOKED'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_identity_bootstrap_v6_result',
            MESSAGE = 'internal sandbox identity bootstrap v6 result invalid';
    END IF;
    RETURN QUERY SELECT base_outcome, base_revision, base_account_count;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.bootstrap_public_name_compat', '', true);
    RAISE;
END
$function$;

ALTER FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v6(
    text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v6(
    text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v5(
    text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid
) FROM iam_sandbox_bootstrap;
GRANT EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v6(
    text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid
) TO iam_sandbox_bootstrap;
