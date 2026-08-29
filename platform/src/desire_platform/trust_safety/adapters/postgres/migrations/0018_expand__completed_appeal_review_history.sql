-- Actor-bound, party-safe history and terminal detail for Appeal Reviewers.

SET LOCAL search_path = pg_catalog, trust;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'trust_migration_runner'
       OR current_user IS DISTINCT FROM 'trust_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'TRUST_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

DO $trust17_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 17
                AND min_app_compatible_version = 17
                AND max_app_compatible_version = 17
                AND required_iam_schema_version = 42
                AND required_demand_schema_version = 12
                AND required_iam_contract_sha256 = decode(
                    'f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    '379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    '6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2',
                    'hex'
                )
                AND event_contract_sha256 = decode(
                    'a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582',
                    'hex'
                )
                AND report_contract_sha256 = decode(
                    '29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278',
                    'hex'
                )
                AND triage_contract_sha256 = decode(
                    'de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084',
                    'hex'
                )
                AND appeal_api_contract_sha256 = decode(
                    '2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522',
                    'hex'
                )
                AND appeal_event_contract_sha256 = decode(
                    '7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba',
                    'hex'
                )
                AND appeal_application_contract_sha256 = decode(
                    '3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223',
                    'hex'
                )
                AND appeal_review_contract_sha256 = decode(
                    '08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b',
                    'hex'
                )
                AND combined_contract_sha256 = decode(
                    'a1ec68f0d0e6685e0cbe842a6bd951f60f334682d26bec549ef9858c81f23d67',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '57c0dd42e18bf3afa7233f9ad673ec3805b325166436a4a1e3021466cd62381f',
                    'hex'
                )
                AND generated_at IS NOT NULL
            ),
            true
        )
    INTO STRICT contract_count, contract_is_exact
    FROM trust_meta.schema_contracts;

    IF contract_count NOT BETWEEN 0 AND 1
       OR (contract_count = 1 AND contract_is_exact IS NOT TRUE)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST17_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust17_contract_baseline$;

CREATE POLICY rls_trust_my_completed_appeal_assignments_select_v1
ON trust.appeal_review_assignments
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '') IN (
        'APPEAL_COMPLETED_HISTORY_READ',
        'APPEAL_COMPLETED_DETAIL_READ'
    )
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_trust_my_completed_appeal_roots_select_v1
ON trust.appeals
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '') IN (
        'APPEAL_COMPLETED_HISTORY_READ',
        'APPEAL_COMPLETED_DETAIL_READ'
    )
    AND status = 'DECIDED'
    AND decision_version_id IS NOT NULL
    AND current_assignment_id IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM trust.appeal_review_assignments AS assignment
        WHERE assignment.appeal_id = appeals.appeal_id
          AND assignment.assignment_id = appeals.current_assignment_id
          AND assignment.reviewer_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_trust_my_completed_appeal_decisions_select_v1
ON trust.appeal_decision_versions
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '') IN (
        'APPEAL_COMPLETED_HISTORY_READ',
        'APPEAL_COMPLETED_DETAIL_READ'
    )
    AND decided_by_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM trust.appeal_review_assignments AS assignment
        WHERE assignment.appeal_id = appeal_decision_versions.appeal_id
          AND assignment.assignment_id
                = appeal_decision_versions.source_assignment_id
          AND assignment.reviewer_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_trust_my_completed_appeal_applications_select_v1
ON trust.appeal_application_versions
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '') IN (
        'APPEAL_COMPLETED_HISTORY_READ',
        'APPEAL_COMPLETED_DETAIL_READ'
    )
    AND EXISTS (
        SELECT 1
        FROM trust.appeal_decision_versions AS decision
        JOIN trust.appeal_review_assignments AS assignment
          ON assignment.appeal_id = decision.appeal_id
         AND assignment.assignment_id = decision.source_assignment_id
        WHERE decision.appeal_id = appeal_application_versions.appeal_id
          AND decision.source_application_version
                = appeal_application_versions.application_version
          AND decision.decided_by_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
          AND assignment.reviewer_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE POLICY rls_trust_my_completed_appeal_review_drafts_select_v1
ON trust.appeal_review_drafts
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '') IN (
        'APPEAL_COMPLETED_HISTORY_READ',
        'APPEAL_COMPLETED_DETAIL_READ'
    )
    AND edited_by_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND sealed_review_note_purpose_code = 'APPEAL_REVIEW_NOTE'
    AND btrim(sealed_review_note_reference) <> ''
    AND octet_length(sealed_review_note_sha256) = 32
    AND EXISTS (
        SELECT 1
        FROM trust.appeal_decision_versions AS decision
        JOIN trust.appeal_review_assignments AS assignment
          ON assignment.appeal_id = decision.appeal_id
         AND assignment.assignment_id = decision.source_assignment_id
        WHERE decision.appeal_id = appeal_review_drafts.appeal_id
          AND decision.source_assignment_id
                = appeal_review_drafts.assignment_id
          AND decision.source_review_draft_version
                = appeal_review_drafts.draft_version
          AND decision.decided_by_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
          AND assignment.reviewer_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
    )
);

CREATE FUNCTION trust_api.list_my_completed_appeal_reviews_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_limit integer
)
RETURNS TABLE (projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    authority record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_limit IS NULL
       OR exact_limit NOT BETWEEN 1 AND 100
    THEN
        RETURN;
    END IF;

    SELECT resolved.*
    INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'READ_ASSIGNED_APPEAL'
    ) AS resolved;

    PERFORM set_config(
        'app.appeal_scope_kind',
        'APPEAL_COMPLETED_HISTORY_READ',
        true
    );
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', '', true);

    RETURN QUERY
    WITH bounded_rows AS MATERIALIZED (
        SELECT
            root.aggregate_version,
            decision.appeal_id,
            decision.decided_at,
            jsonb_build_object(
                'appeal_id', decision.appeal_id,
                'decided_at', decision.decided_at,
                'decision_code', decision.decision_code
            ) AS item
        FROM trust.appeal_decision_versions AS decision
        JOIN trust.appeals AS root
          ON root.appeal_id = decision.appeal_id
         AND root.decision_version_id = decision.decision_version_id
        JOIN trust.appeal_review_assignments AS assignment
          ON assignment.appeal_id = decision.appeal_id
         AND assignment.assignment_id = decision.source_assignment_id
        JOIN trust.appeal_review_drafts AS review
          ON review.appeal_id = decision.appeal_id
         AND review.assignment_id = decision.source_assignment_id
         AND review.draft_version = decision.source_review_draft_version
        WHERE root.status = 'DECIDED'
          AND root.current_assignment_id = decision.source_assignment_id
          AND decision.decided_by_user_id = exact_actor_user_id
          AND assignment.reviewer_user_id = exact_actor_user_id
          AND review.edited_by_user_id = exact_actor_user_id
          AND review.sealed_review_note_purpose_code = 'APPEAL_REVIEW_NOTE'
          AND btrim(review.sealed_review_note_reference) <> ''
          AND octet_length(review.sealed_review_note_sha256) = 32
        ORDER BY decision.decided_at DESC, decision.appeal_id DESC
        LIMIT exact_limit + 1
    ), returned_rows AS MATERIALIZED (
        SELECT aggregate_version, appeal_id, decided_at, item
        FROM bounded_rows
        ORDER BY decided_at DESC, appeal_id DESC
        LIMIT exact_limit
    ), document AS (
        SELECT
            COALESCE(
                (
                    SELECT jsonb_agg(
                        item ORDER BY decided_at DESC, appeal_id DESC
                    )
                    FROM returned_rows
                ),
                '[]'::jsonb
            ) AS items,
            (SELECT count(*) > exact_limit FROM bounded_rows) AS has_more,
            COALESCE(
                (SELECT max(aggregate_version) FROM bounded_rows),
                1
            )::bigint AS collection_version
    )
    SELECT jsonb_build_object(
        'entity_tag', format(
            '"appeal-%s-%s"',
            document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:my-completed-appeal-reviews:v1' || E'\x1f'
                    || document.has_more::text || E'\x1f'
                    || document.items::text,
                'UTF8'
            )), 'hex'), 24)
        ),
        'has_more', document.has_more,
        'items', document.items
    )
    FROM document;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN
        RETURN;
END
$function$;

CREATE FUNCTION trust_api.read_my_completed_appeal_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_appeal_id uuid
)
RETURNS TABLE (projection jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    authority record;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_appeal_id IS NULL
       OR exact_appeal_id = zero_uuid
    THEN
        RETURN;
    END IF;

    SELECT resolved.*
    INTO STRICT authority
    FROM trust.resolve_appeal_reviewer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'READ_ASSIGNED_APPEAL'
    ) AS resolved;

    PERFORM set_config(
        'app.appeal_scope_kind',
        'APPEAL_COMPLETED_DETAIL_READ',
        true
    );
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', exact_appeal_id::text, true);

    RETURN QUERY
    SELECT jsonb_build_object(
        'appeal_id', root.appeal_id,
        'application', jsonb_build_object(
            'grounds', to_jsonb(application.grounds),
            'new_evidence_reference_ids',
                to_jsonb(application.new_evidence_reference_ids),
            'requested_outcome', application.requested_outcome,
            'statement_recorded', true,
            'submitted_at', application.submitted_at
        ),
        'decision', jsonb_build_object(
            'assessments', decision.assessments,
            'decided_at', decision.decided_at,
            'decision_code', decision.decision_code,
            'decision_sha256', encode(decision.decision_sha256, 'hex'),
            'decision_version_id', decision.decision_version_id,
            'policy_version', decision.policy_version,
            'reason_codes', to_jsonb(decision.reason_codes),
            'remedy_delta_codes', to_jsonb(decision.remedy_delta_codes)
        ),
        'entity_tag', trust.appeal_entity_tag_v1(
            root.appeal_id,
            root.aggregate_version,
            root.status,
            root.updated_at
        ),
        'review_note_recorded', true,
        'status', root.status
    )
    FROM trust.appeals AS root
    JOIN trust.appeal_decision_versions AS decision
      ON decision.appeal_id = root.appeal_id
     AND decision.decision_version_id = root.decision_version_id
    JOIN trust.appeal_review_assignments AS assignment
      ON assignment.appeal_id = decision.appeal_id
     AND assignment.assignment_id = decision.source_assignment_id
    JOIN trust.appeal_application_versions AS application
      ON application.appeal_id = decision.appeal_id
     AND application.application_version
            = decision.source_application_version
    JOIN trust.appeal_review_drafts AS review
      ON review.appeal_id = decision.appeal_id
     AND review.assignment_id = decision.source_assignment_id
     AND review.draft_version = decision.source_review_draft_version
    WHERE root.appeal_id = exact_appeal_id
      AND root.status = 'DECIDED'
      AND root.current_assignment_id = decision.source_assignment_id
      AND decision.decided_by_user_id = exact_actor_user_id
      AND assignment.reviewer_user_id = exact_actor_user_id
      AND review.edited_by_user_id = exact_actor_user_id
      AND review.sealed_review_note_purpose_code = 'APPEAL_REVIEW_NOTE'
      AND btrim(review.sealed_review_note_reference) <> ''
      AND octet_length(review.sealed_review_note_sha256) = 32;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN
        RETURN;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.list_my_completed_appeal_reviews_v1(
    uuid, uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_my_completed_appeal_reviews_v1(
    uuid, uuid, integer
) TO trust_appeal;

REVOKE ALL ON FUNCTION trust_api.read_my_completed_appeal_review_v1(
    uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_my_completed_appeal_review_v1(
    uuid, uuid, uuid
) TO trust_appeal;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 18
    AND min_app_compatible_version = 18
    AND max_app_compatible_version = 18
    AND required_iam_schema_version = 42
    AND required_demand_schema_version = 12
),
ADD CONSTRAINT ck_trust_schema_contract_hashes CHECK (
    octet_length(required_iam_contract_sha256) = 32
    AND octet_length(required_demand_contract_sha256) = 32
    AND octet_length(api_contract_sha256) = 32
    AND octet_length(event_contract_sha256) = 32
    AND octet_length(report_contract_sha256) = 32
    AND octet_length(triage_contract_sha256) = 32
    AND octet_length(appeal_api_contract_sha256) = 32
    AND octet_length(appeal_event_contract_sha256) = 32
    AND octet_length(appeal_application_contract_sha256) = 32
    AND octet_length(appeal_review_contract_sha256) = 32
    AND octet_length(combined_contract_sha256) = 32
    AND octet_length(migration_manifest_sha256) = 32
    AND required_iam_contract_sha256 = decode(
        'f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        '379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816',
        'hex'
    )
    AND api_contract_sha256 = decode(
        '6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2',
        'hex'
    )
    AND event_contract_sha256 = decode(
        'a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582',
        'hex'
    )
    AND report_contract_sha256 = decode(
        '29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278',
        'hex'
    )
    AND triage_contract_sha256 = decode(
        'de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084',
        'hex'
    )
    AND appeal_api_contract_sha256 = decode(
        'ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46',
        'hex'
    )
    AND appeal_event_contract_sha256 = decode(
        '7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba',
        'hex'
    )
    AND appeal_application_contract_sha256 = decode(
        '3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223',
        'hex'
    )
    AND appeal_review_contract_sha256 = decode(
        '08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b',
        'hex'
    )
    AND combined_contract_sha256 = sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:trust:combined-contract:v2',
        encode(required_iam_contract_sha256, 'hex'),
        encode(required_demand_contract_sha256, 'hex'),
        encode(api_contract_sha256, 'hex'),
        encode(event_contract_sha256, 'hex'),
        encode(report_contract_sha256, 'hex'),
        encode(triage_contract_sha256, 'hex'),
        encode(appeal_api_contract_sha256, 'hex'),
        encode(appeal_event_contract_sha256, 'hex'),
        encode(appeal_application_contract_sha256, 'hex'),
        encode(appeal_review_contract_sha256, 'hex'),
        encode(migration_manifest_sha256, 'hex')
    ), 'UTF8'))
);
