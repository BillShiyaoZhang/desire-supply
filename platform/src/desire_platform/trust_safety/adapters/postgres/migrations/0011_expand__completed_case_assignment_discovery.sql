-- Actor-bound, party-safe discovery of Trust cases completed by this officer.

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

DO $trust10_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 10
                AND min_app_compatible_version = 10
                AND max_app_compatible_version = 10
                AND required_iam_schema_version = 38
                AND required_demand_schema_version = 11
                AND required_iam_contract_sha256 = decode(
                    '908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    'cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    'a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25',
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
                    '364f22de931a0d3df11fedcdb20f3eaf84690a6649e99c9683af39b86547b93e',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    'd01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683',
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
            MESSAGE = 'TRUST10_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust10_contract_baseline$;

CREATE POLICY rls_trust_my_completed_case_assignments_select_v1
ON trust.case_assignments
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_COMPLETED_ASSIGNMENTS_READ'
    AND officer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND assignment_purpose_code = 'CASE_TRIAGE'
    AND hold_id IS NULL
);

CREATE POLICY rls_trust_my_completed_case_roots_select_v1
ON trust.cases
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_COMPLETED_ASSIGNMENTS_READ'
    AND status = 'DECIDED'
    AND outcome_version_id IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM trust.case_assignments AS assignment
        WHERE assignment.case_id = cases.case_id
          AND assignment.assignment_id = cases.assignment_id
          AND assignment.officer_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
          AND assignment.assignment_purpose_code = 'CASE_TRIAGE'
          AND assignment.hold_id IS NULL
    )
);

CREATE POLICY rls_trust_my_completed_case_outcomes_select_v1
ON trust.case_outcome_versions
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_COMPLETED_ASSIGNMENTS_READ'
    AND decided_by_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND EXISTS (
        SELECT 1
        FROM trust.case_assignments AS assignment
        WHERE assignment.case_id = case_outcome_versions.case_id
          AND assignment.assignment_id
                = case_outcome_versions.decision_assignment_id
          AND assignment.officer_user_id::text
                = NULLIF(current_setting('app.actor_id', true), '')
          AND assignment.assignment_purpose_code = 'CASE_TRIAGE'
          AND assignment.hold_id IS NULL
    )
);

CREATE FUNCTION trust_api.list_my_completed_case_assignments_v1(
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
    authority_count integer;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_limit IS NULL
       OR exact_limit NOT BETWEEN 1 AND 100
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind', 'TRUST_OFFICER', true);
    PERFORM set_config('app.operation', 'READ_ASSIGNED_CASE', true);
    PERFORM set_config('app.actor_id', exact_actor_user_id::text, true);
    PERFORM set_config('app.session_id', exact_session_id::text, true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.membership_id', '', true);
    PERFORM set_config('app.membership_role_grant_id', '', true);
    PERFORM set_config('app.membership_role_grant_version', '', true);
    PERFORM set_config('app.duty_grant_id', '', true);
    PERFORM set_config('app.duty_grant_version', '', true);

    SELECT count(*)
    INTO authority_count
    FROM iam_api.resolve_trust_officer_authority_v1(
        exact_actor_user_id,
        exact_session_id,
        'READ_ASSIGNED_CASE'
    ) AS resolved
    WHERE resolved.actor_user_id = exact_actor_user_id
      AND resolved.session_id = exact_session_id
      AND resolved.user_status = 'ACTIVE'
      AND resolved.session_status = 'ACTIVE'
      AND resolved.session_family_status = 'ACTIVE'
      AND resolved.duty_code = 'TRUST_OFFICER'
      AND resolved.duty_grant_version >= 1
      AND (
        resolved.duty_expires_at IS NULL
        OR transaction_timestamp() < resolved.duty_expires_at
      )
      AND octet_length(resolved.authority_marker_sha256) = 32;
    IF authority_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM set_config(
        'app.trust_scope_kind',
        'TRUST_MY_COMPLETED_ASSIGNMENTS_READ',
        true
    );
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    WITH bounded_rows AS MATERIALIZED (
        SELECT
            case_root.aggregate_version,
            outcome.case_id,
            outcome.decided_at,
            jsonb_build_object(
                'case_id', outcome.case_id,
                'decided_at', outcome.decided_at,
                'outcome_code', outcome.outcome_code
            ) AS item
        FROM trust.case_outcome_versions AS outcome
        JOIN trust.cases AS case_root
          ON case_root.case_id = outcome.case_id
         AND case_root.outcome_version_id = outcome.outcome_version_id
        JOIN trust.case_assignments AS assignment
          ON assignment.case_id = outcome.case_id
         AND assignment.assignment_id = outcome.decision_assignment_id
        WHERE outcome.decided_by_user_id = exact_actor_user_id
          AND assignment.officer_user_id = exact_actor_user_id
          AND assignment.assignment_purpose_code = 'CASE_TRIAGE'
          AND assignment.hold_id IS NULL
          AND case_root.status = 'DECIDED'
        ORDER BY outcome.decided_at DESC, outcome.case_id DESC
        LIMIT exact_limit + 1
    ), returned_rows AS MATERIALIZED (
        SELECT aggregate_version, case_id, decided_at, item
        FROM bounded_rows
        ORDER BY decided_at DESC, case_id DESC
        LIMIT exact_limit
    ), document AS (
        SELECT
            COALESCE(
                (
                    SELECT jsonb_agg(
                        item ORDER BY decided_at DESC, case_id DESC
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
            '"trust-%s-%s"',
            document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:my-completed-case-assignments:v1' || E'\x1f'
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

REVOKE ALL ON FUNCTION trust_api.list_my_completed_case_assignments_v1(
    uuid, uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_my_completed_case_assignments_v1(
    uuid, uuid, integer
) TO trust_officer;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 11
    AND min_app_compatible_version = 11
    AND max_app_compatible_version = 11
    AND required_iam_schema_version = 38
    AND required_demand_schema_version = 11
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
        '908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        'cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87',
        'hex'
    )
    AND api_contract_sha256 = decode(
        'a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25',
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
