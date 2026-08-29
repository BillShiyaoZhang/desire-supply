-- Reporter-owned, minimal Trust report discovery with stable keyset pagination.

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

DO $trust8_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 8
                AND min_app_compatible_version = 8
                AND max_app_compatible_version = 8
                AND required_iam_schema_version = 38
                AND required_demand_schema_version = 10
                AND required_iam_contract_sha256 = decode(
                    '908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    '27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    'f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed',
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
                    '8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722',
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
            MESSAGE = 'TRUST8_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust8_contract_baseline$;

CREATE FUNCTION trust_api.list_own_reports_v1(
    query_actor_user_id uuid,
    query_session_id uuid,
    query_organization_id uuid,
    query_limit integer,
    query_cursor_created_at timestamptz,
    query_cursor_report_id uuid
)
RETURNS TABLE (
    projection jsonb,
    next_created_at timestamptz,
    next_report_id uuid
)
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
       OR session_user IS DISTINCT FROM 'trust_self'
       OR query_actor_user_id IS NULL
       OR query_actor_user_id = zero_uuid
       OR query_session_id IS NULL
       OR query_session_id = zero_uuid
       OR query_organization_id IS NULL
       OR query_organization_id = zero_uuid
       OR query_limit IS NULL
       OR query_limit NOT BETWEEN 1 AND 100
       OR (query_cursor_created_at IS NULL)
            IS DISTINCT FROM (query_cursor_report_id IS NULL)
       OR query_cursor_report_id = zero_uuid
    THEN
        RETURN;
    END IF;

    PERFORM set_config('app.scope_kind', 'TRUST_REPORTER', true);
    PERFORM set_config('app.operation', 'READ_OWN_REPORT', true);
    PERFORM set_config('app.actor_id', query_actor_user_id::text, true);
    PERFORM set_config('app.session_id', query_session_id::text, true);
    PERFORM set_config(
        'app.organization_id', query_organization_id::text, true
    );

    SELECT count(*)
    INTO authority_count
    FROM iam_api.resolve_trust_reporter_authority_v1(
        query_actor_user_id,
        query_session_id,
        query_organization_id,
        'READ_OWN_REPORT'
    ) AS authority
    WHERE authority.actor_user_id = query_actor_user_id
      AND authority.session_id = query_session_id
      AND authority.organization_id = query_organization_id
      AND authority.user_status = 'ACTIVE'
      AND authority.session_status = 'ACTIVE'
      AND authority.session_family_status = 'ACTIVE'
      AND authority.organization_status = 'ACTIVE'
      AND authority.membership_status = 'ACTIVE'
      AND authority.role_code = 'DEMAND_OWNER'
      AND authority.membership_role_grant_version >= 1
      AND authority.policy_requirements_satisfied
      AND octet_length(authority.authority_marker_sha256) = 32;
    IF authority_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM set_config('app.trust_scope_kind', 'TRUST_REPORT_READ', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    IF query_cursor_created_at IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
            FROM trust.reports AS cursor_report
            WHERE cursor_report.organization_id = query_organization_id
              AND cursor_report.reporter_user_id = query_actor_user_id
              AND cursor_report.created_at = query_cursor_created_at
              AND cursor_report.report_id = query_cursor_report_id
       )
    THEN
        RETURN;
    END IF;

    RETURN QUERY
    WITH page_rows AS MATERIALIZED (
        SELECT
            report.created_at AS submitted_at,
            report.report_id,
            safety_case.aggregate_version,
            row_number() OVER (
                ORDER BY report.created_at DESC, report.report_id
            ) AS ordinal,
            jsonb_build_object(
                'category', report.category,
                'demand_id', report.demand_id,
                'outcome', CASE
                    WHEN outcome.outcome_version_id IS NULL THEN 'null'::jsonb
                    ELSE jsonb_build_object(
                        'appeal_deadline',
                            to_jsonb(outcome.appeal_deadline),
                        'appeal_eligibility_code',
                            outcome.appeal_eligibility_code,
                        'decided_at', outcome.decided_at,
                        'outcome_code', outcome.outcome_code,
                        'outcome_version_id', outcome.outcome_version_id
                    )
                END,
                'report_id', report.report_id,
                'status', safety_case.status,
                'submitted_at', report.created_at
            ) AS item
        FROM trust.reports AS report
        JOIN trust.cases AS safety_case
          ON safety_case.organization_id = report.organization_id
         AND safety_case.case_id = report.case_id
        LEFT JOIN trust.case_outcome_versions AS outcome
          ON outcome.organization_id = safety_case.organization_id
         AND outcome.case_id = safety_case.case_id
         AND outcome.outcome_version_id = safety_case.outcome_version_id
        WHERE report.organization_id = query_organization_id
          AND report.reporter_user_id = query_actor_user_id
          AND (
            query_cursor_created_at IS NULL
            OR report.created_at < query_cursor_created_at
            OR (
                report.created_at = query_cursor_created_at
                AND report.report_id > query_cursor_report_id
            )
          )
        ORDER BY report.created_at DESC, report.report_id
        LIMIT query_limit + 1
    ), visible_rows AS MATERIALIZED (
        SELECT *
        FROM page_rows
        WHERE ordinal <= query_limit
    ), page_document AS (
        SELECT
            COALESCE(
                jsonb_agg(item ORDER BY submitted_at DESC, report_id),
                '[]'::jsonb
            ) AS items,
            COALESCE(max(aggregate_version), 1)::bigint AS collection_version,
            EXISTS (
                SELECT 1 FROM page_rows WHERE ordinal > query_limit
            ) AS has_more
        FROM visible_rows
    ), boundary AS (
        SELECT submitted_at, report_id
        FROM visible_rows
        ORDER BY ordinal DESC
        LIMIT 1
    )
    SELECT
        jsonb_build_object(
            'entity_tag', format(
                '"trust-%s-%s"',
                page_document.collection_version,
                left(encode(sha256(convert_to(concat_ws(
                    E'\x1f',
                    'desire:trust:owned-report-list:v1',
                    query_actor_user_id::text,
                    query_organization_id::text,
                    query_limit::text,
                    COALESCE(query_cursor_created_at::text, ''),
                    COALESCE(query_cursor_report_id::text, ''),
                    page_document.items::text
                ), 'UTF8')), 'hex'), 24)
            ),
            'items', page_document.items
        ),
        CASE WHEN page_document.has_more THEN boundary.submitted_at END,
        CASE WHEN page_document.has_more THEN boundary.report_id END
    FROM page_document
    LEFT JOIN boundary ON true;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.list_own_reports_v1(
    uuid, uuid, uuid, integer, timestamptz, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_own_reports_v1(
    uuid, uuid, uuid, integer, timestamptz, uuid
) TO trust_self;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 9
    AND min_app_compatible_version = 9
    AND max_app_compatible_version = 9
    AND required_iam_schema_version = 38
    AND required_demand_schema_version = 10
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
        '27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113',
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
