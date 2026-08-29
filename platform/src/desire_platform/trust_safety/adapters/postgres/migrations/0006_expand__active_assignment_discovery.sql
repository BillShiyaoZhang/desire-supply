-- Minimal, actor-bound discovery of currently actionable Trust assignments.

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

DO $trust5_contract_baseline$
DECLARE
    contract_count bigint;
    contract_is_exact boolean;
BEGIN
    SELECT
        count(*),
        COALESCE(
            bool_and(
                singleton_key IS TRUE
                AND schema_head_version = 5
                AND min_app_compatible_version = 5
                AND max_app_compatible_version = 5
                AND required_iam_schema_version = 36
                AND required_demand_schema_version = 9
                AND required_iam_contract_sha256 = decode(
                    '8be48226b6fb409f442c6331dffcebc69435d401a75aa423614a9b7e60eb86a4',
                    'hex'
                )
                AND required_demand_contract_sha256 = decode(
                    '2ce5929295d30a91b55d9d907e0031707461498d3380e9e9e2e449eec06f9328',
                    'hex'
                )
                AND api_contract_sha256 = decode(
                    '14572f7768f31e9ced0b6ede09eb6eea1da3d2d4abd1c6d80cc4229c28e158bd',
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
                    'e85d905e407679665e7bea0008253bc4ec2bd941c4442964016caeb4ce62ffa7',
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
                    '85ba3eba8e44d325eb581bc1b1153c4e085e58ba66f300591e1bf83c14322865',
                    'hex'
                )
                AND migration_manifest_sha256 = decode(
                    '8b02df9ea6717265e3d69d22b837c9b5455ebab74cebe0c6a112d15de22b1c04',
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
            MESSAGE = 'TRUST5_SCHEMA_CONTRACT_BASELINE_MISMATCH';
    END IF;
END
$trust5_contract_baseline$;

DO $trust5_constraint_baseline$
DECLARE
    constraints_are_exact boolean;
BEGIN
    SELECT
        count(*) = 2
        AND count(*) FILTER (
            WHERE constraint_row.conname = 'ck_trust_schema_contract_versions'
        ) = 1
        AND count(*) FILTER (
            WHERE constraint_row.conname = 'ck_trust_schema_contract_hashes'
        ) = 1
        AND bool_and(
            relation.relkind = 'r'
            AND owner_role.rolname = 'trust_schema_owner'
            AND constraint_row.contype = 'c'
            AND constraint_row.convalidated
            AND NOT constraint_row.condeferrable
            AND NOT constraint_row.condeferred
            AND constraint_row.conislocal
            AND constraint_row.coninhcount = 0
            AND NOT constraint_row.connoinherit
            AND CASE constraint_row.conname
                WHEN 'ck_trust_schema_contract_versions' THEN
                    sha256(convert_to(pg_get_constraintdef(
                        constraint_row.oid,
                        true
                    ), 'UTF8')) = decode(
                        '5ae57b059dd27b509b56b53f6e2fa9ece7a43d028eaa0dadd93e267d7874ea8a',
                        'hex'
                    )
                WHEN 'ck_trust_schema_contract_hashes' THEN
                    sha256(convert_to(pg_get_constraintdef(
                        constraint_row.oid,
                        true
                    ), 'UTF8')) = decode(
                        'c071bbb686294676ceb23b0bc48289453ec52b58bd8b45f90ecf45b1d0d697f7',
                        'hex'
                    )
                ELSE false
            END
        )
    INTO STRICT constraints_are_exact
    FROM pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = constraint_row.conrelid
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = relation.relowner
    WHERE constraint_row.conrelid = 'trust_meta.schema_contracts'::regclass
      AND constraint_row.conname IN (
        'ck_trust_schema_contract_versions',
        'ck_trust_schema_contract_hashes'
      );

    IF constraints_are_exact IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST5_SCHEMA_CONSTRAINT_BASELINE_MISMATCH';
    END IF;
END
$trust5_constraint_baseline$;

ALTER TABLE trust.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.cases FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignment_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.case_assignment_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.safety_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.safety_holds FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeals ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeals FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_review_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_review_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_assignment_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust.appeal_assignment_releases FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_trust_my_case_assignments_select_v1
ON trust.case_assignments
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_ASSIGNMENTS_READ'
    AND officer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND duty_grant_id::text
        = NULLIF(current_setting('app.duty_grant_id', true), '')
    AND duty_grant_version::text
        = NULLIF(current_setting('app.duty_grant_version', true), '')
    AND assignment_purpose_code IN ('CASE_TRIAGE', 'HOLD_RELEASE')
    AND assigned_at <= transaction_timestamp()
    AND transaction_timestamp() < expires_at
);

CREATE POLICY rls_trust_my_case_assignment_releases_select_v1
ON trust.case_assignment_releases
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_ASSIGNMENTS_READ'
    AND EXISTS (
        SELECT 1
        FROM trust.case_assignments AS assignment
        WHERE assignment.assignment_id
            = case_assignment_releases.assignment_id
          AND assignment.case_id = case_assignment_releases.case_id
    )
);

CREATE POLICY rls_trust_my_case_holds_select_v1
ON trust.safety_holds
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_ASSIGNMENTS_READ'
    AND status = 'ACTIVE'
    AND effective_at <= transaction_timestamp()
    AND transaction_timestamp() < expires_at
    AND release_assignment_id IS NOT NULL
    AND requires_independent_release
    AND reason_code IN (
        'PARTICIPANT_SAFETY_RISK',
        'RETALIATION_RISK'
    )
    AND EXISTS (
        SELECT 1
        FROM trust.case_assignments AS assignment
        WHERE assignment.case_id = safety_holds.case_id
          AND assignment.assignment_id = safety_holds.release_assignment_id
          AND assignment.hold_id = safety_holds.hold_id
          AND assignment.assignment_purpose_code = 'HOLD_RELEASE'
          AND assignment.excluded_officer_user_id
                = safety_holds.issued_by_user_id
          AND assignment.officer_user_id
                <> assignment.excluded_officer_user_id
          AND assignment.expires_at <= safety_holds.expires_at
    )
);

CREATE POLICY rls_trust_my_case_roots_select_v1
ON trust.cases
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_CASE'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
        = 'TRUST_MY_ASSIGNMENTS_READ'
    AND EXISTS (
        SELECT 1
        FROM trust.case_assignments AS assignment
        LEFT JOIN trust.safety_holds AS hold
          ON hold.case_id = cases.case_id
         AND hold.hold_id = assignment.hold_id
         AND hold.release_assignment_id = assignment.assignment_id
        WHERE assignment.case_id = cases.case_id
          AND (
            (
                assignment.assignment_purpose_code = 'CASE_TRIAGE'
                AND assignment.hold_id IS NULL
                AND cases.assignment_id = assignment.assignment_id
                AND cases.status IN ('TRIAGING', 'IN_REVIEW', 'DECIDED')
            )
            OR (
                assignment.assignment_purpose_code = 'HOLD_RELEASE'
                AND assignment.hold_id IS NOT NULL
                AND cases.status = 'IN_REVIEW'
                AND hold.status = 'ACTIVE'
                AND hold.requires_independent_release
                AND hold.reason_code IN (
                    'PARTICIPANT_SAFETY_RISK',
                    'RETALIATION_RISK'
                )
                AND hold.effective_at <= transaction_timestamp()
                AND transaction_timestamp() < hold.expires_at
                AND assignment.excluded_officer_user_id
                    = hold.issued_by_user_id
                AND assignment.officer_user_id
                    <> assignment.excluded_officer_user_id
                AND assignment.expires_at <= hold.expires_at
            )
          )
    )
);

CREATE POLICY rls_trust_my_appeal_assignments_select_v1
ON trust.appeal_review_assignments
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
        = 'APPEAL_MY_ASSIGNMENTS_READ'
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND duty_grant_id::text
        = NULLIF(current_setting('app.duty_grant_id', true), '')
    AND duty_grant_version::text
        = NULLIF(current_setting('app.duty_grant_version', true), '')
    AND assigned_at <= transaction_timestamp()
    AND transaction_timestamp() < expires_at
);

CREATE POLICY rls_trust_my_appeal_assignment_releases_select_v1
ON trust.appeal_assignment_releases
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
        = 'APPEAL_MY_ASSIGNMENTS_READ'
    AND EXISTS (
        SELECT 1
        FROM trust.appeal_review_assignments AS assignment
        WHERE assignment.assignment_id
            = appeal_assignment_releases.assignment_id
          AND assignment.appeal_id = appeal_assignment_releases.appeal_id
    )
);

CREATE POLICY rls_trust_my_appeal_roots_select_v1
ON trust.appeals
FOR SELECT TO trust_schema_owner
USING (
    current_user = 'trust_schema_owner'
    AND session_user = 'trust_appeal'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_APPEAL'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_ASSIGNED_APPEAL'
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
        = 'APPEAL_MY_ASSIGNMENTS_READ'
    AND status = 'IN_REVIEW'
    AND decision_version_id IS NULL
    AND current_assignment_id IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM trust.appeal_review_assignments AS assignment
        WHERE assignment.appeal_id = appeals.appeal_id
          AND assignment.assignment_id = appeals.current_assignment_id
    )
);

CREATE FUNCTION trust_api.list_my_active_case_assignments_v1(
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
    resolved_duty_grant_id uuid;
    resolved_duty_grant_version bigint;
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

    SELECT
        count(*),
        (array_agg(resolved.duty_grant_id))[1],
        (array_agg(resolved.duty_grant_version))[1]
    INTO
        authority_count,
        resolved_duty_grant_id,
        resolved_duty_grant_version
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
        'app.duty_grant_id',
        resolved_duty_grant_id::text,
        true
    );
    PERFORM set_config(
        'app.duty_grant_version',
        resolved_duty_grant_version::text,
        true
    );

    PERFORM set_config(
        'app.trust_scope_kind',
        'TRUST_MY_ASSIGNMENTS_READ',
        true
    );
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    WITH active_rows AS MATERIALIZED (
        SELECT
            assignment.case_id,
            assignment.assignment_purpose_code,
            assignment.hold_id,
            assignment.expires_at,
            case_root.aggregate_version,
            jsonb_build_object(
                'assignment_expires_at', assignment.expires_at,
                'assignment_purpose', assignment.assignment_purpose_code,
                'case_id', assignment.case_id,
                'hold_id', assignment.hold_id
            ) AS item
        FROM trust.case_assignments AS assignment
        JOIN trust.cases AS case_root
          ON case_root.case_id = assignment.case_id
        LEFT JOIN trust.safety_holds AS hold
          ON hold.case_id = assignment.case_id
         AND hold.hold_id = assignment.hold_id
         AND hold.release_assignment_id = assignment.assignment_id
        WHERE assignment.officer_user_id = exact_actor_user_id
          AND assignment.duty_grant_id = resolved_duty_grant_id
          AND assignment.duty_grant_version = resolved_duty_grant_version
          AND assignment.assigned_at <= transaction_timestamp()
          AND transaction_timestamp() < assignment.expires_at
          AND NOT EXISTS (
            SELECT 1
            FROM trust.case_assignment_releases AS release
            WHERE release.assignment_id = assignment.assignment_id
              AND release.case_id = assignment.case_id
        )
          AND (
            (
                assignment.assignment_purpose_code = 'CASE_TRIAGE'
                AND assignment.hold_id IS NULL
                AND case_root.assignment_id = assignment.assignment_id
                AND case_root.status IN ('TRIAGING', 'IN_REVIEW')
            )
            OR (
                assignment.assignment_purpose_code = 'HOLD_RELEASE'
                AND assignment.hold_id IS NOT NULL
                AND case_root.status = 'IN_REVIEW'
                AND hold.status = 'ACTIVE'
                AND hold.requires_independent_release
                AND hold.reason_code IN (
                    'PARTICIPANT_SAFETY_RISK',
                    'RETALIATION_RISK'
                )
                AND hold.effective_at <= transaction_timestamp()
                AND transaction_timestamp() < hold.expires_at
                AND assignment.excluded_officer_user_id
                    = hold.issued_by_user_id
                AND assignment.officer_user_id
                    <> assignment.excluded_officer_user_id
                AND assignment.expires_at <= hold.expires_at
            )
          )
        ORDER BY assignment.expires_at, assignment.case_id,
                 assignment.assignment_purpose_code,
                 assignment.hold_id NULLS FIRST
        LIMIT exact_limit
    ), document AS (
        SELECT
            COALESCE(
                jsonb_agg(
                    item ORDER BY expires_at, case_id,
                                  assignment_purpose_code,
                                  hold_id NULLS FIRST
                ),
                '[]'::jsonb
            ) AS items,
            COALESCE(max(aggregate_version), 1)::bigint AS collection_version
        FROM active_rows
    )
    SELECT jsonb_build_object(
        'entity_tag', format(
            '"trust-%s-%s"',
            document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:my-active-case-assignments:v1' || E'\x1f'
                    || document.items::text,
                'UTF8'
            )), 'hex'), 24)
        ),
        'items', document.items
    )
    FROM document;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN
        RETURN;
END
$function$;

CREATE FUNCTION trust_api.read_my_active_case_triage_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_case_id uuid
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
    resolved_duty_grant_id uuid;
    resolved_duty_grant_version bigint;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_case_id IS NULL
       OR exact_case_id = zero_uuid
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

    SELECT
        count(*),
        (array_agg(resolved.duty_grant_id))[1],
        (array_agg(resolved.duty_grant_version))[1]
    INTO
        authority_count,
        resolved_duty_grant_id,
        resolved_duty_grant_version
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
        'app.duty_grant_id',
        resolved_duty_grant_id::text,
        true
    );
    PERFORM set_config(
        'app.duty_grant_version',
        resolved_duty_grant_version::text,
        true
    );
    PERFORM set_config(
        'app.trust_scope_kind',
        'TRUST_MY_ASSIGNMENTS_READ',
        true
    );
    PERFORM set_config('app.case_id', exact_case_id::text, true);
    PERFORM set_config('app.demand_id', '', true);

    PERFORM 1
    FROM trust.case_assignments AS assignment
    JOIN trust.cases AS case_root
      ON case_root.case_id = assignment.case_id
    WHERE assignment.case_id = exact_case_id
      AND assignment.assignment_purpose_code = 'CASE_TRIAGE'
      AND assignment.hold_id IS NULL
      AND assignment.officer_user_id = exact_actor_user_id
      AND assignment.duty_grant_id = resolved_duty_grant_id
      AND assignment.duty_grant_version = resolved_duty_grant_version
      AND assignment.assigned_at <= transaction_timestamp()
      AND transaction_timestamp() < assignment.expires_at
      AND case_root.assignment_id = assignment.assignment_id
      AND case_root.status IN ('TRIAGING', 'IN_REVIEW', 'DECIDED')
      AND NOT EXISTS (
        SELECT 1
        FROM trust.case_assignment_releases AS release
        WHERE release.assignment_id = assignment.assignment_id
          AND release.case_id = assignment.case_id
      );
    IF NOT FOUND THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT current_projection.projection
    FROM trust_api.read_assigned_case_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_case_id
    ) AS current_projection;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN
        RETURN;
END
$function$;

CREATE FUNCTION trust_api.read_my_active_hold_release_assignment_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_hold_id uuid
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
    resolved_duty_grant_id uuid;
    resolved_duty_grant_version bigint;
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR exact_actor_user_id IS NULL
       OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL
       OR exact_session_id = zero_uuid
       OR exact_hold_id IS NULL
       OR exact_hold_id = zero_uuid
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

    SELECT
        count(*),
        (array_agg(resolved.duty_grant_id))[1],
        (array_agg(resolved.duty_grant_version))[1]
    INTO
        authority_count,
        resolved_duty_grant_id,
        resolved_duty_grant_version
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
        'app.duty_grant_id',
        resolved_duty_grant_id::text,
        true
    );
    PERFORM set_config(
        'app.duty_grant_version',
        resolved_duty_grant_version::text,
        true
    );
    PERFORM set_config(
        'app.trust_scope_kind',
        'TRUST_MY_ASSIGNMENTS_READ',
        true
    );
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);

    RETURN QUERY
    SELECT jsonb_build_object(
        'action_codes', to_jsonb(hold.action_codes),
        'assignment_expires_at', assignment.expires_at,
        'case_id', case_root.case_id,
        'case_status', case_root.status,
        'effective_at', hold.effective_at,
        'entity_tag', trust.entity_tag_v1(
            'SafetyHold',
            hold.hold_id,
            hold.aggregate_version,
            hold.status,
            hold.effective_at
        ),
        'expires_at', hold.expires_at,
        'hold_id', hold.hold_id,
        'hold_status', hold.status,
        'reason_code', hold.reason_code
    )
    FROM trust.case_assignments AS assignment
    JOIN trust.safety_holds AS hold
      ON hold.case_id = assignment.case_id
     AND hold.hold_id = assignment.hold_id
     AND hold.release_assignment_id = assignment.assignment_id
    JOIN trust.cases AS case_root
      ON case_root.case_id = assignment.case_id
    WHERE hold.hold_id = exact_hold_id
      AND assignment.assignment_purpose_code = 'HOLD_RELEASE'
      AND assignment.officer_user_id = exact_actor_user_id
      AND assignment.duty_grant_id = resolved_duty_grant_id
      AND assignment.duty_grant_version = resolved_duty_grant_version
      AND assignment.excluded_officer_user_id = hold.issued_by_user_id
      AND assignment.officer_user_id
            <> assignment.excluded_officer_user_id
      AND assignment.assigned_at <= transaction_timestamp()
      AND transaction_timestamp() < assignment.expires_at
      AND assignment.expires_at <= hold.expires_at
      AND case_root.status = 'IN_REVIEW'
      AND hold.status = 'ACTIVE'
      AND hold.requires_independent_release
      AND hold.reason_code IN (
        'PARTICIPANT_SAFETY_RISK',
        'RETALIATION_RISK'
      )
      AND hold.effective_at <= transaction_timestamp()
      AND transaction_timestamp() < hold.expires_at
      AND NOT EXISTS (
        SELECT 1
        FROM trust.case_assignment_releases AS release
        WHERE release.assignment_id = assignment.assignment_id
          AND release.case_id = assignment.case_id
      );
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN
        RETURN;
END
$function$;

CREATE FUNCTION trust_api.list_my_active_appeal_assignments_v1(
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
        'APPEAL_MY_ASSIGNMENTS_READ',
        true
    );
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', '', true);

    RETURN QUERY
    WITH active_rows AS MATERIALIZED (
        SELECT
            assignment.appeal_id,
            assignment.expires_at,
            appeal_root.aggregate_version,
            jsonb_build_object(
                'appeal_id', assignment.appeal_id,
                'assignment_expires_at', assignment.expires_at
            ) AS item
        FROM trust.appeal_review_assignments AS assignment
        JOIN trust.appeals AS appeal_root
          ON appeal_root.appeal_id = assignment.appeal_id
        WHERE assignment.reviewer_user_id = exact_actor_user_id
          AND assignment.duty_grant_id = authority.duty_grant_id
          AND assignment.duty_grant_version = authority.duty_grant_version
          AND assignment.assigned_at <= transaction_timestamp()
          AND transaction_timestamp() < assignment.expires_at
          AND appeal_root.status = 'IN_REVIEW'
          AND appeal_root.decision_version_id IS NULL
          AND appeal_root.current_assignment_id = assignment.assignment_id
          AND NOT EXISTS (
            SELECT 1
            FROM trust.appeal_assignment_releases AS release
            WHERE release.assignment_id = assignment.assignment_id
              AND release.appeal_id = assignment.appeal_id
          )
        ORDER BY assignment.expires_at, assignment.appeal_id
        LIMIT exact_limit
    ), document AS (
        SELECT
            COALESCE(
                jsonb_agg(item ORDER BY expires_at, appeal_id),
                '[]'::jsonb
            ) AS items,
            COALESCE(max(aggregate_version), 1)::bigint AS collection_version
        FROM active_rows
    )
    SELECT jsonb_build_object(
        'entity_tag', format(
            '"appeal-%s-%s"',
            document.collection_version,
            left(encode(sha256(convert_to(
                'desire:trust:my-active-appeal-assignments:v1' || E'\x1f'
                    || document.items::text,
                'UTF8'
            )), 'hex'), 24)
        ),
        'items', document.items
    )
    FROM document;
EXCEPTION
    WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN
        RETURN;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.list_my_active_case_assignments_v1(
    uuid, uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_my_active_case_assignments_v1(
    uuid, uuid, integer
) TO trust_officer;

REVOKE EXECUTE ON FUNCTION trust_api.read_assigned_case_v1(
    uuid, uuid, uuid
) FROM trust_officer;

REVOKE ALL ON FUNCTION trust_api.read_my_active_case_triage_assignment_v1(
    uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_my_active_case_triage_assignment_v1(
    uuid, uuid, uuid
) TO trust_officer;

REVOKE ALL ON FUNCTION trust_api.read_my_active_hold_release_assignment_v1(
    uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_my_active_hold_release_assignment_v1(
    uuid, uuid, uuid
) TO trust_officer;

REVOKE ALL ON FUNCTION trust_api.list_my_active_appeal_assignments_v1(
    uuid, uuid, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.list_my_active_appeal_assignments_v1(
    uuid, uuid, integer
) TO trust_appeal;

DO $assignment_discovery_assertions$
DECLARE
    invalid_relation_count bigint;
    invalid_policy_count bigint;
    invalid_function_count bigint;
BEGIN
    SELECT count(*)
    INTO STRICT invalid_relation_count
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = relation.relowner
    WHERE namespace.nspname = 'trust'
      AND relation.relname IN (
        'cases', 'case_assignments', 'case_assignment_releases',
        'safety_holds', 'appeals', 'appeal_review_assignments',
        'appeal_assignment_releases'
      )
      AND (
        relation.relkind <> 'r'
        OR owner_role.rolname <> 'trust_schema_owner'
        OR NOT relation.relrowsecurity
        OR NOT relation.relforcerowsecurity
      );

    SELECT count(*)
    INTO STRICT invalid_policy_count
    FROM pg_catalog.pg_policy AS policy
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = policy.polrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'trust'
      AND policy.polname IN (
        'rls_trust_my_case_roots_select_v1',
        'rls_trust_my_case_assignments_select_v1',
        'rls_trust_my_case_assignment_releases_select_v1',
        'rls_trust_my_case_holds_select_v1',
        'rls_trust_my_appeal_roots_select_v1',
        'rls_trust_my_appeal_assignments_select_v1',
        'rls_trust_my_appeal_assignment_releases_select_v1'
      )
      AND (
        NOT policy.polpermissive
        OR policy.polcmd <> 'r'
        OR policy.polroles <> ARRAY[
            'trust_schema_owner'::regrole::oid
        ]::oid[]
        OR policy.polqual IS NULL
        OR policy.polwithcheck IS NOT NULL
      );

    SELECT count(*)
    INTO STRICT invalid_function_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'trust_api'
      AND procedure.proname IN (
        'list_my_active_case_assignments_v1',
        'read_my_active_case_triage_assignment_v1',
        'read_my_active_hold_release_assignment_v1',
        'list_my_active_appeal_assignments_v1'
      )
      AND (
        owner_role.rolname <> 'trust_schema_owner'
        OR NOT procedure.prosecdef
        OR procedure.provolatile <> 'v'
        OR procedure.proparallel <> 'u'
        OR procedure.proretset IS NOT TRUE
        OR procedure.pronargs <> 3
        OR procedure.proconfig IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, trust']::text[]
        OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );

    IF invalid_relation_count <> 0
       OR invalid_policy_count <> 0
       OR invalid_function_count <> 0
       OR (
            SELECT count(*)
            FROM pg_catalog.pg_policy AS policy
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = policy.polrelid
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'trust'
              AND policy.polname IN (
                'rls_trust_my_case_roots_select_v1',
                'rls_trust_my_case_assignments_select_v1',
                'rls_trust_my_case_assignment_releases_select_v1',
                'rls_trust_my_case_holds_select_v1',
                'rls_trust_my_appeal_roots_select_v1',
                'rls_trust_my_appeal_assignments_select_v1',
                'rls_trust_my_appeal_assignment_releases_select_v1'
              )
       ) <> 7
       OR (
            SELECT count(*)
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname = 'trust_api'
              AND procedure.proname IN (
                'list_my_active_case_assignments_v1',
                'read_my_active_case_triage_assignment_v1',
                'read_my_active_hold_release_assignment_v1',
                'list_my_active_appeal_assignments_v1'
              )
       ) <> 4
       OR NOT has_function_privilege(
            'trust_officer',
            'trust_api.list_my_active_case_assignments_v1(uuid,uuid,integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'trust_appeal',
            'trust_api.list_my_active_case_assignments_v1(uuid,uuid,integer)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'trust_appeal',
            'trust_api.list_my_active_appeal_assignments_v1(uuid,uuid,integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'trust_officer',
            'trust_api.list_my_active_appeal_assignments_v1(uuid,uuid,integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'trust_officer',
            'trust_api.read_assigned_case_v1(uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'trust_officer',
            'trust_api.read_my_active_case_triage_assignment_v1(uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'trust_appeal',
            'trust_api.read_my_active_case_triage_assignment_v1(uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'trust_officer',
            'trust_api.read_my_active_hold_release_assignment_v1(uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'trust_appeal',
            'trust_api.read_my_active_hold_release_assignment_v1(uuid,uuid,uuid)',
            'EXECUTE'
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'TRUST_ASSIGNMENT_DISCOVERY_ASSERTION_FAILED';
    END IF;
END
$assignment_discovery_assertions$;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions,
DROP CONSTRAINT ck_trust_schema_contract_hashes;

DELETE FROM trust_meta.schema_contracts;

ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 6
    AND min_app_compatible_version = 6
    AND max_app_compatible_version = 6
    AND required_iam_schema_version = 36
    AND required_demand_schema_version = 9
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
        '8be48226b6fb409f442c6331dffcebc69435d401a75aa423614a9b7e60eb86a4',
        'hex'
    )
    AND required_demand_contract_sha256 = decode(
        '2ce5929295d30a91b55d9d907e0031707461498d3380e9e9e2e449eec06f9328',
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
