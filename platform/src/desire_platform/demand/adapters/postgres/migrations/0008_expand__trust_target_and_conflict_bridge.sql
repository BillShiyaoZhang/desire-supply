-- Demand 0008: narrow Trust target, conflict, and future Appeal-party probes.
-- Existing Demand0001..0007 bytes remain immutable.  Runtime roles receive
-- only fixed SECURITY DEFINER entry points and compatibility-view reads; no
-- Trust role receives direct Demand or IAM table privileges.

DO $demand8_role_and_rls_guard$
DECLARE
    expected_role text;
    guarded_table regclass;
    table_security record;
BEGIN
    FOREACH expected_role IN ARRAY ARRAY[
        'trust_schema_owner', 'trust_migration_runner',
        'trust_self', 'trust_officer'
    ] LOOP
        IF pg_catalog.to_regrole(expected_role) IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_demand8_required_role',
                MESSAGE = 'Demand Trust bridge role is not provisioned';
        END IF;
    END LOOP;

    FOREACH guarded_table IN ARRAY ARRAY[
        'demand.demands'::regclass,
        'demand.demand_versions'::regclass,
        'demand.demand_submissions'::regclass,
        'demand.demand_review_assignments'::regclass,
        'demand.demand_reviews'::regclass,
        'demand.manual_funding_review_assignments'::regclass,
        'demand.manual_funding_confirmations'::regclass
    ] LOOP
        SELECT class.relrowsecurity, class.relforcerowsecurity
        INTO table_security
        FROM pg_catalog.pg_class AS class
        WHERE class.oid = guarded_table;
        IF NOT table_security.relrowsecurity
           OR NOT table_security.relforcerowsecurity THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_demand8_required_rls',
                MESSAGE = 'Demand Trust bridge table RLS is not forced';
        END IF;
    END LOOP;
END
$demand8_role_and_rls_guard$;

CREATE POLICY rls_trust_report_target_root_definer
ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_REPORTER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUBMIT_REPORT', 'OPEN_APPEAL'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND creator_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_trust_report_target_version_definer
ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_self'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_REPORTER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'SUBMIT_REPORT', 'OPEN_APPEAL'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND id::text
        = NULLIF(current_setting('app.demand_version_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_root_definer
ON demand.demands
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND id::text = NULLIF(current_setting('app.demand_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_version_definer
ON demand.demand_versions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND id::text
        = NULLIF(current_setting('app.demand_version_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_submission_definer
ON demand.demand_submissions
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND submitted_by_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_review_assignment_definer
ON demand.demand_review_assignments
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_review_definer
ON demand.demand_reviews
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND reviewer_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_finance_assignment_definer
ON demand.manual_funding_review_assignments
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_trust_officer_conflict_finance_confirmation_definer
ON demand.manual_funding_confirmations
FOR SELECT TO demand_schema_owner
USING (
    session_user = 'trust_officer'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'TRUST_OFFICER'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
    )
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
    AND demand_id::text = NULLIF(current_setting('app.demand_id', true), '')
    AND actor_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE FUNCTION demand_api.resolve_trust_report_target_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_membership_id uuid,
    exact_membership_role_grant_id uuid,
    exact_membership_role_grant_version bigint,
    exact_demand_id uuid,
    exact_demand_version_id uuid,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    organization_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    demand_version_no integer,
    demand_aggregate_version bigint,
    demand_status text,
    content_sha256 bytea,
    owner_user_id uuid,
    reportable_until timestamptz,
    reporter_party_marker_sha256 bytea,
    target_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    resolved_authority_marker_sha256 bytea;
    target_row record;
    party_marker bytea;
    not_found_marker bytea;
BEGIN
    IF session_user IS DISTINCT FROM 'trust_self'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_membership_id IS NULL OR exact_membership_id = zero_uuid
       OR exact_membership_role_grant_id IS NULL
       OR exact_membership_role_grant_id = zero_uuid
       OR exact_membership_role_grant_version IS NULL
       OR exact_membership_role_grant_version < 1
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_demand_version_id IS NULL
       OR exact_demand_version_id = zero_uuid
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_REPORTER'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'SUBMIT_REPORT'
       OR NULLIF(current_setting('app.membership_id', true), '')
            IS DISTINCT FROM exact_membership_id::text
       OR NULLIF(current_setting('app.membership_role_grant_id', true), '')
            IS DISTINCT FROM exact_membership_role_grant_id::text
       OR NULLIF(
            current_setting('app.membership_role_grant_version', true), ''
          ) IS DISTINCT FROM exact_membership_role_grant_version::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.demand_version_id', true), '')
            IS DISTINCT FROM exact_demand_version_id::text
       OR NULLIF(current_setting('app.duty_grant_id', true), '') IS NOT NULL
       OR NULLIF(current_setting('app.duty_grant_version', true), '') IS NOT NULL THEN
        RETURN;
    END IF;

    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT resolved_authority_marker_sha256
        FROM iam_api.resolve_trust_reporter_authority_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_organization_id,
            'SUBMIT_REPORT',
            exact_membership_id,
            exact_membership_role_grant_id,
            exact_membership_role_grant_version
        ) AS marker;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;
    IF resolved_authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    party_marker := sha256(convert_to(
        'demand-trust-reporter-party-v1|' || exact_actor_user_id::text || '|' ||
        exact_session_id::text || '|' || exact_organization_id::text || '|' ||
        exact_membership_id::text || '|' ||
        exact_membership_role_grant_id::text || '|' ||
        exact_membership_role_grant_version::text || '|' ||
        exact_demand_id::text || '|' || exact_demand_version_id::text || '|' ||
        encode(expected_authority_marker_sha256, 'hex'),
        'UTF8'
    ));

    SELECT
        root.organization_id,
        root.id AS demand_id,
        root.current_version_id AS demand_version_id,
        version_row.version_no,
        root.aggregate_version,
        root.status,
        version_row.content_sha256,
        root.creator_user_id,
        root.expires_at,
        version_row.id,
        version_row.demand_id
    INTO target_row
    FROM demand.demands AS root
    JOIN demand.demand_versions AS version_row
     ON version_row.organization_id = root.organization_id
     AND version_row.demand_id = root.id
     AND version_row.id = root.current_version_id
     AND version_row.id = exact_demand_version_id
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id
      AND root.creator_user_id = exact_actor_user_id
      AND root.status IN (
          'SUBMITTED', 'NEEDS_CHANGES', 'VERIFIED', 'FUNDING_PENDING',
          'FUNDED', 'MATCHING', 'MATCHED', 'NO_MATCH'
      )
      AND root.expires_at > transaction_timestamp();

    IF NOT FOUND THEN
        not_found_marker := sha256(convert_to(
            'demand-trust-target-not-found-v1|' ||
            exact_actor_user_id::text || '|' || exact_session_id::text || '|' ||
            exact_organization_id::text || '|' || exact_demand_id::text || '|' ||
            exact_demand_version_id::text || '|' ||
            encode(party_marker, 'hex') || '|TARGET_NOT_FOUND',
            'UTF8'
        ));
        RETURN QUERY SELECT
            exact_organization_id,
            exact_demand_id,
            exact_demand_version_id,
            1,
            1::bigint,
            'TARGET_NOT_FOUND'::text,
            not_found_marker,
            exact_actor_user_id,
            timestamptz '1970-01-01 00:00:00+00',
            party_marker,
            not_found_marker;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        target_row.organization_id,
        target_row.demand_id,
        target_row.demand_version_id,
        target_row.version_no,
        target_row.aggregate_version,
        target_row.status::text,
        target_row.content_sha256,
        target_row.creator_user_id,
        target_row.expires_at,
        party_marker,
        sha256(convert_to(
            'demand-trust-target-v1|' || target_row.organization_id::text || '|' ||
            target_row.demand_id::text || '|' ||
            target_row.demand_version_id::text || '|' ||
            target_row.version_no::text || '|' ||
            target_row.aggregate_version::text || '|' ||
            target_row.status::text || '|' ||
            encode(target_row.content_sha256, 'hex') || '|' ||
            target_row.creator_user_id::text || '|' ||
            extract(epoch FROM target_row.expires_at)::text || '|' ||
            encode(party_marker, 'hex'),
            'UTF8'
        ));
END
$function$;

CREATE VIEW demand.trust_schema_dependency_v1 AS
SELECT
    'demand'::text AS component,
    COALESCE((
        SELECT max(migration.version)
        FROM demand_meta.schema_migrations AS migration
        WHERE migration.component = 'demand'
    ), 0)::integer AS current_schema_version,
    contract.schema_head_version,
    contract.min_app_compatible_version,
    contract.max_app_compatible_version,
    contract.required_iam_schema_version,
    contract.api_contract_sha256,
    contract.event_contract_sha256,
    contract.content_contract_sha256,
    contract.migration_manifest_sha256,
    sha256(convert_to(concat_ws(
        E'\x1f',
        'desire:demand:trust-schema-dependency:v1',
        contract.schema_head_version::text,
        contract.min_app_compatible_version::text,
        contract.max_app_compatible_version::text,
        contract.required_iam_schema_version::text,
        encode(contract.api_contract_sha256, 'hex'),
        encode(contract.event_contract_sha256, 'hex'),
        encode(contract.content_contract_sha256, 'hex'),
        encode(contract.migration_manifest_sha256, 'hex')
    ), 'UTF8')) AS dependency_sha256
FROM demand_meta.schema_contracts AS contract
WHERE contract.singleton_key;

ALTER VIEW demand.trust_schema_dependency_v1 OWNER TO demand_schema_owner;
REVOKE ALL ON demand.trust_schema_dependency_v1 FROM PUBLIC;

CREATE FUNCTION demand_api.resolve_trust_officer_conflict_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint,
    exact_organization_id uuid,
    exact_demand_id uuid,
    exact_demand_version_id uuid,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (
    officer_user_id uuid,
    organization_id uuid,
    demand_id uuid,
    demand_version_id uuid,
    conflict_free boolean,
    conflict_attestation_sha256 bytea,
    evaluated_at timestamptz,
    valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    resolved_authority_marker_sha256 bytea;
    organization_membership_conflict boolean;
    conflict_facts_marker_sha256 bytea;
    target_row record;
    creator_conflict boolean;
    submitter_conflict boolean;
    reviewer_assignment_conflict boolean;
    reviewer_decision_conflict boolean;
    finance_assignment_conflict boolean;
    finance_confirmation_conflict boolean;
    result_conflict_free boolean;
    result_evaluated_at timestamptz;
    result_valid_until timestamptz;
BEGIN
    IF session_user IS DISTINCT FROM 'trust_officer'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_operation NOT IN ('CLAIM_CASE', 'CLAIM_HOLD_RELEASE')
       OR exact_duty_grant_id IS NULL OR exact_duty_grant_id = zero_uuid
       OR exact_duty_grant_version IS NULL OR exact_duty_grant_version < 1
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_demand_version_id IS NULL OR exact_demand_version_id = zero_uuid
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_OFFICER'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.duty_grant_id', true), '')
            IS DISTINCT FROM exact_duty_grant_id::text
       OR NULLIF(current_setting('app.duty_grant_version', true), '')
            IS DISTINCT FROM exact_duty_grant_version::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.demand_version_id', true), '')
            IS DISTINCT FROM exact_demand_version_id::text
       OR NULLIF(current_setting('app.membership_id', true), '') IS NOT NULL
       OR NULLIF(
            current_setting('app.membership_role_grant_id', true), ''
          ) IS NOT NULL
       OR NULLIF(
            current_setting('app.membership_role_grant_version', true), ''
          ) IS NOT NULL THEN
        RETURN;
    END IF;

    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT resolved_authority_marker_sha256
        FROM iam_api.resolve_trust_officer_authority_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_operation,
            exact_duty_grant_id,
            exact_duty_grant_version
        ) AS marker;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;
    IF resolved_authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    BEGIN
        SELECT
            facts.organization_membership_conflict,
            facts.conflict_facts_marker_sha256
        INTO STRICT
            organization_membership_conflict,
            conflict_facts_marker_sha256
        FROM iam_api.resolve_trust_party_conflict_facts_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_organization_id,
            exact_operation,
            exact_duty_grant_id,
            exact_duty_grant_version,
            expected_authority_marker_sha256
        ) AS facts;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;
    IF organization_membership_conflict IS NULL
       OR conflict_facts_marker_sha256 IS NULL
       OR octet_length(conflict_facts_marker_sha256) <> 32 THEN
        RETURN;
    END IF;

    SELECT
        root.organization_id,
        root.id AS demand_id,
        root.aggregate_version,
        root.creator_user_id,
        version_row.id AS demand_version_id,
        version_row.content_sha256
    INTO target_row
    FROM demand.demands AS root
    JOIN demand.demand_versions AS version_row
      ON version_row.organization_id = root.organization_id
     AND version_row.demand_id = root.id
     AND version_row.id = exact_demand_version_id
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id;
    IF NOT FOUND THEN RETURN; END IF;

    creator_conflict := target_row.creator_user_id = exact_actor_user_id;
    SELECT EXISTS (
        SELECT 1
        FROM demand.demand_submissions AS submission
        WHERE submission.organization_id = exact_organization_id
          AND submission.demand_id = exact_demand_id
          AND submission.submitted_by_user_id = exact_actor_user_id
    ) INTO submitter_conflict;
    SELECT EXISTS (
        SELECT 1
        FROM demand.demand_review_assignments AS assignment
        WHERE assignment.organization_id = exact_organization_id
          AND assignment.demand_id = exact_demand_id
          AND assignment.reviewer_user_id = exact_actor_user_id
    ) INTO reviewer_assignment_conflict;
    SELECT EXISTS (
        SELECT 1
        FROM demand.demand_reviews AS review_row
        WHERE review_row.organization_id = exact_organization_id
          AND review_row.demand_id = exact_demand_id
          AND review_row.reviewer_user_id = exact_actor_user_id
    ) INTO reviewer_decision_conflict;
    SELECT EXISTS (
        SELECT 1
        FROM demand.manual_funding_review_assignments AS finance_assignment
        WHERE finance_assignment.organization_id = exact_organization_id
          AND finance_assignment.demand_id = exact_demand_id
          AND finance_assignment.actor_user_id = exact_actor_user_id
    ) INTO finance_assignment_conflict;
    SELECT EXISTS (
        SELECT 1
        FROM demand.manual_funding_confirmations AS confirmation
        WHERE confirmation.organization_id = exact_organization_id
          AND confirmation.demand_id = exact_demand_id
          AND confirmation.actor_user_id = exact_actor_user_id
    ) INTO finance_confirmation_conflict;

    result_conflict_free := NOT (
        organization_membership_conflict
        OR creator_conflict
        OR submitter_conflict
        OR reviewer_assignment_conflict
        OR reviewer_decision_conflict
        OR finance_assignment_conflict
        OR finance_confirmation_conflict
    );
    result_evaluated_at := transaction_timestamp();
    result_valid_until := result_evaluated_at + interval '5 minutes';

    RETURN QUERY SELECT
        exact_actor_user_id,
        target_row.organization_id,
        target_row.demand_id,
        target_row.demand_version_id,
        result_conflict_free,
        sha256(convert_to(
            'demand-trust-officer-conflict-v1|' ||
            exact_actor_user_id::text || '|' || exact_session_id::text || '|' ||
            exact_operation || '|' ||
            exact_duty_grant_id::text || '|' ||
            exact_duty_grant_version::text || '|' ||
            target_row.organization_id::text || '|' ||
            target_row.demand_id::text || '|' ||
            target_row.demand_version_id::text || '|' ||
            target_row.aggregate_version::text || '|' ||
            encode(target_row.content_sha256, 'hex') || '|' ||
            organization_membership_conflict::text || '|' ||
            creator_conflict::text || '|' || submitter_conflict::text || '|' ||
            reviewer_assignment_conflict::text || '|' ||
            reviewer_decision_conflict::text || '|' ||
            finance_assignment_conflict::text || '|' ||
            finance_confirmation_conflict::text || '|' ||
            result_conflict_free::text || '|' ||
            encode(conflict_facts_marker_sha256, 'hex') || '|' ||
            encode(expected_authority_marker_sha256, 'hex') || '|' ||
            extract(epoch FROM result_evaluated_at)::text || '|' ||
            extract(epoch FROM result_valid_until)::text,
            'UTF8'
        )),
        result_evaluated_at,
        result_valid_until;
END
$function$;

CREATE FUNCTION demand_api.resolve_appeal_applicant_party_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_membership_id uuid,
    exact_membership_role_grant_id uuid,
    exact_membership_role_grant_version bigint,
    exact_demand_id uuid,
    exact_demand_version_id uuid,
    expected_authority_marker_sha256 bytea
)
RETURNS TABLE (applicant_party_marker_sha256 bytea)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    resolved_authority_marker_sha256 bytea;
    target_content_sha256 bytea;
BEGIN
    IF session_user IS DISTINCT FROM 'trust_self'
       OR current_user IS DISTINCT FROM 'demand_schema_owner'
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_membership_id IS NULL OR exact_membership_id = zero_uuid
       OR exact_membership_role_grant_id IS NULL
       OR exact_membership_role_grant_id = zero_uuid
       OR exact_membership_role_grant_version IS NULL
       OR exact_membership_role_grant_version < 1
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR exact_demand_version_id IS NULL OR exact_demand_version_id = zero_uuid
       OR expected_authority_marker_sha256 IS NULL
       OR octet_length(expected_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_REPORTER'
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'OPEN_APPEAL'
       OR NULLIF(current_setting('app.membership_id', true), '')
            IS DISTINCT FROM exact_membership_id::text
       OR NULLIF(current_setting('app.membership_role_grant_id', true), '')
            IS DISTINCT FROM exact_membership_role_grant_id::text
       OR NULLIF(
            current_setting('app.membership_role_grant_version', true), ''
          ) IS DISTINCT FROM exact_membership_role_grant_version::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM exact_demand_id::text
       OR NULLIF(current_setting('app.demand_version_id', true), '')
            IS DISTINCT FROM exact_demand_version_id::text THEN
        RETURN;
    END IF;

    BEGIN
        SELECT marker.authority_marker_sha256
        INTO STRICT resolved_authority_marker_sha256
        FROM iam_api.resolve_trust_reporter_authority_marker_v1(
            exact_actor_user_id,
            exact_session_id,
            exact_organization_id,
            'OPEN_APPEAL',
            exact_membership_id,
            exact_membership_role_grant_id,
            exact_membership_role_grant_version
        ) AS marker;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN RETURN;
    END;
    IF resolved_authority_marker_sha256
            IS DISTINCT FROM expected_authority_marker_sha256 THEN
        RETURN;
    END IF;

    SELECT version_row.content_sha256
    INTO target_content_sha256
    FROM demand.demands AS root
    JOIN demand.demand_versions AS version_row
      ON version_row.organization_id = root.organization_id
     AND version_row.demand_id = root.id
     AND version_row.id = exact_demand_version_id
    WHERE root.organization_id = exact_organization_id
      AND root.id = exact_demand_id
      AND root.creator_user_id = exact_actor_user_id;
    IF NOT FOUND THEN RETURN; END IF;

    RETURN QUERY SELECT sha256(convert_to(
        'demand-appeal-applicant-party-v1|' || exact_actor_user_id::text || '|' ||
        exact_session_id::text || '|' || exact_organization_id::text || '|' ||
        exact_membership_id::text || '|' ||
        exact_membership_role_grant_id::text || '|' ||
        exact_membership_role_grant_version::text || '|' ||
        exact_demand_id::text || '|' || exact_demand_version_id::text || '|' ||
        encode(target_content_sha256, 'hex') || '|' ||
        encode(expected_authority_marker_sha256, 'hex'),
        'UTF8'
    ));
END
$function$;

ALTER FUNCTION demand_api.resolve_trust_report_target_v1(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.resolve_trust_officer_conflict_v1(
    uuid, uuid, text, uuid, bigint, uuid, uuid, uuid, bytea
) OWNER TO demand_schema_owner;
ALTER FUNCTION demand_api.resolve_appeal_applicant_party_v1(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid, bytea
) OWNER TO demand_schema_owner;

REVOKE ALL ON FUNCTION demand_api.resolve_trust_report_target_v1(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid, bytea
) FROM PUBLIC, trust_self, trust_officer, trust_schema_owner;
REVOKE ALL ON FUNCTION demand_api.resolve_trust_officer_conflict_v1(
    uuid, uuid, text, uuid, bigint, uuid, uuid, uuid, bytea
) FROM PUBLIC, trust_self, trust_officer, trust_schema_owner;
REVOKE ALL ON FUNCTION demand_api.resolve_appeal_applicant_party_v1(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid, bytea
) FROM PUBLIC, trust_self, trust_officer, trust_schema_owner;

GRANT USAGE ON SCHEMA demand_api
TO trust_self, trust_officer, trust_schema_owner;
GRANT USAGE ON SCHEMA demand
TO trust_migration_runner, trust_schema_owner, trust_self, trust_officer;
GRANT SELECT ON demand.schema_compatibility TO trust_self, trust_officer;
GRANT SELECT ON demand.trust_schema_dependency_v1
TO trust_migration_runner, trust_schema_owner;
GRANT EXECUTE ON FUNCTION demand_api.resolve_trust_report_target_v1(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid, bytea
) TO trust_self, trust_schema_owner;
GRANT EXECUTE ON FUNCTION demand_api.resolve_trust_officer_conflict_v1(
    uuid, uuid, text, uuid, bigint, uuid, uuid, uuid, bytea
) TO trust_officer, trust_schema_owner;
GRANT EXECUTE ON FUNCTION demand_api.resolve_appeal_applicant_party_v1(
    uuid, uuid, uuid, uuid, uuid, bigint, uuid, uuid, bytea
) TO trust_self, trust_schema_owner;

DO $demand8_assertions$
DECLARE
    invalid_function_count integer;
    runtime_role text;
    base_table text;
BEGIN
    SELECT count(*)
    INTO invalid_function_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'demand_api'
      AND procedure.proname IN (
          'resolve_trust_report_target_v1',
          'resolve_trust_officer_conflict_v1',
          'resolve_appeal_applicant_party_v1'
      )
      AND (
          owner_role.rolname <> 'demand_schema_owner'
          OR NOT procedure.prosecdef
          OR procedure.provolatile <> 's'
          OR procedure.proparallel <> 'u'
          OR procedure.proconfig IS DISTINCT FROM
              ARRAY['search_path=pg_catalog, demand, iam_api']::text[]
          OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_function_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'trust_self',
            'demand_api.resolve_trust_report_target_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'trust_officer',
            'demand_api.resolve_trust_report_target_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'trust_officer',
            'demand_api.resolve_trust_officer_conflict_v1(uuid,uuid,text,uuid,bigint,uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'trust_self',
            'demand_api.resolve_trust_officer_conflict_v1(uuid,uuid,text,uuid,bigint,uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'trust_schema_owner',
            'demand_api.resolve_trust_report_target_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'trust_schema_owner',
            'demand_api.resolve_trust_officer_conflict_v1(uuid,uuid,text,uuid,bigint,uuid,uuid,uuid,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'ck_demand8_function_boundary',
            MESSAGE = 'Demand Trust bridge function boundary drifted';
    END IF;

    FOREACH runtime_role IN ARRAY ARRAY['trust_self', 'trust_officer'] LOOP
        FOREACH base_table IN ARRAY ARRAY[
            'demand.demands',
            'demand.demand_versions',
            'demand.demand_submissions',
            'demand.demand_review_assignments',
            'demand.demand_reviews',
            'demand.manual_funding_review_assignments',
            'demand.manual_funding_confirmations'
        ] LOOP
            IF pg_catalog.has_table_privilege(
                runtime_role, base_table, 'SELECT,INSERT,UPDATE,DELETE'
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '42501',
                    CONSTRAINT = 'ck_demand8_no_base_table_privilege',
                    MESSAGE = 'Trust runtime role can access a Demand table';
            END IF;
        END LOOP;
    END LOOP;
END
$demand8_assertions$;
