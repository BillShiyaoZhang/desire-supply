-- Administrator demand progress projection. Runtime EXECUTE only; FORCE RLS remains enabled.
SET LOCAL search_path = pg_catalog, matching;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
GRANT USAGE ON SCHEMA matching_api TO iam_app;
CREATE POLICY rls_admin_demand_timeline_definer ON matching.matching_attempts
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON matching.match_runs
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON matching.invitations
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON matching.selections
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON matching.candidate_selector_assignments
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON matching.matching_review_assignments
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON matching.match_jobs
FOR SELECT TO matching_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE FUNCTION matching_api.admin_demand_facts_v1(exact_organization_id uuid, exact_demand_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, matching, iam_api
AS $function$
DECLARE result jsonb; actors uuid[];
BEGIN
    IF exact_organization_id IS NULL OR exact_demand_id IS NULL
       OR NOT COALESCE(iam_api.admin_demand_scope_v1(exact_organization_id), false)
       OR COALESCE(current_setting('app.operation', true), '') NOT IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    THEN RETURN NULL; END IF;
    SELECT jsonb_build_object('matching_attempts',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'status',status,'current_match_run_id',current_match_run_id,'selection_id',selection_id,'created_at',created_at,'updated_at',updated_at) ORDER BY id), '[]'::jsonb) FROM matching.matching_attempts WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'match_runs',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'attempt_id',attempt_id,'status',status,'run_no',run_no,'candidate_count',candidate_count,'eligible_count',eligible_count,'failure_code',failure_code,'created_at',created_at,'updated_at',updated_at) ORDER BY id), '[]'::jsonb) FROM matching.match_runs WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'invitations',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'attempt_id',attempt_id,'status',status,'creator_user_id',creator_user_id,'created_by_user_id',created_by_user_id,'created_at',created_at,'sent_at',sent_at,'responded_at',responded_at,'expires_at',expires_at,'updated_at',updated_at) ORDER BY id), '[]'::jsonb) FROM matching.invitations WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'selections',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'attempt_id',attempt_id,'status',status,'decision_user_id',decision_actor_id,'created_at',created_at,'updated_at',updated_at) ORDER BY id), '[]'::jsonb) FROM matching.selections WHERE organization_id=exact_organization_id AND attempt_id IN (SELECT id FROM matching.matching_attempts WHERE demand_id=exact_demand_id AND organization_id=exact_organization_id)),'candidate_selector_assignments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'status',status,'assignee_user_id',assignee_user_id,'assigned_at',assigned_at,'expires_at',expires_at,'completed_at',completed_at) ORDER BY id), '[]'::jsonb) FROM matching.candidate_selector_assignments WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'matching_review_assignments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'status',status,'reviewer_user_id',reviewer_user_id,'purpose_code',purpose_code,'created_at',created_at,'expires_at',expires_at,'completed_at',completed_at) ORDER BY id), '[]'::jsonb) FROM matching.matching_review_assignments WHERE organization_id=exact_organization_id AND attempt_id IN (SELECT id FROM matching.matching_attempts WHERE demand_id=exact_demand_id AND organization_id=exact_organization_id)),'match_jobs',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'attempt_id',attempt_id,'match_run_id',match_run_id,'status',status,'job_kind',job_kind,'attempt_count',attempt_count,'created_at',created_at,'completed_at',completed_at) ORDER BY id), '[]'::jsonb) FROM matching.match_jobs WHERE organization_id=exact_organization_id AND attempt_id IN (SELECT id FROM matching.matching_attempts WHERE demand_id=exact_demand_id AND organization_id=exact_organization_id))) INTO result;
    SELECT array_agg(DISTINCT field.value::uuid) INTO actors
    FROM jsonb_each(result) groups CROSS JOIN LATERAL jsonb_array_elements(groups.value) item
    CROSS JOIN LATERAL jsonb_each_text(item) field(key,value)
    WHERE field.key LIKE '%user_id' AND field.value IS NOT NULL;
    RETURN result || jsonb_build_object('names',iam_api.admin_demand_participant_names_v1(actors));
END
$function$;
ALTER FUNCTION matching_api.admin_demand_facts_v1(uuid,uuid) OWNER TO matching_schema_owner;
REVOKE ALL ON FUNCTION matching_api.admin_demand_facts_v1(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION matching_api.admin_demand_facts_v1(uuid,uuid) TO iam_app;
