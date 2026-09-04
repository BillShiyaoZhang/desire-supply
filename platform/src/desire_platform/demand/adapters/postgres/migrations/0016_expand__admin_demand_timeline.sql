-- Administrator demand progress projection. Runtime EXECUTE only; FORCE RLS remains enabled.
SET LOCAL search_path = pg_catalog, demand;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
GRANT USAGE ON SCHEMA demand_api TO iam_app;
CREATE POLICY rls_admin_demand_timeline_definer ON demand.demands
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.demand_versions
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.demand_submissions
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.demand_review_assignments
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.demand_reviews
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.manual_funding_review_cases
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.manual_funding_review_assignments
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.manual_funding_confirmations
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.manual_funding_findings
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.matching_requests
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE POLICY rls_admin_demand_timeline_definer ON demand.matching_requested_deliveries
FOR SELECT TO demand_schema_owner USING (
    session_user = 'iam_app' AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    AND iam_api.admin_demand_scope_v1(organization_id)
);
CREATE INDEX ix_admin_demand_discovery ON demand.demands (created_at DESC,id DESC);
CREATE FUNCTION demand_api.list_admin_demands_v1(exact_demand_id uuid, maximum_items integer, cursor_created_at timestamptz, cursor_demand_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER STABLE PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
BEGIN
    IF NOT COALESCE(iam_api.admin_demand_scope_v1(NULL), false) THEN RETURN NULL; END IF;
    IF maximum_items IS NULL OR maximum_items NOT BETWEEN 1 AND 101
       OR (cursor_created_at IS NULL) IS DISTINCT FROM (cursor_demand_id IS NULL)
    THEN RETURN NULL; END IF;
    RETURN (SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'demand_id', d.id, 'organization_id',d.organization_id, 'creator_user_id',d.creator_user_id,
        'title',left(COALESCE(NULLIF(v.content->>'title',''),NULLIF(v.content->'content'->>'title',''),NULLIF(v.content#>>'{scope,deliverables,0,description}',''),NULLIF(v.content#>>'{content,scope,deliverables,0,description}',''),'未命名需求'),160),
        'status',d.status,'aggregate_version',d.aggregate_version,
        'created_at',d.created_at,'updated_at',d.updated_at,'expires_at',d.expires_at,
        'terminal_reason_code',d.terminal_reason_code
    ) ORDER BY d.created_at DESC,d.id DESC),'[]'::jsonb)
    FROM (SELECT * FROM demand.demands root
          WHERE (exact_demand_id IS NULL OR root.id=exact_demand_id)
          AND (cursor_created_at IS NULL OR (root.created_at,root.id)<(cursor_created_at,cursor_demand_id))
          ORDER BY root.created_at DESC,root.id DESC LIMIT maximum_items) d
    JOIN demand.demand_versions v ON v.id=d.current_version_id AND v.demand_id=d.id AND v.organization_id=d.organization_id);
END
$function$;
ALTER FUNCTION demand_api.list_admin_demands_v1(uuid,integer,timestamptz,uuid) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.list_admin_demands_v1(uuid,integer,timestamptz,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demand_api.list_admin_demands_v1(uuid,integer,timestamptz,uuid) TO iam_app;
CREATE FUNCTION demand_api.admin_demand_facts_v1(exact_organization_id uuid, exact_demand_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, demand, iam_api
AS $function$
DECLARE result jsonb; actors uuid[];
BEGIN
    IF exact_organization_id IS NULL OR exact_demand_id IS NULL
       OR NOT COALESCE(iam_api.admin_demand_scope_v1(exact_organization_id), false)
       OR COALESCE(current_setting('app.operation', true), '') NOT IN ('ADMIN_DEMAND_LIST','ADMIN_DEMAND_TIMELINE')
    THEN RETURN NULL; END IF;
    SELECT jsonb_build_object('demand_versions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'version_no',version_no,'created_by_user_id',created_by_user_id,'created_at',created_at) ORDER BY id), '[]'::jsonb) FROM demand.demand_versions WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'demand_submissions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'submitted_by_user_id',submitted_by_user_id,'submitted_at',submitted_at) ORDER BY id), '[]'::jsonb) FROM demand.demand_submissions WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'demand_review_assignments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'reviewer_user_id',reviewer_user_id,'status',status,'created_at',created_at,'completed_at',completed_at,'expires_at',expires_at) ORDER BY id), '[]'::jsonb) FROM demand.demand_review_assignments WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'demand_reviews',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'reviewer_user_id',reviewer_user_id,'decision',decision,'reason_codes',reason_codes,'required_field_codes',required_field_codes,'reviewed_at',reviewed_at) ORDER BY id), '[]'::jsonb) FROM demand.demand_reviews WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'manual_funding_review_cases',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'status',status,'required_confirmations',required_confirmations,'evidence_kind',evidence_kind,'legal_effect',legal_effect,'created_at',created_at,'completed_at',completed_at,'expires_at',expires_at) ORDER BY id), '[]'::jsonb) FROM demand.manual_funding_review_cases WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'manual_funding_review_assignments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'actor_user_id',actor_user_id,'status',status,'created_at',created_at,'completed_at',completed_at,'expires_at',expires_at) ORDER BY id), '[]'::jsonb) FROM demand.manual_funding_review_assignments WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'manual_funding_confirmations',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'actor_user_id',actor_user_id,'funding_review_id',funding_review_id,'confirmed_at',confirmed_at) ORDER BY id), '[]'::jsonb) FROM demand.manual_funding_confirmations WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'manual_funding_findings',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'actor_user_id',actor_user_id,'disposition',disposition,'reason_codes',reason_codes,'required_field_codes',required_field_codes,'created_at',created_at) ORDER BY id), '[]'::jsonb) FROM demand.manual_funding_findings WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'matching_requests',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'status',status,'requested_at',requested_at,'closed_at',closed_at) ORDER BY id), '[]'::jsonb) FROM demand.matching_requests WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id),'matching_requested_deliveries',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',delivery_id,'matching_request_id',matching_request_id,'status',status,'attempt_count',attempt_count,'last_failure_code',last_failure_code,'terminal_at',terminal_at,'created_at',created_at,'updated_at',updated_at,'completed_at',completed_at) ORDER BY delivery_id), '[]'::jsonb) FROM demand.matching_requested_deliveries WHERE organization_id=exact_organization_id AND demand_id=exact_demand_id)) INTO result;
    SELECT array_agg(DISTINCT field.value::uuid) INTO actors
    FROM jsonb_each(result) groups CROSS JOIN LATERAL jsonb_array_elements(groups.value) item
    CROSS JOIN LATERAL jsonb_each_text(item) field(key,value)
    WHERE field.key LIKE '%user_id' AND field.value IS NOT NULL;
    RETURN result || jsonb_build_object('names',iam_api.admin_demand_participant_names_v1(actors));
END
$function$;
ALTER FUNCTION demand_api.admin_demand_facts_v1(uuid,uuid) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.admin_demand_facts_v1(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demand_api.admin_demand_facts_v1(uuid,uuid) TO iam_app;
