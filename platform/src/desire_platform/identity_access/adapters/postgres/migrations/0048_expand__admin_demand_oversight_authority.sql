-- Read-only administrator oversight of existing Demand workflows.
-- Every read re-proves the exact active IAM principal and selected workspace.
-- No runtime receives direct access to audit, names, or another domain table.
SET LOCAL search_path = pg_catalog, iam, iam_api;

CREATE FUNCTION iam_api.admin_demand_scope_v1(exact_organization_id uuid)
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
SELECT session_user = 'iam_app'
AND current_setting('app.operation', true) IN ('ADMIN_DEMAND_LIST', 'ADMIN_DEMAND_TIMELINE')
AND EXISTS (
    SELECT 1 FROM iam_api.resolve_editor_principal_v1(
        NULLIF(current_setting('app.actor_user_id', true), '')::uuid,
        NULLIF(current_setting('app.session_id', true), '')::uuid
    ) AS principal
    WHERE principal.workspace_id = current_setting('app.admin_workspace_id', true)
      AND encode(principal.principal_marker_sha256, 'hex') = current_setting('app.authority_marker_sha256', true)
      AND (
        (principal.workspace_kind = 'PLATFORM' AND 'ACCESS_ADMIN' = ANY(principal.platform_duty_codes))
        OR (principal.workspace_kind = 'ORGANIZATION' AND 'ORG_ADMIN' = ANY(principal.organization_role_codes)
            AND (exact_organization_id IS NULL OR principal.organization_id = exact_organization_id))
      )
)
$function$;
ALTER FUNCTION iam_api.admin_demand_scope_v1(uuid) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.admin_demand_scope_v1(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.admin_demand_scope_v1(uuid)
TO iam_app, demand_schema_owner, matching_schema_owner, trust_schema_owner;

-- A name lookup is only reachable from the fixed domain projection programs.
-- Those programs pass IDs obtained from already authorized Demand facts.
CREATE POLICY rls_admin_demand_participant_names_definer ON iam.users
FOR SELECT TO schema_owner USING (
    session_user = 'iam_app'
    AND current_setting('app.scope_kind', true) = 'EDITOR_PRINCIPAL'
    AND current_setting('app.operation', true) = 'ADMIN_DEMAND_TIMELINE'
    AND id = ANY(COALESCE(NULLIF(current_setting('app.admin_participant_ids', true), ''), '{}')::uuid[])
);
CREATE FUNCTION iam_api.admin_demand_participant_names_v1(exact_user_ids uuid[])
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE answer jsonb;
BEGIN
    IF NOT COALESCE(iam_api.admin_demand_scope_v1(NULL), false)
       OR current_setting('app.operation', true) IS DISTINCT FROM 'ADMIN_DEMAND_TIMELINE'
    THEN RETURN '{}'::jsonb; END IF;
    PERFORM set_config('app.admin_participant_ids', COALESCE(exact_user_ids, '{}')::text, true);
    SELECT COALESCE(jsonb_object_agg(actor.id::text, actor.display_handle), '{}'::jsonb)
    INTO answer FROM iam.users actor WHERE actor.id = ANY(exact_user_ids);
    PERFORM set_config('app.admin_participant_ids', '', true);
    RETURN answer;
END
$function$;
ALTER FUNCTION iam_api.admin_demand_participant_names_v1(uuid[]) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.admin_demand_participant_names_v1(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.admin_demand_participant_names_v1(uuid[])
TO demand_schema_owner, matching_schema_owner, trust_schema_owner;

CREATE INDEX ix_audit_demand_admin_target_history ON audit.audit_events (organization_id, target_id, occurred_at, event_id);
CREATE POLICY rls_admin_demand_audit_definer ON audit.audit_events
FOR SELECT TO schema_owner USING (
    session_user = 'iam_app'
    AND current_setting('app.operation', true) = 'ADMIN_DEMAND_TIMELINE'
    AND organization_id IS NOT NULL
    AND iam_api.admin_demand_scope_v1(organization_id)
    AND target_kind IN ('Demand','MatchingAttempt','MatchRun','Invitation','Selection',
        'CandidateSelectorAssignment','MatchingReviewAssignment','SafetyReport','SafetyCase',
        'SafetyHold','Appeal','AppealReviewAssignment','DemandReviewAssignment')
);
CREATE FUNCTION iam_api.read_admin_demand_audit_v1(exact_organization_id uuid, exact_target_ids uuid[])
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api, audit
AS $function$
DECLARE events jsonb; names jsonb; actors uuid[];
BEGIN
    IF exact_organization_id IS NULL OR NOT COALESCE(iam_api.admin_demand_scope_v1(exact_organization_id), false)
       OR current_setting('app.operation', true) IS DISTINCT FROM 'ADMIN_DEMAND_TIMELINE'
    THEN RETURN NULL; END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'event_id', e.event_id, 'occurred_at', e.occurred_at,
        'actor_kind', e.actor_kind, 'actor_user_id', CASE WHEN e.actor_kind='USER' THEN e.actor_id END,
        'original_actor_user_id', e.original_actor_id,
        'action', e.action_code, 'target_kind', e.target_kind, 'target_id', e.target_id,
        'before_status', e.before_status, 'after_status', e.after_status,
        'before_version', e.before_version, 'after_version', e.after_version,
        'role_code', e.role_code, 'reason_code', e.reason_code, 'result_code', e.result_code
    ) ORDER BY e.occurred_at, e.event_id), '[]'::jsonb),
    array_agg(DISTINCT CASE WHEN e.actor_kind='USER' THEN e.actor_id END)
    INTO events, actors FROM audit.audit_events e
    WHERE e.organization_id = exact_organization_id AND e.target_id = ANY(exact_target_ids);
    names := iam_api.admin_demand_participant_names_v1(actors);
    RETURN jsonb_build_object('events',events,'names',names);
END
$function$;
ALTER FUNCTION iam_api.read_admin_demand_audit_v1(uuid,uuid[]) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.read_admin_demand_audit_v1(uuid,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.read_admin_demand_audit_v1(uuid,uuid[]) TO iam_app;
