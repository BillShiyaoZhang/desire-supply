-- Generate future immutable disclosures using the frozen public UTC-Z contract.
-- Preserve microseconds and use UTC explicitly, independent of session TimeZone.
-- This changes no stored disclosure, digest, function privilege, or Matching1-7 byte.

CREATE OR REPLACE FUNCTION matching.expected_invitation_disclosure_v1(
    exact_invitation_id uuid,
    exact_organization_id uuid,
    exact_attempt_id uuid,
    exact_demand_id uuid,
    exact_demand_version_id uuid,
    exact_profile_id uuid,
    exact_profile_version_id uuid,
    exact_expires_at timestamptz,
    exact_demand_content_sha256 bytea,
    exact_profile_content_sha256 bytea,
    exact_canonical_demand_version jsonb
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT jsonb_build_object(
        'schema_version',1,
        'canonicalization_version','invitation-disclosure-json-v1',
        'invitation_id',exact_invitation_id::text,
        'attempt_id',exact_attempt_id::text,
        'demand_id',exact_demand_id::text,
        'demand_version_id',exact_demand_version_id::text,
        'profile_id',exact_profile_id::text,
        'profile_version_id',exact_profile_version_id::text,
        'organization_preview',jsonb_build_object(
            'organization_id',exact_organization_id::text,
            'display_label','Organization '
                || substr(replace(exact_organization_id::text,'-',''),1,12)
        ),
        'opportunity',jsonb_build_object(
            'title',left(COALESCE(
                exact_canonical_demand_version->'content'->'problem'
                    ->'desired_outcomes'->>0,
                exact_canonical_demand_version->'content'->'problem'
                    ->>'domain_code'
            ),120),
            'problem_summary',left(
                exact_canonical_demand_version->'content'->'problem'
                    ->>'background',500
            ),
            'deliverable_summaries',COALESCE((
                SELECT jsonb_agg(left(item.value->>'description',500)
                    ORDER BY item.ordinality)
                FROM jsonb_array_elements(
                    exact_canonical_demand_version->'content'->'scope'
                        ->'deliverables'
                ) WITH ORDINALITY AS item(value,ordinality)
            ),'[]'::jsonb),
            'acceptance_summaries',COALESCE((
                SELECT jsonb_agg(left(item.value->>'description',500)
                    ORDER BY item.ordinality)
                FROM jsonb_array_elements(
                    exact_canonical_demand_version->'content'->'acceptance'
                        ->'criteria'
                ) WITH ORDINALITY AS item(value,ordinality)
            ),'[]'::jsonb)
        ),
        'offer',jsonb_build_object(
            'currency',exact_canonical_demand_version->'content'->'budget'
                ->>'currency',
            'minimum_amount_minor',(
                exact_canonical_demand_version->'content'->'budget'
                    ->>'minimum_amount_minor'
            )::bigint,
            'maximum_amount_minor',(
                exact_canonical_demand_version->'content'->'budget'
                    ->>'maximum_amount_minor'
            )::bigint,
            'schedule_code','SCHEDULE.' || (
                exact_canonical_demand_version->'content'->'collaboration'
                    ->>'work_mode'
            ),
            'duration_weeks',(
                exact_canonical_demand_version->'content'->'schedule'
                    ->>'duration_weeks'
            )::integer
        ),
        'constraints',jsonb_build_object(
            'region_codes',COALESCE((
                SELECT jsonb_agg('REGION.' || upper(item.value)
                    ORDER BY item.value COLLATE "C")
                FROM jsonb_array_elements_text(
                    exact_canonical_demand_version->'content'->'location'
                        ->'allowed_creator_region_codes'
                ) AS item(value)
            ),'[]'::jsonb),
            'language_codes',COALESCE((
                SELECT jsonb_agg('LANGUAGE.' || upper(item.value)
                    ORDER BY item.value COLLATE "C")
                FROM jsonb_array_elements_text(
                    exact_canonical_demand_version->'content'
                        ->'collaboration'->'languages'
                ) AS item(value)
            ),'[]'::jsonb),
            'data_sensitivity_code',
                exact_canonical_demand_version->'content'->'risk'
                    ->>'data_sensitivity',
            'ai_use_code',CASE
                WHEN (exact_canonical_demand_version->'content'->'ai'
                        ->>'required')::boolean THEN 'REQUIRED'
                WHEN (exact_canonical_demand_version->'content'->'ai'
                        ->>'allowed')::boolean THEN 'OPTIONAL'
                ELSE 'PROHIBITED' END
        ),
        'expires_at',to_char(
            exact_expires_at AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        ),
        'demand_content_sha256',encode(exact_demand_content_sha256,'hex'),
        'profile_content_sha256',encode(exact_profile_content_sha256,'hex')
    )
$function$;
