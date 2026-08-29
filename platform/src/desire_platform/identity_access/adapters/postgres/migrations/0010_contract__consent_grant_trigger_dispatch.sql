-- Forward-only repair for the deferred consent-grant trigger's relation dispatch.

CREATE OR REPLACE FUNCTION iam.enforce_consent_grant_matches_offer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    checked_grant_id uuid;
BEGIN
    IF TG_TABLE_SCHEMA = 'iam' AND TG_TABLE_NAME = 'consent_grants' THEN
        checked_grant_id := NEW.id;
    ELSIF TG_TABLE_SCHEMA = 'iam'
          AND TG_TABLE_NAME = 'consent_grant_data_categories' THEN
        checked_grant_id := NEW.grant_id;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_grant_matches_offer',
            MESSAGE = 'consent grant trigger relation is invalid';
    END IF;

    PERFORM iam.assert_consent_grant_matches_offer(checked_grant_id);
    RETURN NULL;
END
$function$;
