ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions;
DELETE FROM trust_meta.schema_contracts;
ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 3
    AND min_app_compatible_version = 3
    AND max_app_compatible_version = 3
    AND required_iam_schema_version = 36
    AND required_demand_schema_version = 8
);

CREATE POLICY rls_appeal_receipt_policy_runtime_readiness
ON trust.appeal_receipt_key_policy FOR SELECT TO trust_schema_owner
USING (
    singleton_key
    AND current_user = 'trust_schema_owner'
    AND session_user IN ('trust_self', 'trust_appeal')
    AND NULLIF(current_setting('app.appeal_scope_kind', true), '')
            = 'APPEAL_RUNTIME_READINESS'
    AND NULLIF(current_setting('app.trust_scope_kind', true), '')
            = 'TRUST_RUNTIME_READINESS'
    AND NULLIF(current_setting('app.actor_id', true), '') IS NULL
    AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
    AND NULLIF(current_setting('app.appeal_id', true), '') IS NULL
    AND NULLIF(current_setting('app.case_id', true), '') IS NULL
    AND NULLIF(current_setting('app.demand_id', true), '') IS NULL
);

CREATE FUNCTION trust_api.assert_appeal_runtime_policy_v1(
    exact_active_idempotency_key_id text,
    exact_retained_idempotency_key_ids text[],
    exact_active_payload_key_id text,
    exact_retained_payload_key_ids text[],
    exact_canonicalization_version text,
    exact_active_sealed_text_key_id text,
    exact_retained_sealed_text_key_ids text[]
)
RETURNS TABLE (ready boolean)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL RESTRICTED
ROWS 1
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner'
       OR session_user NOT IN ('trust_self', 'trust_appeal')
       OR exact_canonicalization_version IS DISTINCT FROM
            'appeal-command-json-v1'
       OR trust.active_first_key_array_v1(
            exact_retained_idempotency_key_ids,
            exact_active_idempotency_key_id,
            4
       ) IS NOT TRUE
       OR trust.active_first_key_array_v1(
            exact_retained_payload_key_ids,
            exact_active_payload_key_id,
            4
       ) IS NOT TRUE
       OR trust.active_first_key_array_v1(
            exact_retained_sealed_text_key_ids,
            exact_active_sealed_text_key_id,
            4
       ) IS NOT TRUE
       OR (
            exact_retained_idempotency_key_ids
                && exact_retained_payload_key_ids
       ) IS NOT FALSE
    THEN
        RETURN;
    END IF;
    PERFORM set_config(
        'app.appeal_scope_kind', 'APPEAL_RUNTIME_READINESS', true
    );
    PERFORM set_config(
        'app.trust_scope_kind', 'TRUST_RUNTIME_READINESS', true
    );
    PERFORM set_config('app.actor_id', '', true);
    PERFORM set_config('app.organization_id', '', true);
    PERFORM set_config('app.appeal_id', '', true);
    PERFORM set_config('app.case_id', '', true);
    PERFORM set_config('app.demand_id', '', true);
    RETURN QUERY
    SELECT true
    FROM trust.appeal_receipt_key_policy AS appeal
    CROSS JOIN trust.sealed_text_key_policy AS sealed
    WHERE appeal.singleton_key
      AND sealed.singleton_key
      AND appeal.active_idempotency_key_id
              = exact_active_idempotency_key_id
      AND appeal.retained_idempotency_key_ids
              = exact_retained_idempotency_key_ids
      AND appeal.active_payload_key_id = exact_active_payload_key_id
      AND appeal.retained_payload_key_ids = exact_retained_payload_key_ids
      AND appeal.canonicalization_version = exact_canonicalization_version
      AND sealed.active_encryption_key_id = exact_active_sealed_text_key_id
      AND sealed.retained_encryption_key_ids
              = exact_retained_sealed_text_key_ids
    ;
END
$function$;

REVOKE ALL ON FUNCTION trust_api.assert_appeal_runtime_policy_v1(
    text, text[], text, text[], text, text, text[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.assert_appeal_runtime_policy_v1(
    text, text[], text, text[], text, text, text[]
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.assert_appeal_runtime_policy_v1(
    text, text[], text, text[], text, text, text[]
) TO trust_appeal;
