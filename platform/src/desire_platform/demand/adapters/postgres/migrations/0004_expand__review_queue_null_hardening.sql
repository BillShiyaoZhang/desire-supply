-- Forward-only NULL hardening for the reviewed Demand queue functions.
-- Version 0003 remains byte-immutable; the original functions are retained as
-- owner-only implementation details behind closed online wrappers.

ALTER FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) RENAME TO list_available_demand_reviews_legacy_v1;

REVOKE ALL ON FUNCTION demand_api.list_available_demand_reviews_legacy_v1(
    uuid, uuid, bytea, integer
) FROM PUBLIC, demand_review;
GRANT EXECUTE ON FUNCTION demand_api.list_available_demand_reviews_legacy_v1(
    uuid, uuid, bytea, integer
) TO demand_schema_owner;

CREATE FUNCTION demand_api.list_available_demand_reviews_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea,
    maximum_items integer
)
RETURNS TABLE (
    demand_id uuid,
    demand_revision bigint,
    demand_version_no integer,
    submitted_at timestamptz,
    demand_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand_api
AS $function$
BEGIN
    IF exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR expected_principal_marker_sha256 IS NULL
       OR maximum_items IS NULL
       OR maximum_items NOT BETWEEN 1 AND 100 THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT legacy.demand_id,
           legacy.demand_revision,
           legacy.demand_version_no,
           legacy.submitted_at,
           legacy.demand_expires_at
    FROM demand_api.list_available_demand_reviews_legacy_v1(
        exact_actor_user_id,
        exact_session_id,
        expected_principal_marker_sha256,
        maximum_items
    ) AS legacy;
END
$function$;

ALTER FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demand_api.list_available_demand_reviews_v1(
    uuid, uuid, bytea, integer
) TO demand_review;

ALTER FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) RENAME TO claim_demand_review_legacy_v1;

REVOKE ALL ON FUNCTION demand_api.claim_demand_review_legacy_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC, demand_review;
GRANT EXECUTE ON FUNCTION demand_api.claim_demand_review_legacy_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_schema_owner;

CREATE FUNCTION demand_api.claim_demand_review_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_demand_id uuid,
    expected_demand_revision bigint,
    expected_principal_marker_sha256 bytea,
    new_assignment_id uuid,
    new_receipt_id uuid,
    exact_idempotency_key_digest_key_id text,
    exact_idempotency_key_digest bytea,
    exact_payload_hash_key_id text,
    exact_payload_hash bytea,
    new_audit_event_id uuid,
    new_outbox_event_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid
)
RETURNS TABLE (
    assignment_id uuid,
    demand_id uuid,
    demand_revision bigint,
    assignment_status text,
    assignment_expires_at timestamptz,
    response_entity_tag text,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, demand_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_demand_id IS NULL OR exact_demand_id = zero_uuid
       OR expected_demand_revision IS NULL
       OR expected_demand_revision < 1
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR new_assignment_id IS NULL OR new_assignment_id = zero_uuid
       OR new_receipt_id IS NULL OR new_receipt_id = zero_uuid
       OR exact_idempotency_key_digest_key_id IS NULL
       OR exact_idempotency_key_digest IS NULL
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR exact_payload_hash_key_id IS NULL
       OR exact_payload_hash IS NULL
       OR octet_length(exact_payload_hash) <> 32
       OR new_audit_event_id IS NULL OR new_audit_event_id = zero_uuid
       OR new_outbox_event_id IS NULL OR new_outbox_event_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS NULL OR exact_causation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT legacy.assignment_id,
           legacy.demand_id,
           legacy.demand_revision,
           legacy.assignment_status,
           legacy.assignment_expires_at,
           legacy.response_entity_tag,
           legacy.replayed
    FROM demand_api.claim_demand_review_legacy_v1(
        exact_actor_user_id,
        exact_session_id,
        exact_organization_id,
        exact_demand_id,
        expected_demand_revision,
        expected_principal_marker_sha256,
        new_assignment_id,
        new_receipt_id,
        exact_idempotency_key_digest_key_id,
        exact_idempotency_key_digest,
        exact_payload_hash_key_id,
        exact_payload_hash,
        new_audit_event_id,
        new_outbox_event_id,
        exact_correlation_id,
        exact_causation_id,
        exact_trace_id
    ) AS legacy;
END
$function$;

ALTER FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) OWNER TO demand_schema_owner;
REVOKE ALL ON FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demand_api.claim_demand_review_v1(
    uuid, uuid, uuid, uuid, bigint, bytea, uuid, uuid, text, bytea,
    text, bytea, uuid, uuid, uuid, uuid, uuid
) TO demand_review;

DO $assert$
BEGIN
    IF pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.list_available_demand_reviews_legacy_v1(uuid,uuid,bytea,integer)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.claim_demand_review_legacy_v1(uuid,uuid,uuid,uuid,bigint,bytea,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.list_available_demand_reviews_v1(uuid,uuid,bytea,integer)',
            'EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'demand_review',
            'demand_api.claim_demand_review_v1(uuid,uuid,uuid,uuid,bigint,bytea,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Demand review queue NULL hardening assertion failed';
    END IF;
END
$assert$;
