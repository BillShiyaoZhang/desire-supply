-- IAM 0031: two fixed FINANCE_OPERATOR accounts and manual funding authority.
--
-- Existing migration bytes and the v2 four-account bootstrap remain immutable.
-- V3 normalizes the two new duty codes only while delegating the established
-- identity/policy/session lifecycle to v1, then restores the exact six-account
-- graph atomically.  The digest bridge makes rotations explicit and auditable.

CREATE TABLE infra.iam_sandbox_bootstrap_manifest_bridges (
    bootstrap_id uuid NOT NULL,
    revision integer NOT NULL,
    manifest_sha256 bytea NOT NULL,
    normalized_manifest_sha256 bytea NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_iam_sandbox_bootstrap_manifest_bridges
        PRIMARY KEY (bootstrap_id, revision),
    CONSTRAINT uq_iam_sandbox_bootstrap_manifest_digest
        UNIQUE (bootstrap_id, manifest_sha256),
    CONSTRAINT ck_iam_sandbox_bootstrap_manifest_bridge_revision
        CHECK (revision >= 1),
    CONSTRAINT ck_iam_sandbox_bootstrap_manifest_bridge_digests CHECK (
        octet_length(manifest_sha256) = 32
        AND octet_length(normalized_manifest_sha256) = 32
        AND manifest_sha256 <> normalized_manifest_sha256
    )
);

ALTER TABLE infra.iam_sandbox_bootstrap_manifest_bridges
ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_sandbox_bootstrap_manifest_bridges
FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE infra.iam_sandbox_bootstrap_manifest_bridges FROM PUBLIC;

CREATE POLICY rls_sandbox_bootstrap_manifest_bridges
ON infra.iam_sandbox_bootstrap_manifest_bridges
FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());

CREATE FUNCTION iam.internal_sandbox_derived_uuid_v1(
    exact_domain text,
    exact_source_id uuid
)
RETURNS uuid
LANGUAGE sql
SECURITY INVOKER
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
SELECT (
    substr(digest, 1, 8) || '-' ||
    substr(digest, 9, 4) || '-' ||
    substr(digest, 13, 4) || '-' ||
    substr(digest, 17, 4) || '-' ||
    substr(digest, 21, 12)
)::uuid
FROM (
    SELECT pg_catalog.md5(exact_domain || '|' || exact_source_id::text) AS digest
) AS derived
WHERE exact_domain IN (
    'finance-bootstrap-command',
    'finance-bootstrap-receipt',
    'finance-bootstrap-audit'
)
  AND exact_source_id IS NOT NULL
$function$;

ALTER FUNCTION iam.internal_sandbox_derived_uuid_v1(text, uuid)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_derived_uuid_v1(text, uuid)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_independent_role_graph_v3(
    exact_manifest jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, iam, infra
AS $function$
WITH accounts AS (
    SELECT
        item.value->>'account_code' AS account_code,
        (item.value->>'user_id')::uuid AS user_id,
        (item.value#>>'{creator_grant,grant_id}')::uuid AS creator_grant_id,
        CASE WHEN pg_catalog.jsonb_typeof(
                item.value->'demand_owner_grant'
             ) = 'object'
            THEN (item.value#>>'{demand_owner_grant,grant_id}')::uuid
            ELSE NULL
        END AS demand_owner_grant_id,
        CASE WHEN pg_catalog.jsonb_typeof(
                item.value->'demand_owner_grant'
             ) = 'object'
            THEN (item.value#>>'{demand_owner_grant,membership_id}')::uuid
            ELSE NULL
        END AS membership_id,
        CASE WHEN pg_catalog.jsonb_typeof(
                item.value->'demand_owner_grant'
             ) = 'object'
            THEN (item.value#>>'{demand_owner_grant,organization_id}')::uuid
            ELSE NULL
        END AS organization_id,
        CASE WHEN pg_catalog.jsonb_array_length(
                item.value->'platform_duty_grants'
             ) = 1
            THEN item.value#>>'{platform_duty_grants,0,duty_code}'
            ELSE NULL
        END AS duty_code,
        CASE WHEN pg_catalog.jsonb_array_length(
                item.value->'platform_duty_grants'
             ) = 1
            THEN (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
            ELSE NULL
        END AS duty_grant_id
    FROM pg_catalog.jsonb_array_elements(
        exact_manifest->'accounts'
    ) AS item(value)
),
bootstrap_accounts AS (
    SELECT account.*
    FROM accounts AS account
    JOIN infra.iam_sandbox_bootstrap_accounts AS state
      ON state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
     AND state.account_code = account.account_code
     AND state.user_id = account.user_id
),
active_user_roles AS (
    SELECT grant_row.id, grant_row.user_id, grant_row.role_code
    FROM iam.user_role_grants AS grant_row
    JOIN accounts AS account ON account.user_id = grant_row.user_id
    WHERE grant_row.revoked_at IS NULL
),
isolated_creator_roles AS (
    SELECT grant_row.id, grant_row.user_id
    FROM iam.user_role_grants AS grant_row
    JOIN accounts AS account
      ON account.user_id = grant_row.user_id
     AND account.creator_grant_id = grant_row.id
    WHERE account.account_code <> 'creator_01'
      AND grant_row.role_code = 'CREATOR'
      AND grant_row.revoked_at IS NOT NULL
      AND grant_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
),
active_membership_roles AS (
    SELECT grant_row.id, grant_row.user_id, grant_row.membership_id,
        grant_row.organization_id, grant_row.role_code
    FROM iam.membership_role_grants AS grant_row
    JOIN accounts AS account ON account.user_id = grant_row.user_id
    WHERE grant_row.revoked_at IS NULL
),
active_duties AS (
    SELECT grant_row.id, grant_row.user_id, grant_row.duty_code
    FROM iam.platform_duty_grants AS grant_row
    JOIN accounts AS account ON account.user_id = grant_row.user_id
    WHERE grant_row.revoked_at IS NULL
)
SELECT
    (SELECT count(*) FROM accounts) = 6
    AND (SELECT count(*) FROM bootstrap_accounts) = 6
    AND (
        SELECT count(*)
        FROM infra.iam_sandbox_bootstrap_accounts AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 6
    AND (
        SELECT count(*)
        FROM active_user_roles AS role_row
        JOIN accounts AS account
          ON account.user_id = role_row.user_id
         AND account.creator_grant_id = role_row.id
        WHERE account.account_code = 'creator_01'
          AND role_row.role_code = 'CREATOR'
    ) = 1
    AND (SELECT count(*) FROM active_user_roles) = 1
    AND (SELECT count(*) FROM isolated_creator_roles) = 5
    AND (
        SELECT count(*)
        FROM active_membership_roles AS role_row
        JOIN accounts AS account
          ON account.user_id = role_row.user_id
         AND account.demand_owner_grant_id = role_row.id
         AND account.membership_id = role_row.membership_id
         AND account.organization_id = role_row.organization_id
        JOIN iam.memberships AS membership
          ON membership.id = role_row.membership_id
         AND membership.organization_id = role_row.organization_id
         AND membership.user_id = role_row.user_id
         AND membership.status = 'ACTIVE'
        WHERE account.account_code = 'demand_owner_01'
          AND role_row.role_code = 'DEMAND_OWNER'
    ) = 1
    AND (SELECT count(*) FROM active_membership_roles) = 1
    AND (
        SELECT count(*)
        FROM active_duties AS duty
        JOIN accounts AS account
          ON account.user_id = duty.user_id
         AND account.duty_grant_id = duty.id
         AND account.duty_code = duty.duty_code
        WHERE (
            account.account_code = 'access_admin_01'
            AND duty.duty_code = 'ACCESS_ADMIN'
        ) OR (
            account.account_code = 'operations_reviewer_01'
            AND duty.duty_code = 'OPERATIONS_REVIEWER'
        ) OR (
            account.account_code IN (
                'finance_operator_01', 'finance_operator_02'
            )
            AND duty.duty_code = 'FINANCE_OPERATOR'
        )
    ) = 4
    AND (SELECT count(*) FROM active_duties) = 4
$function$;

ALTER FUNCTION iam.internal_sandbox_independent_role_graph_v3(jsonb)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION
    iam.internal_sandbox_independent_role_graph_v3(jsonb)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_normalize_finance_graph_v1(
    exact_manifest jsonb,
    exact_normalized_manifest jsonb,
    exact_normalized_manifest_sha256 bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    affected integer;
BEGIN
    IF NOT iam.internal_sandbox_bootstrap_context_v1()
       OR pg_catalog.jsonb_array_length(exact_manifest->'accounts') <> 6
       OR pg_catalog.jsonb_array_length(
            exact_normalized_manifest->'accounts'
       ) <> 6
       OR exact_normalized_manifest_sha256 IS NULL
       OR octet_length(exact_normalized_manifest_sha256) <> 32 THEN
        RETURN false;
    END IF;

    UPDATE infra.iam_sandbox_bootstrap_state
    SET manifest_sha256 = exact_normalized_manifest_sha256,
        updated_at = transaction_timestamp()
    WHERE bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND status = 'ACTIVE';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN RETURN false; END IF;

    UPDATE infra.iam_sandbox_bootstrap_accounts AS account
    SET authority_shape_sha256 = sha256(convert_to(
            (item.value - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text,
            'UTF8'
        )),
        updated_at = transaction_timestamp()
    FROM pg_catalog.jsonb_array_elements(
        exact_normalized_manifest->'accounts'
    ) AS item(value)
    WHERE account.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND account.account_code = item.value->>'account_code'
      AND account.user_id = (item.value->>'user_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 6 THEN RETURN false; END IF;

    UPDATE iam.platform_duty_grants AS duty
    SET duty_code = 'OPERATIONS_REVIEWER',
        updated_at = transaction_timestamp()
    FROM pg_catalog.jsonb_array_elements(
        exact_manifest->'accounts'
    ) AS item(value)
    WHERE item.value->>'account_code' IN (
            'finance_operator_01', 'finance_operator_02'
      )
      AND duty.id = (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
      AND duty.user_id = (item.value->>'user_id')::uuid
      AND duty.duty_code = 'FINANCE_OPERATOR';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 2 THEN RETURN false; END IF;

    PERFORM set_config(
        'app.bootstrap_role_isolation_transition', 'RESTORE', true
    );
    UPDATE iam.user_role_grants AS grant_row
    SET revoked_at = NULL,
        revocation_reason_code = NULL,
        aggregate_version = grant_row.aggregate_version + 1
    FROM pg_catalog.jsonb_array_elements(
        exact_manifest->'accounts'
    ) AS item(value)
    WHERE item.value->>'account_code' <> 'creator_01'
      AND grant_row.id = (item.value#>>'{creator_grant,grant_id}')::uuid
      AND grant_row.user_id = (item.value->>'user_id')::uuid
      AND grant_row.role_code = 'CREATOR'
      AND grant_row.revoked_at IS NOT NULL
      AND grant_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION';
    GET DIAGNOSTICS affected = ROW_COUNT;
    PERFORM set_config(
        'app.bootstrap_role_isolation_transition', '', true
    );
    RETURN affected = 5;
END
$function$;

ALTER FUNCTION iam.internal_sandbox_normalize_finance_graph_v1(
    jsonb, jsonb, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_normalize_finance_graph_v1(
    jsonb, jsonb, bytea
) FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_apply_finance_graph_v1(
    exact_manifest jsonb,
    exact_manifest_sha256 bytea,
    isolate_creator_roles boolean
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    affected integer;
BEGIN
    IF NOT iam.internal_sandbox_bootstrap_context_v1()
       OR pg_catalog.jsonb_array_length(exact_manifest->'accounts') <> 6
       OR exact_manifest_sha256 IS NULL
       OR octet_length(exact_manifest_sha256) <> 32
       OR isolate_creator_roles IS NULL THEN
        RETURN false;
    END IF;

    UPDATE infra.iam_sandbox_bootstrap_state
    SET manifest_sha256 = exact_manifest_sha256,
        updated_at = transaction_timestamp()
    WHERE bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN RETURN false; END IF;

    UPDATE infra.iam_sandbox_bootstrap_accounts AS account
    SET authority_shape_sha256 = sha256(convert_to(
            (item.value - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text,
            'UTF8'
        )),
        updated_at = transaction_timestamp()
    FROM pg_catalog.jsonb_array_elements(
        exact_manifest->'accounts'
    ) AS item(value)
    WHERE account.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND account.account_code = item.value->>'account_code'
      AND account.user_id = (item.value->>'user_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 6 THEN RETURN false; END IF;

    UPDATE iam.platform_duty_grants AS duty
    SET duty_code = 'FINANCE_OPERATOR',
        updated_at = transaction_timestamp()
    FROM pg_catalog.jsonb_array_elements(
        exact_manifest->'accounts'
    ) AS item(value)
    WHERE item.value->>'account_code' IN (
            'finance_operator_01', 'finance_operator_02'
      )
      AND duty.id = (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
      AND duty.user_id = (item.value->>'user_id')::uuid
      AND duty.duty_code = 'OPERATIONS_REVIEWER';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 2 THEN RETURN false; END IF;

    IF isolate_creator_roles THEN
        UPDATE iam.user_role_grants AS grant_row
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION',
            aggregate_version = grant_row.aggregate_version + 1
        FROM pg_catalog.jsonb_array_elements(
            exact_manifest->'accounts'
        ) AS item(value)
        WHERE item.value->>'account_code' <> 'creator_01'
          AND grant_row.id = (item.value#>>'{creator_grant,grant_id}')::uuid
          AND grant_row.user_id = (item.value->>'user_id')::uuid
          AND grant_row.role_code = 'CREATOR'
          AND grant_row.revoked_at IS NULL;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 5
           OR NOT iam.internal_sandbox_independent_role_graph_v3(
                exact_manifest
           ) THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
END
$function$;

ALTER FUNCTION iam.internal_sandbox_apply_finance_graph_v1(
    jsonb, bytea, boolean
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_apply_finance_graph_v1(
    jsonb, bytea, boolean
) FROM PUBLIC;

CREATE FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v3(
    exact_action text,
    exact_canonical_manifest bytea,
    exact_manifest_sha256 bytea,
    exact_command_id uuid,
    exact_receipt_id uuid,
    exact_audit_event_id uuid,
    exact_system_actor_id uuid,
    exact_correlation_id uuid,
    exact_trace_id uuid,
    exact_bootstrap_id uuid
)
RETURNS TABLE(outcome text, revision integer, account_count integer)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    manifest_document jsonb;
    normalized_manifest jsonb;
    normalized_manifest_bytes bytea;
    normalized_manifest_digest bytea;
    previous_normalized_digest bytea;
    current_normalized_digest bytea;
    manifest_revision integer;
    state_row infra.iam_sandbox_bootstrap_state%ROWTYPE;
    state_found boolean := false;
    base_outcome text;
    base_revision integer;
    base_account_count integer;
    internal_command_id uuid;
    internal_receipt_id uuid;
    internal_audit_event_id uuid;
    bootstrap_command_name text;
    before_revision integer;
    prior_receipt infra.command_receipts%ROWTYPE;
BEGIN
    IF exact_action NOT IN ('APPLY', 'VERIFY', 'REVOKE_ACCESS')
       OR exact_canonical_manifest IS NULL
       OR octet_length(exact_canonical_manifest) NOT BETWEEN 1 AND 131072
       OR exact_manifest_sha256 IS NULL
       OR octet_length(exact_manifest_sha256) <> 32
       OR sha256(exact_canonical_manifest) <> exact_manifest_sha256
       OR exact_command_id IS NULL OR exact_command_id = zero_uuid
       OR exact_receipt_id IS NULL OR exact_receipt_id = zero_uuid
       OR exact_audit_event_id IS NULL OR exact_audit_event_id = zero_uuid
       OR exact_system_actor_id IS NULL OR exact_system_actor_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR exact_bootstrap_id IS NULL OR exact_bootstrap_id = zero_uuid
       OR session_user IS DISTINCT FROM 'iam_sandbox_bootstrap'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.internal_sandbox_bootstrap_context_v1()
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_action
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text
       OR NULLIF(current_setting('app.manifest_sha256', true), '')
            IS DISTINCT FROM encode(exact_manifest_sha256, 'hex')
       OR NULLIF(current_setting(
            'app.bootstrap_role_isolation_transition', true
       ), '') IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_invocation',
            MESSAGE = 'internal sandbox finance bootstrap invocation invalid';
    END IF;

    BEGIN
        manifest_document := convert_from(
            exact_canonical_manifest, 'UTF8'
        )::jsonb;
        manifest_revision := (manifest_document->>'revision')::integer;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_manifest',
            MESSAGE = 'internal sandbox finance bootstrap manifest invalid';
    END;

    IF manifest_document->>'schema_name'
            <> 'desire-internal-sandbox-identity-bootstrap-v1'
       OR manifest_document->>'environment_id' <> 'internal-sandbox'
       OR manifest_document->>'bootstrap_id' <> exact_bootstrap_id::text
       OR pg_catalog.jsonb_typeof(manifest_document->'accounts') <> 'array'
       OR jsonb_array_length(manifest_document->'accounts') <> 6
       OR (
            SELECT count(DISTINCT item.value->>'account_code')
            FROM jsonb_array_elements(
                manifest_document->'accounts'
            ) AS item(value)
       ) <> 6
       OR EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                manifest_document->'accounts'
            ) AS item(value)
            WHERE CASE item.value->>'account_code'
                WHEN 'access_admin_01' THEN NOT (
                    jsonb_typeof(item.value->'demand_owner_grant') = 'null'
                    AND jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 1
                    AND item.value#>>'{platform_duty_grants,0,duty_code}'
                        = 'ACCESS_ADMIN'
                )
                WHEN 'creator_01' THEN NOT (
                    jsonb_typeof(item.value->'demand_owner_grant') = 'null'
                    AND jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 0
                )
                WHEN 'demand_owner_01' THEN NOT (
                    jsonb_typeof(item.value->'demand_owner_grant') = 'object'
                    AND jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 0
                )
                WHEN 'finance_operator_01' THEN NOT (
                    jsonb_typeof(item.value->'demand_owner_grant') = 'null'
                    AND jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 1
                    AND item.value#>>'{platform_duty_grants,0,duty_code}'
                        = 'FINANCE_OPERATOR'
                )
                WHEN 'finance_operator_02' THEN NOT (
                    jsonb_typeof(item.value->'demand_owner_grant') = 'null'
                    AND jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 1
                    AND item.value#>>'{platform_duty_grants,0,duty_code}'
                        = 'FINANCE_OPERATOR'
                )
                WHEN 'operations_reviewer_01' THEN NOT (
                    jsonb_typeof(item.value->'demand_owner_grant') = 'null'
                    AND jsonb_array_length(
                        item.value->'platform_duty_grants'
                    ) = 1
                    AND item.value#>>'{platform_duty_grants,0,duty_code}'
                        = 'OPERATIONS_REVIEWER'
                )
                ELSE true
            END
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_manifest',
            MESSAGE = 'internal sandbox finance bootstrap manifest invalid';
    END IF;

    SELECT jsonb_set(
        manifest_document,
        '{accounts}',
        jsonb_agg(
            CASE WHEN item.value->>'account_code' IN (
                'finance_operator_01', 'finance_operator_02'
            ) THEN jsonb_set(
                item.value,
                '{platform_duty_grants,0,duty_code}',
                to_jsonb('OPERATIONS_REVIEWER'::text),
                false
            ) ELSE item.value END
            ORDER BY item.value->>'account_code'
        ),
        false
    )
    INTO normalized_manifest
    FROM jsonb_array_elements(
        manifest_document->'accounts'
    ) AS item(value);

    IF manifest_revision > 1 THEN
        SELECT bridge.normalized_manifest_sha256
        INTO previous_normalized_digest
        FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
        WHERE bridge.bootstrap_id = exact_bootstrap_id
          AND bridge.revision = manifest_revision - 1
          AND bridge.manifest_sha256 = decode(
                manifest_document->>'previous_manifest_sha256', 'hex'
          );
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_bridge',
                MESSAGE = 'internal sandbox finance bootstrap bridge missing';
        END IF;
        normalized_manifest := jsonb_set(
            normalized_manifest,
            '{previous_manifest_sha256}',
            to_jsonb(encode(previous_normalized_digest, 'hex')),
            false
        );
    END IF;

    normalized_manifest_bytes := convert_to(
        normalized_manifest::text, 'UTF8'
    );
    normalized_manifest_digest := sha256(normalized_manifest_bytes);
    IF normalized_manifest_digest = exact_manifest_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_normalization',
            MESSAGE = 'internal sandbox finance bootstrap normalization invalid';
    END IF;

    internal_command_id := iam.internal_sandbox_derived_uuid_v1(
        'finance-bootstrap-command', exact_command_id
    );
    internal_receipt_id := iam.internal_sandbox_derived_uuid_v1(
        'finance-bootstrap-receipt', exact_receipt_id
    );
    internal_audit_event_id := iam.internal_sandbox_derived_uuid_v1(
        'finance-bootstrap-audit', exact_audit_event_id
    );
    IF internal_command_id IS NULL
       OR internal_receipt_id IS NULL
       OR internal_audit_event_id IS NULL
       OR cardinality(ARRAY[
            exact_command_id, exact_receipt_id, exact_audit_event_id,
            internal_command_id, internal_receipt_id, internal_audit_event_id
       ]) <> cardinality(ARRAY(
            SELECT DISTINCT identifier
            FROM unnest(ARRAY[
                exact_command_id, exact_receipt_id, exact_audit_event_id,
                internal_command_id, internal_receipt_id,
                internal_audit_event_id
            ]) AS identifier
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_identifiers',
            MESSAGE = 'internal sandbox finance bootstrap identifiers invalid';
    END IF;

    PERFORM pg_advisory_xact_lock(1229016369, 31);
    SELECT * INTO state_row
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.bootstrap_id = exact_bootstrap_id
    FOR UPDATE;
    state_found := FOUND;

    IF state_found AND state_row.status = 'REVOKED' THEN
        IF state_row.manifest_sha256 = exact_manifest_sha256
           AND state_row.revision = manifest_revision
           AND state_row.account_count = 6
           AND exact_action IN ('VERIFY', 'REVOKE_ACCESS') THEN
            RETURN QUERY SELECT
                'ALREADY_REVOKED'::text, manifest_revision, 6;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_revoked',
            MESSAGE = 'internal sandbox finance bootstrap was revoked';
    END IF;

    IF state_found
       AND state_row.status = 'ACTIVE'
       AND state_row.manifest_sha256 = exact_manifest_sha256
       AND state_row.revision = manifest_revision
       AND state_row.account_count = 6
       AND exact_action IN ('APPLY', 'VERIFY') THEN
        IF NOT iam.internal_sandbox_independent_role_graph_v3(
            manifest_document
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_graph',
                MESSAGE = 'internal sandbox finance bootstrap graph drifted';
        END IF;
        SELECT bridge.normalized_manifest_sha256
        INTO current_normalized_digest
        FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
        WHERE bridge.bootstrap_id = exact_bootstrap_id
          AND bridge.revision = manifest_revision
          AND bridge.manifest_sha256 = exact_manifest_sha256;
        IF NOT FOUND
           OR current_normalized_digest <> normalized_manifest_digest THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_bridge',
                MESSAGE = 'internal sandbox finance bootstrap bridge drifted';
        END IF;

        BEGIN
            PERFORM set_config(
                'app.command_id', internal_command_id::text, true
            );
            PERFORM set_config(
                'app.manifest_sha256',
                encode(normalized_manifest_digest, 'hex'),
                true
            );
            IF NOT iam.internal_sandbox_normalize_finance_graph_v1(
                manifest_document,
                normalized_manifest,
                current_normalized_digest
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'Z3102',
                    MESSAGE = 'normalized finance bootstrap graph invalid';
            END IF;
            SELECT base.outcome, base.revision, base.account_count
            INTO base_outcome, base_revision, base_account_count
            FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1(
                exact_action,
                normalized_manifest_bytes,
                normalized_manifest_digest,
                internal_command_id,
                internal_receipt_id,
                internal_audit_event_id,
                exact_system_actor_id,
                exact_correlation_id,
                exact_trace_id,
                exact_bootstrap_id
            ) AS base;
            RAISE EXCEPTION USING
                ERRCODE = 'Z3101',
                MESSAGE = 'rollback normalized finance bootstrap replay';
        EXCEPTION WHEN SQLSTATE 'Z3101' THEN
            NULL;
        END;
        PERFORM set_config('app.command_id', exact_command_id::text, true);
        PERFORM set_config(
            'app.manifest_sha256', encode(exact_manifest_sha256, 'hex'), true
        );
    ELSE
        IF state_found THEN
            SELECT bridge.normalized_manifest_sha256
            INTO current_normalized_digest
            FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
            WHERE bridge.bootstrap_id = exact_bootstrap_id
              AND bridge.revision = state_row.revision
              AND bridge.manifest_sha256 = state_row.manifest_sha256;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_bridge',
                    MESSAGE = 'internal sandbox finance bootstrap bridge missing';
            END IF;
            IF NOT iam.internal_sandbox_normalize_finance_graph_v1(
                manifest_document,
                normalized_manifest,
                current_normalized_digest
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_restore',
                    MESSAGE = 'internal sandbox finance bootstrap restore failed';
            END IF;
        END IF;

        PERFORM set_config(
            'app.command_id', internal_command_id::text, true
        );
        PERFORM set_config(
            'app.manifest_sha256',
            encode(normalized_manifest_digest, 'hex'),
            true
        );
        SELECT base.outcome, base.revision, base.account_count
        INTO base_outcome, base_revision, base_account_count
        FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1(
            exact_action,
            normalized_manifest_bytes,
            normalized_manifest_digest,
            internal_command_id,
            internal_receipt_id,
            internal_audit_event_id,
            exact_system_actor_id,
            exact_correlation_id,
            exact_trace_id,
            exact_bootstrap_id
        ) AS base;
        PERFORM set_config('app.command_id', exact_command_id::text, true);
        PERFORM set_config(
            'app.manifest_sha256', encode(exact_manifest_sha256, 'hex'), true
        );

        IF base_outcome IN ('APPLIED', 'ROTATED') THEN
            IF NOT iam.internal_sandbox_apply_finance_graph_v1(
                manifest_document, exact_manifest_sha256, true
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_isolation',
                    MESSAGE = 'internal sandbox finance bootstrap isolation failed';
            END IF;
            INSERT INTO infra.iam_sandbox_bootstrap_manifest_bridges (
                bootstrap_id, revision, manifest_sha256,
                normalized_manifest_sha256, created_at
            ) VALUES (
                exact_bootstrap_id, manifest_revision,
                exact_manifest_sha256, normalized_manifest_digest,
                transaction_timestamp()
            );
        ELSIF base_outcome = 'REVOKED' THEN
            IF NOT iam.internal_sandbox_apply_finance_graph_v1(
                manifest_document, exact_manifest_sha256, false
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_revoke',
                    MESSAGE = 'internal sandbox finance bootstrap revoke failed';
            END IF;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_outcome',
                MESSAGE = 'internal sandbox finance bootstrap outcome invalid';
        END IF;
    END IF;

    IF base_revision <> manifest_revision
       OR base_account_count <> 6
       OR base_outcome NOT IN (
            'APPLIED', 'ROTATED', 'REPLAYED', 'VERIFIED', 'REVOKED'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_result',
            MESSAGE = 'internal sandbox finance bootstrap result invalid';
    END IF;

    bootstrap_command_name := CASE exact_action
        WHEN 'APPLY' THEN 'ApplyInternalSandboxIdentityBootstrap'
        ELSE 'RevokeInternalSandboxIdentityBootstrapAccess'
    END;
    before_revision := CASE base_outcome
        WHEN 'APPLIED' THEN NULL
        WHEN 'ROTATED' THEN manifest_revision - 1
        ELSE manifest_revision
    END;

    IF base_outcome = 'REPLAYED' THEN
        SELECT * INTO prior_receipt
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'SYSTEM'
          AND receipt.principal_id = exact_system_actor_id
          AND receipt.command_name = bootstrap_command_name
          AND receipt.command_version = 1
          AND receipt.idempotency_key_digest_key_id
                = 'internal-sandbox-bootstrap-v3'
          AND receipt.idempotency_key_digest = sha256(convert_to(
                exact_action || '|' || encode(exact_manifest_sha256, 'hex'),
                'UTF8'
          ))
        FOR UPDATE;
        IF NOT FOUND
           OR prior_receipt.status <> 'COMPLETED'
           OR prior_receipt.payload_hash_key_id
                <> 'internal-sandbox-bootstrap-v3'
           OR prior_receipt.payload_hash <> exact_manifest_sha256
           OR prior_receipt.target_kind
                <> 'InternalSandboxIdentityBootstrap'
           OR prior_receipt.target_id <> exact_bootstrap_id
           OR prior_receipt.safe_response_body->>'account_count' <> '6'
           OR prior_receipt.safe_response_body->>'manifest_sha256'
                <> encode(exact_manifest_sha256, 'hex')
           OR (prior_receipt.safe_response_body->>'revision')::integer
                <> manifest_revision
           OR prior_receipt.safe_response_body->>'outcome'
                NOT IN ('APPLIED', 'ROTATED') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_finance_bootstrap_replay',
                MESSAGE = 'internal sandbox finance bootstrap replay invalid';
        END IF;
        RETURN QUERY SELECT base_outcome, manifest_revision, 6;
        RETURN;
    ELSIF base_outcome = 'VERIFIED' THEN
        RETURN QUERY SELECT base_outcome, manifest_revision, 6;
        RETURN;
    END IF;

    INSERT INTO infra.command_receipts (
        id, principal_kind, principal_id, command_name, command_version,
        idempotency_key_digest, idempotency_key_digest_key_id, payload_hash,
        payload_hash_key_id, canonicalization_version, target_kind, target_id,
        http_method, canonical_path, if_match_version, status,
        response_schema_version, safe_response_body, reconstruction_metadata,
        created_at, retain_until, completed_at
    ) VALUES (
        exact_receipt_id, 'SYSTEM', exact_system_actor_id,
        bootstrap_command_name, 1,
        sha256(convert_to(
            exact_action || '|' || encode(exact_manifest_sha256, 'hex'),
            'UTF8'
        )), 'internal-sandbox-bootstrap-v3', exact_manifest_sha256,
        'internal-sandbox-bootstrap-v3', 'restricted-canonical-json-v1',
        'InternalSandboxIdentityBootstrap', exact_bootstrap_id, 'POST',
        '/v1/deployment/internal-sandbox/identity-bootstrap/' ||
            exact_bootstrap_id::text || '/' || lower(exact_action),
        before_revision, 'COMPLETED', 1,
        jsonb_build_object(
            'account_count', 6,
            'manifest_sha256', encode(exact_manifest_sha256, 'hex'),
            'outcome', base_outcome,
            'revision', manifest_revision
        ), NULL, transaction_timestamp(),
        transaction_timestamp() + interval '10 years',
        transaction_timestamp()
    );

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id, before_status,
        after_status, before_version, after_version, role_code, purpose_code,
        reason_code, auth_strength_code, result_code, command_id,
        correlation_id, causation_id, trace_id, safe_attributes
    ) VALUES (
        exact_audit_event_id, transaction_timestamp(), 'SYSTEM',
        exact_system_actor_id, NULL, bootstrap_command_name,
        'InternalSandboxIdentityBootstrap', exact_bootstrap_id, NULL,
        CASE WHEN base_outcome = 'APPLIED' THEN NULL ELSE 'ACTIVE' END,
        CASE WHEN base_outcome = 'REVOKED' THEN 'REVOKED' ELSE 'ACTIVE' END,
        before_revision, manifest_revision, NULL, 'INTERNAL_SANDBOX',
        'FINANCE_ROLE_GRAPH', NULL, 'SUCCEEDED', exact_command_id,
        exact_correlation_id, exact_command_id, exact_trace_id,
        jsonb_build_object(
            'account_count', 6,
            'finance_operator_count', 2,
            'manifest_sha256', encode(exact_manifest_sha256, 'hex'),
            'revision', manifest_revision
        )
    );

    RETURN QUERY SELECT base_outcome, manifest_revision, 6;
END
$function$;

ALTER FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v3(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v3(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v2(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
FROM iam_sandbox_bootstrap;
GRANT EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v3(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
TO iam_sandbox_bootstrap;

CREATE FUNCTION iam.finance_funding_authority_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT
    session_user = 'demand_finance'
    AND current_user = 'schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'FINANCE_FUNDING'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'LIST_FUNDING_REVIEWS',
        'GET_FUNDING_REVIEW',
        'CLAIM_FUNDING_REVIEW',
        'CONFIRM_FUNDING_REVIEW'
    )
    AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
$function$;

ALTER FUNCTION iam.finance_funding_authority_context_v1()
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.finance_funding_authority_context_v1()
FROM PUBLIC;

CREATE POLICY rls_finance_funding_iam_user_definer
ON iam.users
FOR ALL TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
)
WITH CHECK (
    iam.finance_funding_authority_context_v1()
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_finance_funding_iam_family_definer
ON iam.session_families
FOR ALL TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
)
WITH CHECK (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_finance_funding_iam_session_definer
ON iam.sessions
FOR ALL TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
)
WITH CHECK (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
);

CREATE POLICY rls_finance_funding_iam_duty_definer
ON iam.platform_duty_grants
FOR ALL TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
)
WITH CHECK (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_finance_funding_iam_user_role_definer
ON iam.user_role_grants
FOR SELECT TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_finance_funding_iam_membership_role_definer
ON iam.membership_role_grants
FOR SELECT TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE POLICY rls_finance_funding_iam_organization_definer
ON iam.organizations
FOR ALL TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND (
        id::text = NULLIF(current_setting('app.organization_id', true), '')
        OR EXISTS (
            SELECT 1
            FROM iam.memberships AS actor_membership
            WHERE actor_membership.organization_id = organizations.id
              AND actor_membership.user_id::text
                    = NULLIF(current_setting('app.actor_id', true), '')
        )
    )
)
WITH CHECK (
    iam.finance_funding_authority_context_v1()
    AND (
        id::text = NULLIF(current_setting('app.organization_id', true), '')
        OR EXISTS (
            SELECT 1
            FROM iam.memberships AS actor_membership
            WHERE actor_membership.organization_id = organizations.id
              AND actor_membership.user_id::text
                    = NULLIF(current_setting('app.actor_id', true), '')
        )
    )
);

CREATE POLICY rls_finance_funding_iam_membership_definer
ON iam.memberships
FOR ALL TO schema_owner
USING (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
)
WITH CHECK (
    iam.finance_funding_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE FUNCTION iam_api.finance_funding_principal_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid
)
RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    principal record;
    user_role_facts text;
    platform_duty_facts text;
    organization_facts text;
BEGIN
    IF exact_actor_user_id IS NULL
       OR exact_session_id IS NULL
       OR session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.finance_funding_authority_context_v1()
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN NULL;
    END IF;

    SELECT
        actor_user.aggregate_version AS user_version,
        actor_session.aggregate_version AS session_version,
        actor_session.family_id,
        actor_session.generation AS session_generation,
        actor_family.aggregate_version AS family_version,
        actor_family.current_generation AS family_generation
    INTO principal
    FROM iam.users AS actor_user
    JOIN iam.sessions AS actor_session
      ON actor_session.user_id = actor_user.id
    JOIN iam.session_families AS actor_family
      ON actor_family.id = actor_session.family_id
     AND actor_family.user_id = actor_session.user_id
    WHERE actor_user.id = exact_actor_user_id
      AND actor_user.status = 'ACTIVE'
      AND actor_session.id = exact_session_id
      AND actor_session.status = 'ACTIVE'
      AND actor_session.generation = actor_family.current_generation
      AND transaction_timestamp() < actor_session.idle_expires_at
      AND transaction_timestamp() < actor_session.absolute_expires_at
      AND actor_family.status = 'ACTIVE';
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT COALESCE(
        string_agg(
            role_grant.id::text || ':' || role_grant.role_code || ':'
                || role_grant.aggregate_version::text,
            ',' ORDER BY role_grant.id
        ),
        ''
    )
    INTO user_role_facts
    FROM iam.user_role_grants AS role_grant
    WHERE role_grant.user_id = exact_actor_user_id
      AND role_grant.granted_at <= transaction_timestamp()
      AND role_grant.revoked_at IS NULL;

    SELECT COALESCE(
        string_agg(
            duty_grant.id::text || ':' || duty_grant.duty_code || ':'
                || duty_grant.aggregate_version::text || ':'
                || COALESCE(
                    extract(epoch FROM duty_grant.expires_at)::text,
                    'none'
                ),
            ',' ORDER BY duty_grant.id
        ),
        ''
    )
    INTO platform_duty_facts
    FROM iam.platform_duty_grants AS duty_grant
    WHERE duty_grant.user_id = exact_actor_user_id
      AND duty_grant.granted_at <= transaction_timestamp()
      AND duty_grant.revoked_at IS NULL
      AND (
          duty_grant.expires_at IS NULL
          OR transaction_timestamp() < duty_grant.expires_at
      );

    SELECT COALESCE(
        string_agg(
            membership.organization_id::text || ':'
                || organization.aggregate_version::text || ':'
                || membership.id::text || ':'
                || membership.aggregate_version::text || ':'
                || role_grant.id::text || ':' || role_grant.role_code || ':'
                || role_grant.aggregate_version::text,
            ',' ORDER BY membership.organization_id, role_grant.id
        ),
        ''
    )
    INTO organization_facts
    FROM iam.memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'ACTIVE'
    JOIN iam.membership_role_grants AS role_grant
      ON role_grant.membership_id = membership.id
     AND role_grant.organization_id = membership.organization_id
     AND role_grant.user_id = membership.user_id
     AND role_grant.granted_at <= transaction_timestamp()
     AND role_grant.revoked_at IS NULL
    WHERE membership.user_id = exact_actor_user_id
      AND membership.status = 'ACTIVE';

    RETURN sha256(
        convert_to(
            concat_ws(
                E'\n',
                'editor-principal-marker-v1',
                exact_actor_user_id::text,
                exact_session_id::text,
                principal.user_version::text,
                principal.session_version::text,
                principal.family_id::text,
                principal.session_generation::text,
                principal.family_version::text,
                principal.family_generation::text,
                user_role_facts,
                platform_duty_facts,
                organization_facts
            ),
            'UTF8'
        )
    );
END
$function$;

CREATE FUNCTION iam_api.verify_finance_funding_principal_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam_api
AS $function$
DECLARE
    computed_marker bytea;
BEGIN
    IF expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.finance_funding_authority_context_v1()
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN false;
    END IF;
    computed_marker := iam_api.finance_funding_principal_marker_v1(
        exact_actor_user_id,
        exact_session_id
    );
    RETURN computed_marker IS NOT NULL
       AND computed_marker = expected_principal_marker_sha256;
END
$function$;

ALTER FUNCTION iam_api.finance_funding_principal_marker_v1(uuid, uuid)
OWNER TO schema_owner;
ALTER FUNCTION iam_api.verify_finance_funding_principal_marker_v1(
    uuid, uuid, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.finance_funding_principal_marker_v1(
    uuid, uuid
) FROM PUBLIC, demand_finance;
REVOKE ALL ON FUNCTION iam_api.verify_finance_funding_principal_marker_v1(
    uuid, uuid, bytea
) FROM PUBLIC, demand_finance;
GRANT EXECUTE ON FUNCTION iam_api.verify_finance_funding_principal_marker_v1(
    uuid, uuid, bytea
) TO demand_schema_owner;

CREATE FUNCTION iam_api.authorize_finance_funding_queue_v1(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF candidate_actor_user_id IS NULL
       OR candidate_actor_user_id = zero_uuid
       OR candidate_session_id IS NULL
       OR candidate_session_id = zero_uuid
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.finance_funding_authority_context_v1()
       OR NULLIF(current_setting('app.operation', true), '') NOT IN (
            'LIST_FUNDING_REVIEWS', 'GET_FUNDING_REVIEW'
       )
       OR NULLIF(current_setting('app.organization_id', true), '') IS NOT NULL
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NOT iam_api.verify_finance_funding_principal_marker_v1(
            candidate_actor_user_id,
            candidate_session_id,
            expected_principal_marker_sha256
       ) THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT duty.id, duty.aggregate_version, duty.expires_at
    FROM iam.platform_duty_grants AS duty
    WHERE duty.user_id = candidate_actor_user_id
      AND duty.duty_code = 'FINANCE_OPERATOR'
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (
          duty.expires_at IS NULL
          OR transaction_timestamp() < duty.expires_at
      );
END
$function$;

CREATE FUNCTION iam_api.lock_finance_funding_authority_v1(
    candidate_actor_user_id uuid,
    candidate_session_id uuid,
    candidate_organization_id uuid,
    candidate_demand_id uuid,
    candidate_operation text,
    expected_principal_marker_sha256 bytea
)
RETURNS TABLE (
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    locked_family_id uuid;
    locked_family_version bigint;
    locked_family_generation bigint;
    locked_session_version bigint;
    locked_session_generation bigint;
    locked_user_version bigint;
    locked_organization_version bigint;
    locked_duty_id uuid;
    locked_duty_version bigint;
    locked_duty_expires_at timestamptz;
    computed_marker bytea;
BEGIN
    IF candidate_actor_user_id IS NULL
       OR candidate_actor_user_id = zero_uuid
       OR candidate_session_id IS NULL
       OR candidate_session_id = zero_uuid
       OR candidate_organization_id IS NULL
       OR candidate_organization_id = zero_uuid
       OR candidate_demand_id IS NULL
       OR candidate_demand_id = zero_uuid
       OR candidate_operation NOT IN (
            'CLAIM_FUNDING_REVIEW', 'CONFIRM_FUNDING_REVIEW'
       )
       OR expected_principal_marker_sha256 IS NULL
       OR octet_length(expected_principal_marker_sha256) <> 32
       OR session_user IS DISTINCT FROM 'demand_finance'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.finance_funding_authority_context_v1()
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM candidate_operation
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM candidate_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM candidate_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM candidate_organization_id::text
       OR NULLIF(current_setting('app.demand_id', true), '')
            IS DISTINCT FROM candidate_demand_id::text
       OR NOT iam_api.verify_finance_funding_principal_marker_v1(
            candidate_actor_user_id,
            candidate_session_id,
            expected_principal_marker_sha256
       ) THEN
        RETURN;
    END IF;

    SELECT family.id, family.aggregate_version, family.current_generation
    INTO locked_family_id, locked_family_version, locked_family_generation
    FROM iam.session_families AS family
    WHERE family.user_id = candidate_actor_user_id
      AND family.status = 'ACTIVE'
      AND family.revoked_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM iam.sessions AS candidate_session
          WHERE candidate_session.id = candidate_session_id
            AND candidate_session.family_id = family.id
            AND candidate_session.user_id = candidate_actor_user_id
      )
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT active_session.aggregate_version, active_session.generation
    INTO locked_session_version, locked_session_generation
    FROM iam.sessions AS active_session
    WHERE active_session.id = candidate_session_id
      AND active_session.family_id = locked_family_id
      AND active_session.user_id = candidate_actor_user_id
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = locked_family_generation
      AND active_session.last_activity_at <= transaction_timestamp()
      AND active_session.last_activity_at < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT actor.aggregate_version
    INTO locked_user_version
    FROM iam.users AS actor
    WHERE actor.id = candidate_actor_user_id
      AND actor.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT organization.aggregate_version
    INTO locked_organization_version
    FROM iam.organizations AS organization
    WHERE organization.id = candidate_organization_id
      AND organization.status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM 1
    FROM iam.memberships AS membership
    WHERE membership.organization_id = candidate_organization_id
      AND membership.user_id = candidate_actor_user_id
      AND membership.status = 'ACTIVE'
    FOR UPDATE;
    IF FOUND THEN RETURN; END IF;

    SELECT duty.id, duty.aggregate_version, duty.expires_at
    INTO locked_duty_id, locked_duty_version, locked_duty_expires_at
    FROM iam.platform_duty_grants AS duty
    WHERE duty.user_id = candidate_actor_user_id
      AND duty.duty_code = 'FINANCE_OPERATOR'
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (
          duty.expires_at IS NULL
          OR transaction_timestamp() < duty.expires_at
      )
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    IF NOT iam_api.verify_finance_funding_principal_marker_v1(
        candidate_actor_user_id,
        candidate_session_id,
        expected_principal_marker_sha256
    ) THEN
        RETURN;
    END IF;

    computed_marker := sha256(convert_to(
        'iam-finance-funding-authority-v1|' || candidate_operation || '|' ||
        candidate_actor_user_id::text || '|' || candidate_session_id::text ||
        '|' || candidate_organization_id::text || '|' ||
        candidate_demand_id::text || '|' || locked_family_id::text || '|' ||
        locked_family_version::text || '|' ||
        locked_family_generation::text || '|' ||
        locked_session_version::text || '|' ||
        locked_session_generation::text || '|' || locked_user_version::text ||
        '|' || locked_organization_version::text || '|' ||
        locked_duty_id::text || '|' || locked_duty_version::text || '|' ||
        COALESCE(extract(epoch FROM locked_duty_expires_at)::text, 'none') ||
        '|' || encode(expected_principal_marker_sha256, 'hex'),
        'UTF8'
    ));

    RETURN QUERY SELECT
        locked_duty_id,
        locked_duty_version,
        locked_duty_expires_at,
        computed_marker;
END
$function$;

ALTER FUNCTION iam_api.authorize_finance_funding_queue_v1(
    uuid, uuid, bytea
) OWNER TO schema_owner;
ALTER FUNCTION iam_api.lock_finance_funding_authority_v1(
    uuid, uuid, uuid, uuid, text, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.authorize_finance_funding_queue_v1(
    uuid, uuid, bytea
) FROM PUBLIC, demand_finance;
REVOKE ALL ON FUNCTION iam_api.lock_finance_funding_authority_v1(
    uuid, uuid, uuid, uuid, text, bytea
) FROM PUBLIC, demand_finance;
GRANT USAGE ON SCHEMA iam_api TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.authorize_finance_funding_queue_v1(
    uuid, uuid, bytea
) TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.lock_finance_funding_authority_v1(
    uuid, uuid, uuid, uuid, text, bytea
) TO demand_schema_owner;

DO $assertions$
BEGIN
    IF pg_catalog.has_function_privilege(
        'iam_sandbox_bootstrap',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v2(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'iam_sandbox_bootstrap',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v3(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_finance',
        'iam_api.authorize_finance_funding_queue_v1(uuid,uuid,bytea)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'demand_finance',
        'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'demand_schema_owner',
        'iam_api.verify_finance_funding_principal_marker_v1(uuid,uuid,bytea)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'demand_schema_owner',
        'iam_api.authorize_finance_funding_queue_v1(uuid,uuid,bytea)',
        'EXECUTE'
    ) OR NOT pg_catalog.has_function_privilege(
        'demand_schema_owner',
        'iam_api.lock_finance_funding_authority_v1(uuid,uuid,uuid,uuid,text,bytea)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'finance funding IAM authority assertion failed';
    END IF;
END
$assertions$;
