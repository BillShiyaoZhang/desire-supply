-- IAM 0036: exact Trust/Appeal authorities, ten-account sandbox bootstrap,
-- and durable current-Session logout.  IAM0000..0035 remain byte-immutable.

DO $iam36_online_role_guard$
DECLARE
    expected_role text;
    actual record;
BEGIN
    FOREACH expected_role IN ARRAY ARRAY[
        'trust_self', 'trust_officer', 'trust_appeal', 'trust_decision'
    ] LOOP
        SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
               rolbypassrls
        INTO actual
        FROM pg_catalog.pg_roles
        WHERE rolname = expected_role;
        IF NOT FOUND
           OR NOT actual.rolcanlogin
           OR actual.rolinherit
           OR actual.rolsuper
           OR actual.rolcreatedb
           OR actual.rolcreaterole
           OR actual.rolbypassrls THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_iam36_online_role_attributes',
                MESSAGE = 'Trust online database roles are not provisioned';
        END IF;
    END LOOP;
END;
$iam36_online_role_guard$;

CREATE FUNCTION iam.internal_sandbox_derived_uuid_v3(
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
    substr(digest, 1, 8) || '-' || substr(digest, 9, 4) || '-' ||
    substr(digest, 13, 4) || '-' || substr(digest, 17, 4) || '-' ||
    substr(digest, 21, 12)
)::uuid
FROM (
    SELECT pg_catalog.md5(exact_domain || '|' || exact_source_id::text) AS digest
) AS derived
WHERE exact_domain IN (
    'trust-appeal-bootstrap-command',
    'trust-appeal-bootstrap-receipt',
    'trust-appeal-bootstrap-audit'
)
  AND exact_source_id IS NOT NULL
$function$;

ALTER FUNCTION iam.internal_sandbox_derived_uuid_v3(text, uuid)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_derived_uuid_v3(text, uuid)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_manifest_v5_valid(
    exact_manifest jsonb,
    exact_bootstrap_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    account jsonb;
    code text;
    owner_organization_id uuid;
    admin_organization_id uuid;
BEGIN
    IF exact_bootstrap_id IS NULL
       OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
            exact_manifest,
            ARRAY[
                'accounts', 'bootstrap_id', 'environment_id', 'issuer',
                'policy', 'previous_manifest_sha256', 'revision', 'schema_name'
            ]
       )
       OR exact_manifest->>'schema_name'
            <> 'desire-internal-sandbox-identity-bootstrap-v1'
       OR exact_manifest->>'environment_id' <> 'internal-sandbox'
       OR (exact_manifest->>'bootstrap_id')::uuid <> exact_bootstrap_id
       OR jsonb_typeof(exact_manifest->'accounts') <> 'array'
       OR jsonb_array_length(exact_manifest->'accounts') <> 10
       OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
            exact_manifest->'policy',
            ARRAY[
                'creator_bundle_id', 'demand_owner_bundle_id',
                'document_id', 'org_admin_bundle_id'
            ]
       )
       OR (
            SELECT array_agg(item.value->>'account_code' ORDER BY 1)
            FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
       ) <> ARRAY[
            'access_admin_01', 'appeal_reviewer_01', 'creator_01',
            'demand_owner_01', 'finance_operator_01',
            'finance_operator_02', 'operations_reviewer_01',
            'org_admin_01', 'trust_officer_01', 'trust_officer_02'
       ]::text[] THEN
        RETURN false;
    END IF;

    PERFORM (exact_manifest#>>'{policy,creator_bundle_id}')::uuid,
            (exact_manifest#>>'{policy,demand_owner_bundle_id}')::uuid,
            (exact_manifest#>>'{policy,document_id}')::uuid,
            (exact_manifest#>>'{policy,org_admin_bundle_id}')::uuid;

    FOR account IN
        SELECT item.value
        FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    LOOP
        code := account->>'account_code';
        IF NOT iam.sandbox_jsonb_has_exact_keys_v1(
                account,
                ARRAY[
                    'account_code', 'activation_event_id', 'contact_point',
                    'creator_grant', 'demand_owner_grant', 'external_identity',
                    'organization_grant', 'platform_duty_grants',
                    'revocation_event_id', 'user_id'
                ]
           )
           OR jsonb_typeof(account->'platform_duty_grants') <> 'array'
           OR (CASE code
                WHEN 'access_admin_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'ACCESS_ADMIN'
                )
                WHEN 'appeal_reviewer_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'APPEAL_REVIEWER'
                )
                WHEN 'creator_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 0
                )
                WHEN 'demand_owner_01' THEN NOT (
                    iam.sandbox_jsonb_has_exact_keys_v1(
                        account->'demand_owner_grant',
                        ARRAY[
                            'grant_id', 'invitation_id', 'membership_id',
                            'organization_id'
                        ]
                    )
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 0
                )
                WHEN 'finance_operator_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'FINANCE_OPERATOR'
                )
                WHEN 'finance_operator_02' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'FINANCE_OPERATOR'
                )
                WHEN 'operations_reviewer_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'OPERATIONS_REVIEWER'
                )
                WHEN 'org_admin_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND iam.sandbox_jsonb_has_exact_keys_v1(
                        account->'organization_grant',
                        ARRAY[
                            'grant_id', 'invitation_id', 'membership_id',
                            'organization_id', 'role_code'
                        ]
                    )
                    AND account#>>'{organization_grant,role_code}' = 'ORG_ADMIN'
                    AND jsonb_array_length(account->'platform_duty_grants') = 0
                )
                WHEN 'trust_officer_01' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'TRUST_OFFICER'
                )
                WHEN 'trust_officer_02' THEN NOT (
                    jsonb_typeof(account->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account->'organization_grant') = 'null'
                    AND jsonb_array_length(account->'platform_duty_grants') = 1
                    AND account#>>'{platform_duty_grants,0,duty_code}'
                        = 'TRUST_OFFICER'
                )
                ELSE true
              END) THEN
            RETURN false;
        END IF;
    END LOOP;

    SELECT (item.value#>>'{demand_owner_grant,organization_id}')::uuid
    INTO owner_organization_id
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' = 'demand_owner_01';
    SELECT (item.value#>>'{organization_grant,organization_id}')::uuid
    INTO admin_organization_id
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' = 'org_admin_01';
    RETURN owner_organization_id IS NOT NULL
       AND owner_organization_id = admin_organization_id;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$function$;

ALTER FUNCTION iam.internal_sandbox_manifest_v5_valid(jsonb, uuid)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_manifest_v5_valid(jsonb, uuid)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_independent_role_graph_v5(
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
    SELECT item.value AS document,
           item.value->>'account_code' AS account_code,
           (item.value->>'user_id')::uuid AS user_id,
           (item.value#>>'{creator_grant,grant_id}')::uuid AS creator_grant_id,
           CASE WHEN jsonb_array_length(item.value->'platform_duty_grants') = 1
                THEN (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
           END AS duty_grant_id,
           CASE WHEN jsonb_array_length(item.value->'platform_duty_grants') = 1
                THEN item.value#>>'{platform_duty_grants,0,duty_code}'
           END AS duty_code,
           CASE WHEN jsonb_typeof(item.value->'demand_owner_grant') = 'object'
                THEN (item.value#>>'{demand_owner_grant,grant_id}')::uuid
           END AS demand_grant_id,
           CASE WHEN jsonb_typeof(item.value->'demand_owner_grant') = 'object'
                THEN (item.value#>>'{demand_owner_grant,invitation_id}')::uuid
           END AS demand_invitation_id,
           CASE WHEN jsonb_typeof(item.value->'demand_owner_grant') = 'object'
                THEN (item.value#>>'{demand_owner_grant,membership_id}')::uuid
           END AS demand_membership_id,
           CASE WHEN jsonb_typeof(item.value->'demand_owner_grant') = 'object'
                THEN (item.value#>>'{demand_owner_grant,organization_id}')::uuid
           END AS demand_organization_id,
           CASE WHEN jsonb_typeof(item.value->'organization_grant') = 'object'
                THEN (item.value#>>'{organization_grant,grant_id}')::uuid
           END AS org_grant_id,
           CASE WHEN jsonb_typeof(item.value->'organization_grant') = 'object'
                THEN (item.value#>>'{organization_grant,invitation_id}')::uuid
           END AS org_invitation_id,
           CASE WHEN jsonb_typeof(item.value->'organization_grant') = 'object'
                THEN (item.value#>>'{organization_grant,membership_id}')::uuid
           END AS org_membership_id,
           CASE WHEN jsonb_typeof(item.value->'organization_grant') = 'object'
                THEN (item.value#>>'{organization_grant,organization_id}')::uuid
           END AS org_organization_id
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
), bootstrap_users AS (
    SELECT user_id FROM accounts
), active_roles AS (
    SELECT role_row.*
    FROM iam.user_role_grants AS role_row
    JOIN accounts AS account ON account.user_id = role_row.user_id
    WHERE role_row.revoked_at IS NULL
), isolated_roles AS (
    SELECT role_row.*
    FROM iam.user_role_grants AS role_row
    JOIN accounts AS account
      ON account.user_id = role_row.user_id
     AND account.creator_grant_id = role_row.id
    WHERE account.account_code <> 'creator_01'
      AND role_row.role_code = 'CREATOR'
      AND role_row.revoked_at IS NOT NULL
      AND role_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
), active_duties AS (
    SELECT duty.*
    FROM iam.platform_duty_grants AS duty
    JOIN accounts AS account ON account.user_id = duty.user_id
    WHERE duty.revoked_at IS NULL
), active_membership_roles AS (
    SELECT grant_row.*
    FROM iam.membership_role_grants AS grant_row
    JOIN accounts AS account
      ON account.user_id = grant_row.user_id
     AND grant_row.id IN (account.demand_grant_id, account.org_grant_id)
    WHERE grant_row.revoked_at IS NULL
)
SELECT
    (SELECT count(*) FROM accounts) = 10
    AND EXISTS (
        SELECT 1 FROM infra.iam_sandbox_bootstrap_state AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
          AND state.account_count = 10
          AND state.status = 'ACTIVE'
          AND state.revision IN (
              (exact_manifest->>'revision')::integer,
              (exact_manifest->>'revision')::integer - 1
          )
    )
    AND (
        SELECT count(*)
        FROM infra.iam_sandbox_bootstrap_accounts AS state
        JOIN accounts AS account
          ON account.account_code = state.account_code
         AND account.user_id = state.user_id
         AND state.authority_shape_sha256 = sha256(convert_to(
             (account.document - ARRAY[
                 'activation_event_id', 'contact_point',
                 'external_identity', 'revocation_event_id'
             ])::text, 'UTF8'
         ))
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 10
    AND (
        SELECT count(*) FROM infra.iam_sandbox_bootstrap_accounts AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 10
    AND (
        SELECT count(*) FROM iam.users AS exact_user
        JOIN accounts AS account ON account.user_id = exact_user.id
        WHERE exact_user.status = 'ACTIVE'
          AND exact_user.display_handle = 'sandbox_' || account.account_code
    ) = 10
    AND (SELECT count(*) FROM active_roles) = 1
    AND EXISTS (
        SELECT 1 FROM active_roles AS role_row
        JOIN accounts AS account
          ON account.user_id = role_row.user_id
         AND account.creator_grant_id = role_row.id
        WHERE account.account_code = 'creator_01'
          AND role_row.role_code = 'CREATOR'
    )
    AND (SELECT count(*) FROM isolated_roles) = 9
    AND (SELECT count(*) FROM active_duties) = 7
    AND (
        SELECT count(*) FROM active_duties AS duty
        JOIN accounts AS account
          ON account.user_id = duty.user_id
         AND account.duty_grant_id = duty.id
         AND account.duty_code = duty.duty_code
        WHERE (account.account_code = 'access_admin_01'
               AND duty.duty_code = 'ACCESS_ADMIN')
           OR (account.account_code = 'appeal_reviewer_01'
               AND duty.duty_code = 'APPEAL_REVIEWER')
           OR (account.account_code IN (
                    'finance_operator_01', 'finance_operator_02'
               ) AND duty.duty_code = 'FINANCE_OPERATOR')
           OR (account.account_code = 'operations_reviewer_01'
               AND duty.duty_code = 'OPERATIONS_REVIEWER')
           OR (account.account_code IN (
                    'trust_officer_01', 'trust_officer_02'
               )
               AND duty.duty_code = 'TRUST_OFFICER')
    ) = 7
    AND (SELECT count(*) FROM active_membership_roles) = 2
    AND EXISTS (
        SELECT 1 FROM accounts AS owner
        JOIN iam.access_invitations AS invitation
          ON invitation.id = owner.demand_invitation_id
         AND invitation.organization_id = owner.demand_organization_id
         AND invitation.target_role = 'DEMAND_OWNER'
         AND invitation.status = 'ACCEPTED'
         AND invitation.accepted_by_user_id = owner.user_id
        JOIN iam.memberships AS membership
          ON membership.id = owner.demand_membership_id
         AND membership.organization_id = owner.demand_organization_id
         AND membership.user_id = owner.user_id
         AND membership.source_invitation_id = invitation.id
         AND membership.status = 'ACTIVE'
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.id = owner.demand_grant_id
         AND grant_row.membership_id = membership.id
         AND grant_row.organization_id = membership.organization_id
         AND grant_row.user_id = owner.user_id
         AND grant_row.source_invitation_id = invitation.id
         AND grant_row.role_code = 'DEMAND_OWNER'
         AND grant_row.revoked_at IS NULL
        WHERE owner.account_code = 'demand_owner_01'
    )
    AND EXISTS (
        SELECT 1 FROM accounts AS admin
        JOIN iam.access_invitations AS invitation
          ON invitation.id = admin.org_invitation_id
         AND invitation.organization_id = admin.org_organization_id
         AND invitation.purpose = 'ORGANIZATION_MEMBERSHIP'
         AND invitation.target_scope = 'ORGANIZATION'
         AND invitation.target_role = 'ORG_ADMIN'
         AND invitation.is_initial_admin
         AND invitation.masked_recipient_label = 'sandbox-account'
         AND invitation.issued_policy_bundle_id =
                (exact_manifest#>>'{policy,org_admin_bundle_id}')::uuid
         AND invitation.status = 'ACCEPTED'
         AND invitation.token_key_id = 'internal-sandbox-bootstrap-v4'
         AND invitation.token_format_version = 'access-invitation-token-v1'
         AND invitation.accepted_by_user_id = admin.user_id
         AND invitation.aggregate_version = 2
        JOIN iam.policy_selectors AS selector
          ON selector.selector_digest = invitation.policy_selector_digest
         AND selector.current_bundle_id = invitation.issued_policy_bundle_id
         AND selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
         AND selector.scope_type = 'ORGANIZATION_ROLE'
         AND selector.target_role = 'ORG_ADMIN'
         AND selector.jurisdiction = 'ZZ_INTERNAL'
         AND selector.locale = 'en'
        JOIN iam.policy_bundles AS bundle
          ON bundle.id = selector.current_bundle_id
         AND bundle.selector_digest = selector.selector_digest
         AND bundle.status = 'ACTIVE'
         AND bundle.release_signing_key_id = 'internal-sandbox-bootstrap-v4'
         AND bundle.aggregate_version = 2
        JOIN iam.memberships AS membership
          ON membership.id = admin.org_membership_id
         AND membership.organization_id = admin.org_organization_id
         AND membership.user_id = admin.user_id
         AND membership.source_invitation_id = invitation.id
         AND membership.status = 'ACTIVE'
         AND membership.aggregate_version = 1
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.id = admin.org_grant_id
         AND grant_row.membership_id = membership.id
         AND grant_row.organization_id = membership.organization_id
         AND grant_row.user_id = admin.user_id
         AND grant_row.source_invitation_id = invitation.id
         AND grant_row.policy_selector_digest = selector.selector_digest
         AND grant_row.role_code = 'ORG_ADMIN'
         AND grant_row.revoked_at IS NULL
         AND grant_row.aggregate_version = 1
        WHERE admin.account_code = 'org_admin_01'
          AND admin.org_organization_id = (
              SELECT demand_organization_id FROM accounts
              WHERE account_code = 'demand_owner_01'
          )
    )
    AND NOT EXISTS (
        SELECT 1 FROM iam.sessions AS session_row
        JOIN bootstrap_users AS exact_user
          ON exact_user.user_id = session_row.user_id
        WHERE session_row.status = 'ACTIVE'
          AND NOT EXISTS (
              SELECT 1 FROM iam.session_families AS family
              WHERE family.id = session_row.family_id
                AND family.user_id = session_row.user_id
                AND family.status = 'ACTIVE'
                AND family.current_generation = session_row.generation
          )
    )
$function$;

ALTER FUNCTION iam.internal_sandbox_independent_role_graph_v5(jsonb)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_independent_role_graph_v5(jsonb)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_normalize_trust_appeal_graph_v1(
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
    org_admin jsonb;
    temporary_membership_id uuid;
    temporary_grant_id uuid;
    affected integer;
BEGIN
    IF NOT iam.internal_sandbox_bootstrap_context_v1()
       OR jsonb_array_length(exact_manifest->'accounts') <> 10
       OR jsonb_array_length(exact_normalized_manifest->'accounts') <> 10
       OR exact_normalized_manifest_sha256 IS NULL
       OR octet_length(exact_normalized_manifest_sha256) <> 32
       OR NOT iam.internal_sandbox_independent_role_graph_v5(exact_manifest)
    THEN RETURN false;
    END IF;

    SELECT item.value INTO org_admin
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' = 'org_admin_01';
    IF NOT FOUND THEN RETURN false; END IF;
    temporary_membership_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-membership',
        (org_admin#>>'{organization_grant,membership_id}')::uuid
    );
    temporary_grant_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-grant',
        (org_admin#>>'{organization_grant,grant_id}')::uuid
    );

    UPDATE infra.iam_sandbox_bootstrap_state
    SET manifest_sha256 = exact_normalized_manifest_sha256,
        updated_at = transaction_timestamp()
    WHERE bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND status = 'ACTIVE' AND account_count = 10;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN RETURN false; END IF;

    UPDATE infra.iam_sandbox_bootstrap_accounts AS state
    SET authority_shape_sha256 = sha256(convert_to(
            (item.value - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text, 'UTF8'
        )), updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_normalized_manifest->'accounts') AS item(value)
    WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND state.account_code = item.value->>'account_code'
      AND state.user_id = (item.value->>'user_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 10 THEN RETURN false; END IF;

    UPDATE iam.platform_duty_grants AS duty
    SET duty_code = 'OPERATIONS_REVIEWER',
        updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' IN (
            'finance_operator_01', 'finance_operator_02',
            'trust_officer_01', 'trust_officer_02', 'appeal_reviewer_01'
      )
      AND duty.id = (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
      AND duty.user_id = (item.value->>'user_id')::uuid
      AND duty.duty_code = item.value#>>'{platform_duty_grants,0,duty_code}';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 5 THEN RETURN false; END IF;

    PERFORM set_config('app.bootstrap_role_isolation_transition', 'RESTORE', true);
    UPDATE iam.user_role_grants AS role_row
    SET revoked_at = NULL, revocation_reason_code = NULL,
        aggregate_version = role_row.aggregate_version + 1
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' <> 'creator_01'
      AND role_row.id = (item.value#>>'{creator_grant,grant_id}')::uuid
      AND role_row.user_id = (item.value->>'user_id')::uuid
      AND role_row.role_code = 'CREATOR'
      AND role_row.revoked_at IS NOT NULL
      AND role_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 9 THEN
        PERFORM set_config('app.bootstrap_role_isolation_transition', '', true);
        RETURN false;
    END IF;

    UPDATE iam.memberships
    SET status = 'ACTIVE', aggregate_version = aggregate_version + 1,
        updated_at = transaction_timestamp()
    WHERE id = temporary_membership_id AND status = 'REVOKED';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        PERFORM set_config('app.bootstrap_role_isolation_transition', '', true);
        RETURN false;
    END IF;
    UPDATE iam.membership_role_grants
    SET revoked_at = NULL, revocation_reason_code = NULL,
        aggregate_version = aggregate_version + 1
    WHERE id = temporary_grant_id
      AND role_code = 'DEMAND_OWNER'
      AND revoked_at IS NOT NULL
      AND revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION';
    GET DIAGNOSTICS affected = ROW_COUNT;
    PERFORM set_config('app.bootstrap_role_isolation_transition', '', true);
    RETURN affected = 1;
END;
$function$;

ALTER FUNCTION iam.internal_sandbox_normalize_trust_appeal_graph_v1(
    jsonb, jsonb, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_normalize_trust_appeal_graph_v1(
    jsonb, jsonb, bytea
) FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_apply_trust_appeal_graph_v1(
    exact_manifest jsonb,
    exact_manifest_sha256 bytea,
    isolate_roles boolean
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
       OR jsonb_array_length(exact_manifest->'accounts') <> 10
       OR exact_manifest_sha256 IS NULL
       OR octet_length(exact_manifest_sha256) <> 32
       OR isolate_roles IS NULL THEN
        RETURN false;
    END IF;

    UPDATE iam.platform_duty_grants AS duty
    SET duty_code = item.value#>>'{platform_duty_grants,0,duty_code}',
        updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' IN (
            'trust_officer_01', 'trust_officer_02', 'appeal_reviewer_01'
      )
      AND duty.id = (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
      AND duty.user_id = (item.value->>'user_id')::uuid
      AND duty.duty_code = 'OPERATIONS_REVIEWER';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 3 THEN RETURN false; END IF;

    IF isolate_roles THEN
        UPDATE iam.user_role_grants AS role_row
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION',
            aggregate_version = role_row.aggregate_version + 1
        FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
        WHERE item.value->>'account_code' IN (
                'trust_officer_01', 'trust_officer_02', 'appeal_reviewer_01'
          )
          AND role_row.id = (item.value#>>'{creator_grant,grant_id}')::uuid
          AND role_row.user_id = (item.value->>'user_id')::uuid
          AND role_row.role_code = 'CREATOR'
          AND role_row.revoked_at IS NULL;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 3 THEN RETURN false; END IF;
    END IF;

    UPDATE infra.iam_sandbox_bootstrap_accounts AS state
    SET authority_shape_sha256 = sha256(convert_to(
            (item.value - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text, 'UTF8'
        )), updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' IN (
            'trust_officer_01', 'trust_officer_02', 'appeal_reviewer_01'
      )
      AND state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND state.account_code = item.value->>'account_code'
      AND state.user_id = (item.value->>'user_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 3 THEN RETURN false; END IF;

    UPDATE infra.iam_sandbox_bootstrap_state
    SET manifest_sha256 = exact_manifest_sha256,
        updated_at = transaction_timestamp()
    WHERE bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND account_count = 10;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN RETURN false; END IF;

    RETURN NOT isolate_roles
        OR iam.internal_sandbox_independent_role_graph_v5(exact_manifest);
END;
$function$;

ALTER FUNCTION iam.internal_sandbox_apply_trust_appeal_graph_v1(
    jsonb, bytea, boolean
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_apply_trust_appeal_graph_v1(
    jsonb, bytea, boolean
) FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_revoked_role_graph_v5(
    exact_manifest jsonb,
    exact_manifest_sha256 bytea
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, iam, infra
AS $function$
WITH accounts AS (
    SELECT item.value AS document,
           item.value->>'account_code' AS account_code,
           (item.value->>'user_id')::uuid AS user_id
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
), bootstrap_users AS (
    SELECT user_id FROM accounts
)
SELECT exact_manifest_sha256 IS NOT NULL
    AND octet_length(exact_manifest_sha256) = 32
    AND (SELECT count(*) FROM accounts) = 10
    AND EXISTS (
        SELECT 1 FROM infra.iam_sandbox_bootstrap_state AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
          AND state.manifest_sha256 = exact_manifest_sha256
          AND state.revision = (exact_manifest->>'revision')::integer
          AND state.issuer = exact_manifest->>'issuer'
          AND state.account_count = 10
          AND state.status = 'REVOKED'
    )
    AND (
        SELECT count(*)
        FROM infra.iam_sandbox_bootstrap_accounts AS state
        JOIN accounts AS account
          ON account.account_code = state.account_code
         AND account.user_id = state.user_id
         AND state.current_external_identity_id =
                (account.document#>>'{external_identity,id}')::uuid
         AND state.current_subject_digest = decode(
                account.document#>>'{external_identity,subject_digest_sha256}',
                'hex'
             )
         AND state.current_contact_point_id =
                (account.document#>>'{contact_point,id}')::uuid
         AND state.authority_shape_sha256 = sha256(convert_to(
                (account.document - ARRAY[
                    'activation_event_id', 'contact_point',
                    'external_identity', 'revocation_event_id'
                ])::text, 'UTF8'
             ))
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 10
    AND (
        SELECT count(*) FROM infra.iam_sandbox_bootstrap_accounts AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 10
    AND (
        SELECT count(*) FROM iam.users AS exact_user
        JOIN accounts AS account ON account.user_id = exact_user.id
        WHERE exact_user.status = 'SUSPENDED'
          AND exact_user.display_handle = 'sandbox_' || account.account_code
    ) = 10
    AND (
        SELECT count(*) FROM iam.external_identities AS identity
        JOIN accounts AS account
          ON identity.id = (account.document#>>'{external_identity,id}')::uuid
         AND identity.user_id = account.user_id
        WHERE identity.status = 'REVOKED'
          AND identity.issuer = exact_manifest->>'issuer'
    ) = 10
    AND NOT EXISTS (
        SELECT 1 FROM iam.user_role_grants AS grant_row
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = grant_row.user_id
        WHERE grant_row.revoked_at IS NULL
    )
    AND NOT EXISTS (
        SELECT 1 FROM iam.membership_role_grants AS grant_row
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = grant_row.user_id
        WHERE grant_row.revoked_at IS NULL
    )
    AND NOT EXISTS (
        SELECT 1 FROM iam.memberships AS membership
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = membership.user_id
        WHERE membership.status <> 'REVOKED'
    )
    AND NOT EXISTS (
        SELECT 1 FROM iam.platform_duty_grants AS duty
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = duty.user_id
        WHERE duty.revoked_at IS NULL
    )
    AND NOT EXISTS (
        SELECT 1 FROM iam.sessions AS session_row
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = session_row.user_id
        WHERE session_row.status = 'ACTIVE'
    )
    AND NOT EXISTS (
        SELECT 1 FROM iam.session_families AS family
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = family.user_id
        WHERE family.status = 'ACTIVE'
    )
$function$;

ALTER FUNCTION iam.internal_sandbox_revoked_role_graph_v5(jsonb, bytea)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_revoked_role_graph_v5(jsonb, bytea)
FROM PUBLIC;

CREATE FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v5(
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
    filtered_org_manifest jsonb;
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
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_invocation',
            MESSAGE = 'internal sandbox Trust/Appeal bootstrap invocation invalid';
    END IF;

    BEGIN
        manifest_document := convert_from(exact_canonical_manifest, 'UTF8')::jsonb;
        manifest_revision := (manifest_document->>'revision')::integer;
        IF NOT iam.internal_sandbox_manifest_v5_valid(
            manifest_document, exact_bootstrap_id
        ) THEN RAISE EXCEPTION 'closed manifest rejected';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_manifest',
            MESSAGE = 'internal sandbox Trust/Appeal bootstrap manifest invalid';
    END;

    SELECT jsonb_set(
        jsonb_set(
            manifest_document,
            '{policy}',
            (manifest_document->'policy') - 'org_admin_bundle_id'::text,
            false
        ),
        '{accounts}',
        jsonb_agg(
            CASE
                WHEN item.value->>'account_code' IN (
                    'finance_operator_01', 'finance_operator_02',
                    'trust_officer_01', 'trust_officer_02',
                    'appeal_reviewer_01'
                ) THEN jsonb_set(
                    item.value - 'organization_grant'::text,
                    '{platform_duty_grants,0,duty_code}',
                    to_jsonb('OPERATIONS_REVIEWER'::text), false
                )
                WHEN item.value->>'account_code' = 'org_admin_01' THEN
                    jsonb_set(
                        item.value - 'organization_grant'::text,
                        '{demand_owner_grant}',
                        jsonb_build_object(
                            'grant_id', iam.internal_sandbox_derived_uuid_v2(
                                'org-admin-bootstrap-grant',
                                (item.value#>>'{organization_grant,grant_id}')::uuid
                            ),
                            'invitation_id', iam.internal_sandbox_derived_uuid_v2(
                                'org-admin-bootstrap-invitation',
                                (item.value#>>'{organization_grant,invitation_id}')::uuid
                            ),
                            'membership_id', iam.internal_sandbox_derived_uuid_v2(
                                'org-admin-bootstrap-membership',
                                (item.value#>>'{organization_grant,membership_id}')::uuid
                            ),
                            'organization_id', iam.internal_sandbox_derived_uuid_v2(
                                'org-admin-bootstrap-organization',
                                (item.value#>>'{organization_grant,membership_id}')::uuid
                            )
                        ), false
                    )
                ELSE item.value - 'organization_grant'::text
            END
            ORDER BY item.value->>'account_code'
        ), false
    ) INTO normalized_manifest
    FROM jsonb_array_elements(manifest_document->'accounts') AS item(value);

    SELECT jsonb_set(
        manifest_document, '{accounts}',
        jsonb_agg(item.value ORDER BY item.value->>'account_code'), false
    ) INTO filtered_org_manifest
    FROM jsonb_array_elements(manifest_document->'accounts') AS item(value)
    WHERE item.value->>'account_code' NOT IN (
        'trust_officer_01', 'trust_officer_02', 'appeal_reviewer_01'
    );

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
                CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_bridge',
                MESSAGE = 'internal sandbox Trust/Appeal bridge missing';
        END IF;
        normalized_manifest := jsonb_set(
            normalized_manifest, '{previous_manifest_sha256}',
            to_jsonb(encode(previous_normalized_digest, 'hex')), false
        );
    END IF;

    normalized_manifest_bytes := convert_to(normalized_manifest::text, 'UTF8');
    normalized_manifest_digest := sha256(normalized_manifest_bytes);
    IF normalized_manifest_digest = exact_manifest_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_normalization',
            MESSAGE = 'internal sandbox Trust/Appeal normalization invalid';
    END IF;

    internal_command_id := iam.internal_sandbox_derived_uuid_v3(
        'trust-appeal-bootstrap-command', exact_command_id
    );
    internal_receipt_id := iam.internal_sandbox_derived_uuid_v3(
        'trust-appeal-bootstrap-receipt', exact_receipt_id
    );
    internal_audit_event_id := iam.internal_sandbox_derived_uuid_v3(
        'trust-appeal-bootstrap-audit', exact_audit_event_id
    );
    IF internal_command_id IS NULL OR internal_receipt_id IS NULL
       OR internal_audit_event_id IS NULL
       OR cardinality(ARRAY[
            exact_command_id, exact_receipt_id, exact_audit_event_id,
            internal_command_id, internal_receipt_id, internal_audit_event_id
       ]) <> cardinality(ARRAY(
            SELECT DISTINCT identifier FROM unnest(ARRAY[
                exact_command_id, exact_receipt_id, exact_audit_event_id,
                internal_command_id, internal_receipt_id,
                internal_audit_event_id
            ]) AS identifier
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_identifiers',
            MESSAGE = 'internal sandbox Trust/Appeal identifiers invalid';
    END IF;

    PERFORM pg_advisory_xact_lock(1229016369, 36);
    SELECT * INTO state_row
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.bootstrap_id = exact_bootstrap_id
    FOR UPDATE;
    state_found := FOUND;

    IF state_found AND state_row.status = 'REVOKED' THEN
        SELECT bridge.normalized_manifest_sha256
        INTO current_normalized_digest
        FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
        WHERE bridge.bootstrap_id = exact_bootstrap_id
          AND bridge.revision = manifest_revision
          AND bridge.manifest_sha256 = exact_manifest_sha256;
        IF state_row.manifest_sha256 = exact_manifest_sha256
           AND state_row.revision = manifest_revision
           AND state_row.issuer = manifest_document->>'issuer'
           AND state_row.account_count = 10
           AND current_normalized_digest = normalized_manifest_digest
           AND exact_action IN ('VERIFY', 'REVOKE_ACCESS')
           AND iam.internal_sandbox_revoked_role_graph_v5(
                manifest_document, exact_manifest_sha256
           ) THEN
            RETURN QUERY SELECT 'ALREADY_REVOKED'::text, manifest_revision, 10;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_revoked',
            MESSAGE = 'internal sandbox Trust/Appeal bootstrap was revoked';
    END IF;

    IF state_found AND state_row.status = 'ACTIVE'
       AND state_row.manifest_sha256 = exact_manifest_sha256
       AND state_row.revision = manifest_revision
       AND state_row.issuer = manifest_document->>'issuer'
       AND state_row.account_count = 10
       AND exact_action IN ('APPLY', 'VERIFY') THEN
        IF NOT iam.internal_sandbox_independent_role_graph_v5(manifest_document)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_graph',
                MESSAGE = 'internal sandbox Trust/Appeal graph drifted';
        END IF;
        SELECT bridge.normalized_manifest_sha256
        INTO current_normalized_digest
        FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
        WHERE bridge.bootstrap_id = exact_bootstrap_id
          AND bridge.revision = manifest_revision
          AND bridge.manifest_sha256 = exact_manifest_sha256;
        IF NOT FOUND OR current_normalized_digest <> normalized_manifest_digest THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_bridge',
                MESSAGE = 'internal sandbox Trust/Appeal bridge drifted';
        END IF;
        BEGIN
            PERFORM set_config('app.command_id', internal_command_id::text, true);
            PERFORM set_config(
                'app.manifest_sha256', encode(normalized_manifest_digest, 'hex'), true
            );
            IF NOT iam.internal_sandbox_normalize_trust_appeal_graph_v1(
                manifest_document, normalized_manifest, current_normalized_digest
            ) THEN RAISE EXCEPTION USING ERRCODE = 'Z3602';
            END IF;
            SELECT base.outcome, base.revision, base.account_count
            INTO base_outcome, base_revision, base_account_count
            FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1(
                exact_action, normalized_manifest_bytes,
                normalized_manifest_digest, internal_command_id,
                internal_receipt_id, internal_audit_event_id,
                exact_system_actor_id, exact_correlation_id, exact_trace_id,
                exact_bootstrap_id
            ) AS base;
            RAISE EXCEPTION USING ERRCODE = 'Z3601';
        EXCEPTION WHEN SQLSTATE 'Z3601' THEN NULL;
        END;
        PERFORM set_config('app.command_id', exact_command_id::text, true);
        PERFORM set_config(
            'app.manifest_sha256', encode(exact_manifest_sha256, 'hex'), true
        );
    ELSE
        IF state_found THEN
            IF state_row.status <> 'ACTIVE' OR state_row.account_count <> 10
               OR NOT iam.internal_sandbox_independent_role_graph_v5(
                    manifest_document
               ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_graph',
                    MESSAGE = 'internal sandbox Trust/Appeal graph drifted';
            END IF;
            SELECT bridge.normalized_manifest_sha256
            INTO current_normalized_digest
            FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
            WHERE bridge.bootstrap_id = exact_bootstrap_id
              AND bridge.revision = state_row.revision
              AND bridge.manifest_sha256 = state_row.manifest_sha256;
            IF NOT FOUND OR NOT iam.internal_sandbox_normalize_trust_appeal_graph_v1(
                manifest_document, normalized_manifest, current_normalized_digest
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_restore',
                    MESSAGE = 'internal sandbox Trust/Appeal restore failed';
            END IF;
        END IF;

        PERFORM set_config('app.command_id', internal_command_id::text, true);
        PERFORM set_config(
            'app.manifest_sha256', encode(normalized_manifest_digest, 'hex'), true
        );
        SELECT base.outcome, base.revision, base.account_count
        INTO base_outcome, base_revision, base_account_count
        FROM iam_api.manage_internal_sandbox_identity_bootstrap_v1(
            exact_action, normalized_manifest_bytes, normalized_manifest_digest,
            internal_command_id, internal_receipt_id, internal_audit_event_id,
            exact_system_actor_id, exact_correlation_id, exact_trace_id,
            exact_bootstrap_id
        ) AS base;
        PERFORM set_config('app.command_id', exact_command_id::text, true);
        PERFORM set_config(
            'app.manifest_sha256', encode(exact_manifest_sha256, 'hex'), true
        );

        IF base_outcome IN ('APPLIED', 'ROTATED') THEN
            IF NOT iam.internal_sandbox_apply_org_admin_graph_v1(
                filtered_org_manifest, exact_manifest_sha256, true,
                exact_system_actor_id, exact_command_id
            ) OR NOT iam.internal_sandbox_apply_trust_appeal_graph_v1(
                manifest_document, exact_manifest_sha256, true
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_isolation',
                    MESSAGE = 'internal sandbox Trust/Appeal isolation failed';
            END IF;
            INSERT INTO infra.iam_sandbox_bootstrap_manifest_bridges (
                bootstrap_id, revision, manifest_sha256,
                normalized_manifest_sha256, created_at
            ) VALUES (
                exact_bootstrap_id, manifest_revision, exact_manifest_sha256,
                normalized_manifest_digest, transaction_timestamp()
            );
        ELSIF base_outcome = 'REVOKED' THEN
            IF NOT iam.internal_sandbox_apply_org_admin_graph_v1(
                filtered_org_manifest, exact_manifest_sha256, false,
                exact_system_actor_id, exact_command_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_revoke',
                    MESSAGE = 'internal sandbox org-admin revoke graph failed';
            END IF;
            IF NOT iam.internal_sandbox_apply_trust_appeal_graph_v1(
                manifest_document, exact_manifest_sha256, false
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_revoke',
                    MESSAGE = 'internal sandbox Trust/Appeal duty revoke graph failed';
            END IF;
            IF NOT iam.internal_sandbox_revoked_role_graph_v5(
                manifest_document, exact_manifest_sha256
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_revoke',
                    MESSAGE = 'internal sandbox Trust/Appeal revoke failed';
            END IF;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_outcome',
                MESSAGE = 'internal sandbox Trust/Appeal outcome invalid';
        END IF;
    END IF;

    IF base_revision <> manifest_revision OR base_account_count <> 10
       OR base_outcome NOT IN (
            'APPLIED', 'ROTATED', 'REPLAYED', 'VERIFIED', 'REVOKED'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_result',
            MESSAGE = 'internal sandbox Trust/Appeal result invalid';
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
                = 'internal-sandbox-bootstrap-v5'
          AND receipt.idempotency_key_digest = sha256(convert_to(
                exact_action || '|' || encode(exact_manifest_sha256, 'hex'),
                'UTF8'
          ))
        FOR UPDATE;
        IF NOT FOUND OR prior_receipt.status <> 'COMPLETED'
           OR prior_receipt.payload_hash_key_id
                <> 'internal-sandbox-bootstrap-v5'
           OR prior_receipt.payload_hash <> exact_manifest_sha256
           OR prior_receipt.target_kind <> 'InternalSandboxIdentityBootstrap'
           OR prior_receipt.target_id <> exact_bootstrap_id
           OR prior_receipt.safe_response_body->>'account_count' <> '10'
           OR prior_receipt.safe_response_body->>'manifest_sha256'
                <> encode(exact_manifest_sha256, 'hex')
           OR (prior_receipt.safe_response_body->>'revision')::integer
                <> manifest_revision
           OR prior_receipt.safe_response_body->>'outcome'
                NOT IN ('APPLIED', 'ROTATED') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_replay',
                MESSAGE = 'internal sandbox Trust/Appeal replay invalid';
        END IF;
        RETURN QUERY SELECT base_outcome, manifest_revision, 10;
        RETURN;
    ELSIF base_outcome = 'VERIFIED' THEN
        RETURN QUERY SELECT base_outcome, manifest_revision, 10;
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
            exact_action || '|' || encode(exact_manifest_sha256, 'hex'), 'UTF8'
        )), 'internal-sandbox-bootstrap-v5', exact_manifest_sha256,
        'internal-sandbox-bootstrap-v5', 'restricted-canonical-json-v1',
        'InternalSandboxIdentityBootstrap', exact_bootstrap_id, 'POST',
        '/v1/deployment/internal-sandbox/identity-bootstrap/' ||
            exact_bootstrap_id::text || '/' || lower(exact_action),
        before_revision, 'COMPLETED', 1,
        jsonb_build_object(
            'account_count', 10,
            'manifest_sha256', encode(exact_manifest_sha256, 'hex'),
            'outcome', base_outcome, 'revision', manifest_revision
        ), NULL, transaction_timestamp(),
        transaction_timestamp() + interval '10 years', transaction_timestamp()
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
        'TRUST_APPEAL_ROLE_GRAPH', NULL, 'SUCCEEDED', exact_command_id,
        exact_correlation_id, exact_command_id, exact_trace_id,
        jsonb_build_object(
            'account_count', 10, 'appeal_reviewer_count', 1,
            'trust_officer_count', 2,
            'manifest_sha256', encode(exact_manifest_sha256, 'hex'),
            'revision', manifest_revision
        )
    );

    IF base_outcome IN ('APPLIED', 'ROTATED')
       AND NOT iam.internal_sandbox_independent_role_graph_v5(manifest_document)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_trust_appeal_bootstrap_final_graph',
            MESSAGE = 'internal sandbox Trust/Appeal final graph invalid';
    END IF;
    RETURN QUERY SELECT base_outcome, manifest_revision, 10;
END;
$function$;

ALTER FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v5(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v5(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v4(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM iam_sandbox_bootstrap;
GRANT EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v5(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) TO iam_sandbox_bootstrap;

CREATE FUNCTION iam.trust_authority_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT current_user = 'schema_owner'
   AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL
   AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
   AND (
        (
            session_user = 'trust_self'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'TRUST_REPORTER'
            AND NULLIF(current_setting('app.operation', true), '') IN (
                'SUBMIT_REPORT', 'READ_OWN_REPORT', 'OPEN_APPEAL',
                'READ_OWN_APPEAL', 'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
            )
        ) OR (
            session_user = 'trust_officer'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'TRUST_OFFICER'
            AND NULLIF(current_setting('app.operation', true), '') IN (
                'CLAIM_CASE', 'RELEASE_CASE_ASSIGNMENT',
                'SAVE_TRIAGE_DRAFT', 'PUBLISH_TRIAGE', 'PLACE_HOLD',
                'CLAIM_HOLD_RELEASE', 'RELEASE_HOLD', 'PUBLISH_OUTCOME',
                'LIST_CASE_QUEUE', 'READ_ASSIGNED_CASE',
                'LIST_HOLD_RELEASE_QUEUE'
            )
        ) OR (
            session_user = 'trust_appeal'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'TRUST_APPEAL'
            AND NULLIF(current_setting('app.operation', true), '') IN (
                'LIST_APPEAL_QUEUE', 'READ_ASSIGNED_APPEAL',
                'CLAIM_APPEAL', 'RELEASE_APPEAL_ASSIGNMENT',
                'SAVE_APPEAL_REVIEW_DRAFT', 'DECIDE_APPEAL'
            )
        ) OR (
            session_user = 'trust_decision'
            AND NULLIF(current_setting('app.scope_kind', true), '')
                = 'TRUST_DECISION'
            AND NULLIF(current_setting('app.operation', true), '')
                = 'APPLY_REMEDY'
        )
   )
$function$;

ALTER FUNCTION iam.trust_authority_context_v1() OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.trust_authority_context_v1() FROM PUBLIC;

CREATE POLICY rls_trust_authority_user_definer_v1 ON iam.users
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND id::text = NULLIF(current_setting('app.actor_id', true), '')
);
CREATE POLICY rls_trust_authority_family_definer_v1 ON iam.session_families
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);
CREATE POLICY rls_trust_authority_session_definer_v1 ON iam.sessions
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
);
CREATE POLICY rls_trust_authority_organization_definer_v1 ON iam.organizations
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND id::text = NULLIF(current_setting('app.organization_id', true), '')
);
CREATE POLICY rls_trust_authority_membership_definer_v1 ON iam.memberships
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
);
CREATE POLICY rls_trust_authority_membership_role_definer_v1
ON iam.membership_role_grants
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
);
CREATE POLICY rls_trust_authority_duty_definer_v1 ON iam.platform_duty_grants
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
    AND (
        (session_user = 'trust_officer' AND duty_code = 'TRUST_OFFICER')
        OR (session_user = 'trust_appeal' AND duty_code = 'APPEAL_REVIEWER')
    )
);
CREATE POLICY rls_trust_authority_invitation_definer_v1
ON iam.access_invitations
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND session_user = 'trust_self'
    AND accepted_by_user_id::text
        = NULLIF(current_setting('app.actor_id', true), '')
    AND organization_id::text
        = NULLIF(current_setting('app.organization_id', true), '')
);
CREATE POLICY rls_trust_authority_selector_definer_v1 ON iam.policy_selectors
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND session_user = 'trust_self'
    AND target_role = 'DEMAND_OWNER'
    AND scope_type = 'ORGANIZATION_ROLE'
);
CREATE POLICY rls_trust_authority_bundle_definer_v1 ON iam.policy_bundles
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND session_user = 'trust_self'
    AND EXISTS (
        SELECT 1 FROM iam.policy_selectors AS selector
        WHERE selector.current_bundle_id = policy_bundles.id
          AND selector.selector_digest = policy_bundles.selector_digest
          AND selector.target_role = 'DEMAND_OWNER'
    )
);
CREATE POLICY rls_trust_authority_bundle_document_definer_v1
ON iam.policy_bundle_documents
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND session_user = 'trust_self'
    AND EXISTS (
        SELECT 1 FROM iam.policy_bundles AS bundle
        WHERE bundle.id = policy_bundle_documents.bundle_id
    )
);
CREATE POLICY rls_trust_authority_document_definer_v1 ON iam.policy_documents
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND session_user = 'trust_self'
    AND EXISTS (
        SELECT 1 FROM iam.policy_bundle_documents AS membership
        WHERE membership.document_id = policy_documents.id
    )
);
CREATE POLICY rls_trust_authority_acceptance_definer_v1 ON iam.policy_acceptances
FOR SELECT TO schema_owner
USING (
    iam.trust_authority_context_v1()
    AND session_user = 'trust_self'
    AND user_id::text = NULLIF(current_setting('app.actor_id', true), '')
);

CREATE FUNCTION iam_api.resolve_trust_reporter_authority_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_operation text
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    organization_id uuid,
    user_status text,
    session_status text,
    session_family_status text,
    organization_status text,
    membership_id uuid,
    membership_status text,
    membership_role_grant_id uuid,
    membership_role_grant_version bigint,
    role_code text,
    policy_requirements_satisfied boolean,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_organization_id IS NULL OR exact_organization_id = zero_uuid
       OR exact_operation NOT IN (
            'SUBMIT_REPORT', 'READ_OWN_REPORT', 'OPEN_APPEAL',
            'READ_OWN_APPEAL', 'SAVE_APPEAL_DRAFT', 'SUBMIT_APPEAL'
       )
       OR session_user IS DISTINCT FROM 'trust_self'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_REPORTER'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text THEN
        RETURN;
    END IF;

    RETURN QUERY
    WITH authority AS (
        SELECT actor.id AS actor_user_id,
               active_session.id AS session_id,
               organization.id AS organization_id,
               actor.status AS user_status,
               active_session.status AS session_status,
               family.status AS family_status,
               organization.status AS organization_status,
               membership.id AS membership_id,
               membership.status AS membership_status,
               owner_grant.id AS grant_id,
               owner_grant.aggregate_version AS grant_version,
               owner_grant.role_code AS role_code,
               family.id AS family_id,
               family.aggregate_version AS family_version,
               family.current_generation,
               active_session.aggregate_version AS session_version,
               actor.aggregate_version AS user_version,
               organization.aggregate_version AS organization_version,
               membership.aggregate_version AS membership_version,
               owner_grant.policy_selector_digest,
               selector.aggregate_version AS selector_version,
               current_bundle.id AS bundle_id,
               current_bundle.aggregate_version AS bundle_version,
               NOT EXISTS (
                   SELECT 1
                   FROM iam.policy_bundle_documents AS bundle_membership
                   JOIN iam.policy_documents AS document
                     ON document.id = bundle_membership.document_id
                   WHERE bundle_membership.bundle_id = current_bundle.id
                     AND bundle_membership.required
                     AND (
                         document.status <> 'ACTIVE'
                         OR document.effective_at IS NULL
                         OR document.effective_at > transaction_timestamp()
                         OR document.legal_effect NOT IN (
                             'NOTICE_ACKNOWLEDGEMENT', 'CONTRACT_ACCEPTANCE'
                         )
                         OR NOT EXISTS (
                             SELECT 1
                             FROM iam.policy_acceptances AS acceptance
                             WHERE acceptance.user_id = actor.id
                               AND acceptance.document_id = document.id
                               AND acceptance.content_sha256
                                    = document.content_sha256
                         )
                     )
               ) AS policy_satisfied
        FROM iam.users AS actor
        JOIN iam.sessions AS active_session
          ON active_session.id = exact_session_id
         AND active_session.user_id = actor.id
        JOIN iam.session_families AS family
          ON family.id = active_session.family_id
         AND family.user_id = actor.id
        JOIN iam.organizations AS organization
          ON organization.id = exact_organization_id
        JOIN iam.memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.user_id = actor.id
        JOIN iam.membership_role_grants AS owner_grant
          ON owner_grant.organization_id = organization.id
         AND owner_grant.membership_id = membership.id
         AND owner_grant.user_id = actor.id
         AND owner_grant.role_code = 'DEMAND_OWNER'
        JOIN iam.access_invitations AS invitation
          ON invitation.id = owner_grant.source_invitation_id
         AND invitation.organization_id = organization.id
         AND invitation.accepted_by_user_id = actor.id
         AND invitation.policy_selector_digest
                = owner_grant.policy_selector_digest
         AND invitation.status = 'ACCEPTED'
        JOIN iam.policy_selectors AS selector
          ON selector.selector_digest = owner_grant.policy_selector_digest
         AND selector.current_bundle_id IS NOT NULL
         AND selector.target_role = 'DEMAND_OWNER'
        JOIN iam.policy_bundles AS current_bundle
          ON current_bundle.id = selector.current_bundle_id
         AND current_bundle.selector_digest = selector.selector_digest
         AND current_bundle.status = 'ACTIVE'
         AND current_bundle.effective_at <= transaction_timestamp()
         AND (
             current_bundle.effective_until IS NULL
             OR transaction_timestamp() < current_bundle.effective_until
         )
        WHERE actor.id = exact_actor_user_id
          AND actor.status = 'ACTIVE'
          AND family.status = 'ACTIVE' AND family.revoked_at IS NULL
          AND active_session.status = 'ACTIVE'
          AND active_session.generation = family.current_generation
          AND transaction_timestamp() < active_session.idle_expires_at
          AND transaction_timestamp() < active_session.absolute_expires_at
          AND organization.status = 'ACTIVE'
          AND membership.status = 'ACTIVE'
          AND owner_grant.granted_at <= transaction_timestamp()
          AND owner_grant.revoked_at IS NULL
    )
    SELECT authority.actor_user_id, authority.session_id,
           authority.organization_id, authority.user_status,
           authority.session_status, authority.family_status,
           authority.organization_status, authority.membership_id,
           authority.membership_status, authority.grant_id,
           authority.grant_version, authority.role_code,
           authority.policy_satisfied,
           sha256(convert_to(concat_ws(
               E'\x1f', 'desire:iam:trust-reporter-authority:v1',
               exact_operation, authority.actor_user_id::text,
               authority.session_id::text, authority.organization_id::text,
               authority.family_id::text, authority.family_version::text,
               authority.current_generation::text,
               authority.session_version::text, authority.user_version::text,
               authority.organization_version::text,
               authority.membership_id::text,
               authority.membership_version::text,
               authority.grant_id::text, authority.grant_version::text,
               encode(authority.policy_selector_digest, 'hex'),
               authority.selector_version::text, authority.bundle_id::text,
               authority.bundle_version::text,
               authority.policy_satisfied::text
           ), 'UTF8'))
    FROM authority;
END;
$function$;

ALTER FUNCTION iam_api.resolve_trust_reporter_authority_v1(
    uuid, uuid, uuid, text
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_trust_reporter_authority_v1(
    uuid, uuid, uuid, text
) FROM PUBLIC;

CREATE FUNCTION iam_api.resolve_trust_officer_authority_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    user_status text,
    session_status text,
    session_family_status text,
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz,
    duty_code text,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_operation NOT IN (
            'CLAIM_CASE', 'RELEASE_CASE_ASSIGNMENT', 'SAVE_TRIAGE_DRAFT',
            'PUBLISH_TRIAGE', 'PLACE_HOLD', 'CLAIM_HOLD_RELEASE',
            'RELEASE_HOLD', 'PUBLISH_OUTCOME', 'LIST_CASE_QUEUE',
            'READ_ASSIGNED_CASE', 'LIST_HOLD_RELEASE_QUEUE'
       )
       OR session_user IS DISTINCT FROM 'trust_officer'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_OFFICER'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT actor.id, active_session.id, actor.status, active_session.status,
           family.status, duty.id, duty.aggregate_version, duty.expires_at,
           duty.duty_code,
           sha256(convert_to(concat_ws(
               E'\x1f', 'desire:iam:trust-officer-authority:v1',
               exact_operation, actor.id::text, active_session.id::text,
               family.id::text, family.aggregate_version::text,
               family.current_generation::text,
               active_session.aggregate_version::text,
               active_session.generation::text, actor.aggregate_version::text,
               duty.id::text, duty.aggregate_version::text,
               coalesce(extract(epoch FROM duty.expires_at)::text, 'none')
           ), 'UTF8'))
    FROM iam.users AS actor
    JOIN iam.sessions AS active_session
      ON active_session.id = exact_session_id
     AND active_session.user_id = actor.id
    JOIN iam.session_families AS family
      ON family.id = active_session.family_id
     AND family.user_id = actor.id
    JOIN iam.platform_duty_grants AS duty
      ON duty.user_id = actor.id AND duty.duty_code = 'TRUST_OFFICER'
    WHERE actor.id = exact_actor_user_id AND actor.status = 'ACTIVE'
      AND family.status = 'ACTIVE' AND family.revoked_at IS NULL
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (duty.expires_at IS NULL OR transaction_timestamp() < duty.expires_at);
END;
$function$;

ALTER FUNCTION iam_api.resolve_trust_officer_authority_v1(uuid, uuid, text)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_trust_officer_authority_v1(
    uuid, uuid, text
) FROM PUBLIC;

CREATE FUNCTION iam_api.resolve_appeal_reviewer_authority_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text
)
RETURNS TABLE (
    actor_user_id uuid,
    session_id uuid,
    user_status text,
    session_status text,
    session_family_status text,
    duty_grant_id uuid,
    duty_grant_version bigint,
    duty_expires_at timestamptz,
    duty_code text,
    authority_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_session_id IS NULL OR exact_session_id = zero_uuid
       OR exact_operation NOT IN (
            'LIST_APPEAL_QUEUE', 'READ_ASSIGNED_APPEAL',
            'CLAIM_APPEAL', 'RELEASE_APPEAL_ASSIGNMENT',
            'SAVE_APPEAL_REVIEW_DRAFT', 'DECIDE_APPEAL'
       )
       OR session_user IS DISTINCT FROM 'trust_appeal'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'TRUST_APPEAL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM exact_operation
       OR NULLIF(current_setting('app.actor_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_session_id::text THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT actor.id, active_session.id, actor.status, active_session.status,
           family.status, duty.id, duty.aggregate_version, duty.expires_at,
           duty.duty_code,
           sha256(convert_to(concat_ws(
               E'\x1f', 'desire:iam:appeal-reviewer-authority:v1',
               exact_operation, actor.id::text, active_session.id::text,
               family.id::text, family.aggregate_version::text,
               family.current_generation::text,
               active_session.aggregate_version::text,
               active_session.generation::text, actor.aggregate_version::text,
               duty.id::text, duty.aggregate_version::text,
               coalesce(extract(epoch FROM duty.expires_at)::text, 'none')
           ), 'UTF8'))
    FROM iam.users AS actor
    JOIN iam.sessions AS active_session
      ON active_session.id = exact_session_id
     AND active_session.user_id = actor.id
    JOIN iam.session_families AS family
      ON family.id = active_session.family_id
     AND family.user_id = actor.id
    JOIN iam.platform_duty_grants AS duty
      ON duty.user_id = actor.id AND duty.duty_code = 'APPEAL_REVIEWER'
    WHERE actor.id = exact_actor_user_id AND actor.status = 'ACTIVE'
      AND family.status = 'ACTIVE' AND family.revoked_at IS NULL
      AND active_session.status = 'ACTIVE'
      AND active_session.generation = family.current_generation
      AND transaction_timestamp() < active_session.idle_expires_at
      AND transaction_timestamp() < active_session.absolute_expires_at
      AND duty.granted_at <= transaction_timestamp()
      AND duty.revoked_at IS NULL
      AND (duty.expires_at IS NULL OR transaction_timestamp() < duty.expires_at);
END;
$function$;

ALTER FUNCTION iam_api.resolve_appeal_reviewer_authority_v1(uuid, uuid, text)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_appeal_reviewer_authority_v1(
    uuid, uuid, text
) FROM PUBLIC;

CREATE FUNCTION iam_api.resolve_trust_reporter_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_operation text,
    exact_membership_id uuid,
    exact_membership_role_grant_id uuid,
    exact_grant_version bigint
)
RETURNS TABLE(authority_marker_sha256 bytea)
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam_api
AS $function$
SELECT authority.authority_marker_sha256
FROM iam_api.resolve_trust_reporter_authority_v1(
    exact_actor_user_id, exact_session_id, exact_organization_id,
    exact_operation
) AS authority
WHERE authority.membership_id = exact_membership_id
  AND authority.membership_role_grant_id = exact_membership_role_grant_id
  AND authority.membership_role_grant_version = exact_grant_version
  AND authority.role_code = 'DEMAND_OWNER'
  AND authority.policy_requirements_satisfied
$function$;

ALTER FUNCTION iam_api.resolve_trust_reporter_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid, bigint
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_trust_reporter_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid, bigint
) FROM PUBLIC;

CREATE FUNCTION iam_api.resolve_trust_officer_authority_marker_v1(
    exact_actor_user_id uuid,
    exact_session_id uuid,
    exact_operation text,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint
)
RETURNS TABLE(authority_marker_sha256 bytea)
LANGUAGE sql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam_api
AS $function$
SELECT authority.authority_marker_sha256
FROM iam_api.resolve_trust_officer_authority_v1(
    exact_actor_user_id, exact_session_id, exact_operation
) AS authority
WHERE authority.duty_grant_id = exact_duty_grant_id
  AND authority.duty_grant_version = exact_duty_grant_version
  AND authority.duty_code = 'TRUST_OFFICER'
$function$;

ALTER FUNCTION iam_api.resolve_trust_officer_authority_marker_v1(
    uuid, uuid, text, uuid, bigint
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_trust_officer_authority_marker_v1(
    uuid, uuid, text, uuid, bigint
) FROM PUBLIC;

CREATE FUNCTION iam_api.resolve_trust_party_conflict_facts_v1(
    exact_officer_user_id uuid,
    exact_session_id uuid,
    exact_organization_id uuid,
    exact_operation text,
    exact_duty_grant_id uuid,
    exact_duty_grant_version bigint,
    exact_authority_marker_sha256 bytea
)
RETURNS TABLE(
    organization_membership_conflict boolean,
    conflict_facts_marker_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, iam_api
AS $function$
DECLARE
    conflict_value boolean;
    marker_value bytea;
BEGIN
    IF exact_organization_id IS NULL
       OR exact_authority_marker_sha256 IS NULL
       OR octet_length(exact_authority_marker_sha256) <> 32
       OR NULLIF(current_setting('app.organization_id', true), '')
            IS DISTINCT FROM exact_organization_id::text THEN
        RETURN;
    END IF;

    SELECT authority.authority_marker_sha256 INTO marker_value
    FROM iam_api.resolve_trust_officer_authority_marker_v1(
        exact_officer_user_id, exact_session_id, exact_operation,
        exact_duty_grant_id, exact_duty_grant_version
    ) AS authority
    WHERE authority.authority_marker_sha256 = exact_authority_marker_sha256;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.organization_id = exact_organization_id
          AND membership.user_id = exact_officer_user_id
          AND membership.status = 'ACTIVE'
    ) INTO conflict_value;

    RETURN QUERY SELECT conflict_value,
        sha256(convert_to(concat_ws(
            E'\x1f', 'desire:iam:trust-party-conflict-facts:v1',
            exact_operation, exact_officer_user_id::text,
            exact_session_id::text, exact_organization_id::text,
            exact_duty_grant_id::text, exact_duty_grant_version::text,
            encode(marker_value, 'hex'), conflict_value::text
        ), 'UTF8'));
END;
$function$;

ALTER FUNCTION iam_api.resolve_trust_party_conflict_facts_v1(
    uuid, uuid, uuid, text, uuid, bigint, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.resolve_trust_party_conflict_facts_v1(
    uuid, uuid, uuid, text, uuid, bigint, bytea
) FROM PUBLIC;

GRANT USAGE ON SCHEMA iam_api TO trust_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_trust_reporter_authority_v1(
    uuid, uuid, uuid, text
) TO trust_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_trust_officer_authority_v1(
    uuid, uuid, text
) TO trust_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_appeal_reviewer_authority_v1(
    uuid, uuid, text
) TO trust_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_trust_reporter_authority_marker_v1(
    uuid, uuid, uuid, text, uuid, uuid, bigint
) TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_trust_officer_authority_marker_v1(
    uuid, uuid, text, uuid, bigint
) TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION iam_api.resolve_trust_party_conflict_facts_v1(
    uuid, uuid, uuid, text, uuid, bigint, bytea
) TO demand_schema_owner;
GRANT USAGE ON SCHEMA infra TO trust_migration_runner;
GRANT SELECT ON TABLE infra.iam_schema_compatibility
TO trust_migration_runner, trust_schema_owner;

ALTER TABLE infra.command_receipts
ADD CONSTRAINT ck_command_receipt_current_session_logout CHECK (
    command_name <> 'RevokeCurrentSession'
    OR (
        command_version = 1
        AND principal_kind = 'USER'
        AND target_kind = 'Session'
        AND http_method = 'DELETE'
        AND canonical_path = '/v1/me/sessions/' || target_id::text
        AND if_match_version IS NULL
        AND reconstruction_metadata IS NULL
        AND (
            (
                status = 'IN_PROGRESS'
                AND response_http_status IS NULL
                AND response_schema_name IS NULL
                AND response_entity_tag IS NULL
                AND current_user_entity_tag IS NULL
            ) OR (
                status = 'COMPLETED'
                AND response_schema_version = 1
                AND response_http_status = 204
                AND response_schema_name = 'Empty204'
                AND response_entity_tag IS NULL
                AND current_user_entity_tag IS NULL
                AND safe_response_body->>'session_id' = target_id::text
                AND safe_response_body->>'session_family_id'
                    ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                AND safe_response_body->>'session_status' IN (
                    'REVOKED', 'EXPIRED'
                )
                AND safe_response_body->>'session_version' ~ '^[1-9][0-9]*$'
                AND safe_response_body->>'outcome' IN (
                    'REVOKED', 'EXPIRED', 'ALREADY_TERMINAL'
                )
                AND safe_response_body->'replayed' = 'false'::jsonb
                AND safe_response_body->'clear_current_session_cookie'
                    = 'true'::jsonb
                AND safe_response_body ?& ARRAY[
                    'outcome', 'session_id', 'session_family_id',
                    'session_status', 'session_version', 'replayed',
                    'clear_current_session_cookie'
                ]
                AND safe_response_body - ARRAY[
                    'outcome', 'session_id', 'session_family_id',
                    'session_status', 'session_version', 'replayed',
                    'clear_current_session_cookie'
                ] = '{}'::jsonb
            )
        )
    )
);

CREATE FUNCTION iam.current_session_logout_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
SELECT session_user = 'iam_app'
   AND current_user = 'schema_owner'
   AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
   AND NULLIF(current_setting('app.operation', true), '')
        = 'REVOKE_CURRENT_SESSION'
   AND NULLIF(current_setting('app.actor_user_id', true), '') IS NOT NULL
   AND NULLIF(current_setting('app.session_id', true), '') IS NOT NULL
   AND NULLIF(current_setting('app.target_session_id', true), '')
        = NULLIF(current_setting('app.session_id', true), '')
   AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
$function$;

ALTER FUNCTION iam.current_session_logout_context_v1() OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.current_session_logout_context_v1() FROM PUBLIC;

CREATE POLICY rls_current_session_logout_user_definer_v1 ON iam.users
FOR ALL TO schema_owner
USING (
    iam.current_session_logout_context_v1()
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_current_session_logout_family_definer_v1
ON iam.session_families
FOR ALL TO schema_owner
USING (
    iam.current_session_logout_context_v1()
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND EXISTS (
        SELECT 1 FROM iam.sessions AS exact_session
        WHERE exact_session.family_id = session_families.id
          AND exact_session.user_id = session_families.user_id
          AND exact_session.id::text
                = NULLIF(current_setting('app.session_id', true), '')
    )
)
WITH CHECK (
    user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_current_session_logout_session_select_definer_v1
ON iam.sessions
FOR SELECT TO schema_owner
USING (
    iam.current_session_logout_context_v1()
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);
CREATE POLICY rls_current_session_logout_session_update_definer_v1
ON iam.sessions
FOR UPDATE TO schema_owner
USING (
    iam.current_session_logout_context_v1()
    AND id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
)
WITH CHECK (
    id::text = NULLIF(current_setting('app.session_id', true), '')
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND status IN ('REVOKED', 'EXPIRED')
);
CREATE POLICY rls_current_session_logout_key_policy_select_definer_v1
ON infra.iam_receipt_key_policy
FOR SELECT TO schema_owner
USING (iam.current_session_logout_context_v1() AND singleton_key);
CREATE POLICY rls_current_session_logout_key_policy_lock_definer_v1
ON infra.iam_receipt_key_policy
FOR UPDATE TO schema_owner
USING (iam.current_session_logout_context_v1() AND singleton_key)
WITH CHECK (singleton_key);
CREATE POLICY rls_current_session_logout_audit_definer_v1
ON audit.audit_events
FOR INSERT TO schema_owner
WITH CHECK (
    iam.current_session_logout_context_v1()
    AND actor_kind = 'USER'
    AND actor_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND original_actor_id IS NULL
    AND action_code = 'RevokeCurrentSession'
    AND target_kind = 'Session'
    AND target_id::text = NULLIF(current_setting('app.session_id', true), '')
    AND organization_id IS NULL
    AND command_id::text = NULLIF(current_setting('app.command_id', true), '')
    AND causation_id = command_id
);
CREATE POLICY rls_current_session_logout_outbox_definer_v1
ON infra.outbox_events
FOR INSERT TO schema_owner
WITH CHECK (
    iam.current_session_logout_context_v1()
    AND event_type = 'SessionRevoked'
    AND aggregate_type = 'Session'
    AND aggregate_id::text = NULLIF(
        current_setting('app.session_id', true), ''
    )
    AND actor_kind = 'USER'
    AND actor_id::text = NULLIF(
        current_setting('app.actor_user_id', true), ''
    )
    AND original_actor_id IS NULL
    AND causation_id::text = NULLIF(
        current_setting('app.command_id', true), ''
    )
    AND organization_id IS NULL
);

CREATE OR REPLACE FUNCTION iam.enforce_session_family_consistent()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    checked_family_id uuid;
    family_status text;
    family_user_id uuid;
    family_current_generation bigint;
    active_session_count integer;
BEGIN
    IF TG_TABLE_NAME = 'session_families' THEN
        checked_family_id := NEW.id;
    ELSE
        checked_family_id := NEW.family_id;
    END IF;

    SELECT status, user_id, current_generation
    INTO family_status, family_user_id, family_current_generation
    FROM iam.session_families
    WHERE id = checked_family_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO active_session_count
    FROM iam.sessions
    WHERE family_id = checked_family_id AND status = 'ACTIVE';
    IF family_status = 'ACTIVE' THEN
        IF active_session_count > 1 OR (
            active_session_count = 1 AND NOT EXISTS (
                SELECT 1
                FROM iam.sessions
                WHERE family_id = checked_family_id
                  AND status = 'ACTIVE'
                  AND generation = family_current_generation
                  AND user_id = family_user_id
            )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_session_family_consistent',
                MESSAGE = 'active session family has an inconsistent current session';
        END IF;
    ELSIF active_session_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_session_family_consistent',
            MESSAGE = 'revoked session family has an active session';
    END IF;

    IF TG_TABLE_NAME = 'sessions' THEN
        IF (
            (NEW.generation = 1 AND NEW.predecessor_session_id IS NOT NULL)
            OR (NEW.generation > 1 AND NOT EXISTS (
                SELECT 1
                FROM iam.sessions AS predecessor
                WHERE predecessor.id = NEW.predecessor_session_id
                  AND predecessor.family_id = NEW.family_id
                  AND predecessor.generation = NEW.generation - 1
            ))
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_session_family_consistent',
                MESSAGE = 'session predecessor generation is inconsistent';
        END IF;
    END IF;
    RETURN NULL;
END;
$function$;

CREATE FUNCTION iam_api.revoke_current_session_v1(
    exact_actor_user_id uuid,
    exact_current_session_id uuid,
    exact_command_id uuid,
    exact_correlation_id uuid,
    exact_causation_id uuid,
    exact_trace_id uuid,
    exact_idempotency_key_digest bytea,
    exact_idempotency_key_digest_key_id text,
    exact_payload_hash bytea,
    exact_payload_hash_key_id text,
    exact_canonicalization_version text,
    exact_retain_until timestamptz,
    new_audit_event_id uuid,
    new_outbox_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, audit, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    server_now timestamptz := transaction_timestamp();
    key_policy infra.iam_receipt_key_policy%ROWTYPE;
    actor_row iam.users%ROWTYPE;
    family_row iam.session_families%ROWTYPE;
    session_row iam.sessions%ROWTYPE;
    existing infra.command_receipts%ROWTYPE;
    resolved_family_id uuid;
    claimed_count integer := 0;
    result_outcome text;
    result_status text;
    before_status text;
    before_version bigint;
    result_version bigint;
    safe_result jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_app'
       OR current_user IS DISTINCT FROM 'schema_owner'
       OR NOT iam.current_session_logout_context_v1()
       OR exact_actor_user_id IS NULL OR exact_actor_user_id = zero_uuid
       OR exact_current_session_id IS NULL
       OR exact_current_session_id = zero_uuid
       OR exact_command_id IS NULL OR exact_command_id = zero_uuid
       OR exact_correlation_id IS NULL OR exact_correlation_id = zero_uuid
       OR exact_causation_id IS DISTINCT FROM exact_command_id
       OR exact_trace_id IS NULL OR exact_trace_id = zero_uuid
       OR new_audit_event_id IS NULL OR new_audit_event_id = zero_uuid
       OR new_outbox_event_id IS NULL OR new_outbox_event_id = zero_uuid
       OR cardinality(ARRAY[
            exact_command_id, new_audit_event_id, new_outbox_event_id
       ]) <> cardinality(ARRAY(
            SELECT DISTINCT identifier FROM unnest(ARRAY[
                exact_command_id, new_audit_event_id, new_outbox_event_id
            ]) AS identifier
       ))
       OR octet_length(exact_idempotency_key_digest) <> 32
       OR octet_length(exact_payload_hash) <> 32
       OR NULLIF(current_setting('app.actor_user_id', true), '')
            IS DISTINCT FROM exact_actor_user_id::text
       OR NULLIF(current_setting('app.session_id', true), '')
            IS DISTINCT FROM exact_current_session_id::text
       OR NULLIF(current_setting('app.target_session_id', true), '')
            IS DISTINCT FROM exact_current_session_id::text
       OR NULLIF(current_setting('app.command_id', true), '')
            IS DISTINCT FROM exact_command_id::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_current_session_logout_context',
            MESSAGE = 'current Session logout context is invalid';
    END IF;

    IF exact_retain_until IS NULL OR exact_retain_until <= server_now THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_current_session_logout_expired',
            MESSAGE = 'current Session logout receipt retention expired';
    END IF;

    SELECT * INTO key_policy
    FROM infra.iam_receipt_key_policy
    WHERE singleton_key
    FOR UPDATE;
    IF NOT FOUND
       OR exact_idempotency_key_digest_key_id
            <> 'iam-receipt-idempotency-hmac-2026-01'
       OR exact_payload_hash_key_id
            <> 'iam-receipt-payload-hmac-2026-01'
       OR exact_canonicalization_version <> 'restricted-canonical-json-v1'
       OR key_policy.active_idempotency_key_id
            <> exact_idempotency_key_digest_key_id
       OR key_policy.active_payload_hash_key_id <> exact_payload_hash_key_id
       OR key_policy.active_canonicalization_version
            <> exact_canonicalization_version
       OR NOT exact_idempotency_key_digest_key_id
            = ANY(key_policy.retained_idempotency_key_ids)
       OR NOT exact_payload_hash_key_id
            = ANY(key_policy.retained_payload_hash_key_ids)
       OR NOT exact_canonicalization_version
            = ANY(key_policy.retained_canonicalization_versions) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_current_session_logout_key_policy',
            MESSAGE = 'current Session logout key policy is unavailable';
    END IF;

    SELECT family_id INTO resolved_family_id
    FROM iam.sessions
    WHERE id = exact_current_session_id
      AND user_id = exact_actor_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_current_session_logout_authentication',
            MESSAGE = 'current Session logout authentication is unavailable';
    END IF;

    SELECT * INTO actor_row
    FROM iam.users
    WHERE id = exact_actor_user_id
    FOR UPDATE;
    SELECT * INTO family_row
    FROM iam.session_families
    WHERE id = resolved_family_id AND user_id = exact_actor_user_id
    FOR UPDATE;
    SELECT * INTO session_row
    FROM iam.sessions
    WHERE id = exact_current_session_id
      AND user_id = exact_actor_user_id
      AND family_id = resolved_family_id
    FOR UPDATE;
    IF actor_row.id IS NULL OR actor_row.status <> 'ACTIVE'
       OR family_row.id IS NULL OR session_row.id IS NULL
       OR (
            session_row.status = 'ACTIVE'
            AND (
                family_row.status <> 'ACTIVE'
                OR family_row.current_generation <> session_row.generation
            )
       )
       OR session_row.status NOT IN ('ACTIVE', 'REVOKED', 'EXPIRED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            CONSTRAINT = 'ck_current_session_logout_authentication',
            MESSAGE = 'current Session logout authentication is unavailable';
    END IF;

    SELECT receipt.* INTO existing
    FROM infra.command_receipts AS receipt
    WHERE receipt.principal_kind = 'USER'
      AND receipt.principal_id = exact_actor_user_id
      AND receipt.idempotency_key_digest_key_id
            = exact_idempotency_key_digest_key_id
      AND receipt.idempotency_key_digest = exact_idempotency_key_digest
    ORDER BY receipt.id
    LIMIT 1
    FOR UPDATE;
    IF FOUND THEN
        IF existing.command_name <> 'RevokeCurrentSession'
           OR existing.command_version <> 1
           OR existing.payload_hash_key_id <> exact_payload_hash_key_id
           OR existing.payload_hash <> exact_payload_hash
           OR existing.canonicalization_version
                <> exact_canonicalization_version
           OR existing.target_kind <> 'Session'
           OR existing.target_id <> exact_current_session_id
           OR existing.http_method <> 'DELETE'
           OR existing.canonical_path
                <> '/v1/me/sessions/' || exact_current_session_id::text
           OR existing.if_match_version IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                CONSTRAINT = 'ck_current_session_logout_idempotency_reused',
                MESSAGE = 'current Session logout idempotency key was reused';
        ELSIF existing.status = 'IN_PROGRESS' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_current_session_logout_in_progress',
                MESSAGE = 'current Session logout is in progress';
        ELSIF existing.status <> 'COMPLETED'
           OR existing.response_schema_version <> 1
           OR existing.response_http_status <> 204
           OR existing.response_schema_name <> 'Empty204'
           OR existing.response_entity_tag IS NOT NULL
           OR existing.current_user_entity_tag IS NOT NULL
           OR existing.reconstruction_metadata IS NOT NULL
           OR existing.safe_response_body IS NULL
           OR existing.retain_until <= server_now
           OR existing.safe_response_body->>'session_id'
                <> exact_current_session_id::text
           OR existing.safe_response_body->>'session_family_id'
                <> resolved_family_id::text
           OR existing.safe_response_body->>'session_status'
                NOT IN ('REVOKED', 'EXPIRED')
           OR existing.safe_response_body->>'outcome' NOT IN (
                'REVOKED', 'EXPIRED', 'ALREADY_TERMINAL'
           )
           OR existing.safe_response_body->>'session_version'
                !~ '^[1-9][0-9]*$'
           OR existing.safe_response_body->'replayed' <> 'false'::jsonb
           OR existing.safe_response_body->'clear_current_session_cookie'
                <> 'true'::jsonb
           OR (
                SELECT count(*)
                FROM jsonb_object_keys(existing.safe_response_body)
              ) <> 7 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_current_session_logout_context',
                MESSAGE = 'current Session logout receipt is inconsistent';
        END IF;
        RETURN jsonb_set(
            jsonb_set(
                existing.safe_response_body,
                '{outcome}', to_jsonb('REPLAYED'::text), false
            ),
            '{replayed}', 'true'::jsonb, false
        );
    END IF;

    IF EXISTS (
        SELECT 1 FROM infra.command_receipts
        WHERE id = exact_command_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'ck_current_session_logout_idempotency_reused',
            MESSAGE = 'current Session logout command identifier was reused';
    END IF;

    INSERT INTO infra.command_receipts (
        id, principal_kind, principal_id, command_name, command_version,
        idempotency_key_digest, idempotency_key_digest_key_id, payload_hash,
        payload_hash_key_id, canonicalization_version, target_kind, target_id,
        http_method, canonical_path, if_match_version, status,
        response_schema_version, safe_response_body, reconstruction_metadata,
        created_at, retain_until, completed_at, response_http_status,
        response_schema_name, response_entity_tag, current_user_entity_tag
    ) VALUES (
        exact_command_id, 'USER', exact_actor_user_id,
        'RevokeCurrentSession', 1, exact_idempotency_key_digest,
        exact_idempotency_key_digest_key_id, exact_payload_hash,
        exact_payload_hash_key_id, exact_canonicalization_version, 'Session',
        exact_current_session_id, 'DELETE',
        '/v1/me/sessions/' || exact_current_session_id::text, NULL,
        'IN_PROGRESS', NULL, NULL, NULL, server_now, exact_retain_until, NULL,
        NULL, NULL, NULL, NULL
    ) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS claimed_count = ROW_COUNT;
    IF claimed_count <> 1 THEN
        SELECT receipt.* INTO existing
        FROM infra.command_receipts AS receipt
        WHERE receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_user_id
          AND receipt.idempotency_key_digest_key_id
                = exact_idempotency_key_digest_key_id
          AND receipt.idempotency_key_digest = exact_idempotency_key_digest
        ORDER BY receipt.id LIMIT 1 FOR UPDATE;
        IF FOUND AND existing.status = 'IN_PROGRESS' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_current_session_logout_in_progress',
                MESSAGE = 'current Session logout is in progress';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'ck_current_session_logout_idempotency_reused',
            MESSAGE = 'current Session logout idempotency claim conflicted';
    END IF;

    before_status := session_row.status;
    before_version := session_row.aggregate_version;
    IF session_row.status = 'ACTIVE'
       AND server_now < session_row.idle_expires_at
       AND server_now < session_row.absolute_expires_at THEN
        UPDATE iam.sessions AS target
        SET status = 'REVOKED', revoked_at = server_now,
            revocation_reason_code = 'USER_LOGOUT_CURRENT_SESSION',
            aggregate_version = target.aggregate_version + 1,
            updated_at = server_now
        WHERE target.id = exact_current_session_id
          AND target.user_id = exact_actor_user_id
          AND target.family_id = resolved_family_id
          AND target.status = 'ACTIVE'
          AND target.aggregate_version = before_version
        RETURNING target.status, target.aggregate_version
        INTO result_status, result_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                CONSTRAINT = 'ck_current_session_logout_context',
                MESSAGE = 'current Session logout write conflicted';
        END IF;
        result_outcome := 'REVOKED';
    ELSIF session_row.status = 'ACTIVE' THEN
        UPDATE iam.sessions AS target
        SET status = 'EXPIRED', revoked_at = server_now,
            revocation_reason_code = 'SESSION_EXPIRED',
            aggregate_version = target.aggregate_version + 1,
            updated_at = server_now
        WHERE target.id = exact_current_session_id
          AND target.user_id = exact_actor_user_id
          AND target.family_id = resolved_family_id
          AND target.status = 'ACTIVE'
          AND target.aggregate_version = before_version
        RETURNING target.status, target.aggregate_version
        INTO result_status, result_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                CONSTRAINT = 'ck_current_session_logout_context',
                MESSAGE = 'current Session expiry write conflicted';
        END IF;
        result_outcome := 'EXPIRED';
    ELSE
        result_outcome := 'ALREADY_TERMINAL';
        result_status := session_row.status;
        result_version := session_row.aggregate_version;
    END IF;

    INSERT INTO audit.audit_events (
        event_id, occurred_at, actor_kind, actor_id, original_actor_id,
        action_code, target_kind, target_id, organization_id, before_status,
        after_status, before_version, after_version, role_code, purpose_code,
        reason_code, auth_strength_code, result_code, command_id,
        correlation_id, causation_id, trace_id, safe_attributes
    ) VALUES (
        new_audit_event_id, server_now, 'USER', exact_actor_user_id, NULL,
        'RevokeCurrentSession', 'Session', exact_current_session_id, NULL,
        before_status, result_status, before_version, result_version, NULL,
        'SELF_SESSION', CASE result_outcome
            WHEN 'REVOKED' THEN 'USER_LOGOUT_CURRENT_SESSION'
            WHEN 'EXPIRED' THEN 'SESSION_EXPIRED'
            ELSE 'ALREADY_TERMINAL'
        END, session_row.acr_code, 'SUCCEEDED', exact_command_id,
        exact_correlation_id, exact_causation_id, exact_trace_id, '{}'::jsonb
    );

    IF result_outcome = 'REVOKED' THEN
        INSERT INTO infra.outbox_events (
            event_id, event_type, schema_version, occurred_at, aggregate_type,
            aggregate_id, aggregate_version, actor_kind, actor_id,
            original_actor_id, correlation_id, causation_id, trace_id,
            organization_id, payload, delivery_status, attempt_count,
            available_at, lease_owner, lease_until, published_at,
            last_error_code, created_at
        ) VALUES (
            new_outbox_event_id, 'SessionRevoked', 1, server_now, 'Session',
            exact_current_session_id, result_version, 'USER',
            exact_actor_user_id, NULL, exact_correlation_id,
            exact_causation_id, exact_trace_id, NULL,
            jsonb_build_object(
                'session_id', exact_current_session_id::text,
                'session_family_id', resolved_family_id::text,
                'user_id', exact_actor_user_id::text,
                'status', 'REVOKED'
            ), 'PENDING', 0, server_now, NULL, NULL, NULL, NULL, server_now
        );
    END IF;

    safe_result := jsonb_build_object(
        'outcome', result_outcome,
        'session_id', exact_current_session_id::text,
        'session_family_id', resolved_family_id::text,
        'session_status', result_status,
        'session_version', result_version,
        'replayed', false,
        'clear_current_session_cookie', true
    );
    UPDATE infra.command_receipts
    SET status = 'COMPLETED', response_schema_version = 1,
        safe_response_body = safe_result, reconstruction_metadata = NULL,
        completed_at = server_now, response_http_status = 204,
        response_schema_name = 'Empty204', response_entity_tag = NULL,
        current_user_entity_tag = NULL
    WHERE id = exact_command_id AND status = 'IN_PROGRESS';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            CONSTRAINT = 'ck_current_session_logout_context',
            MESSAGE = 'current Session logout receipt completion conflicted';
    END IF;
    RETURN safe_result;
END;
$function$;

ALTER FUNCTION iam_api.revoke_current_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.revoke_current_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_api.revoke_current_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) FROM iam_session_authenticator;
GRANT EXECUTE ON FUNCTION iam_api.revoke_current_session_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, text, text,
    timestamptz, uuid, uuid
) TO iam_app;
