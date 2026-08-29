-- IAM 0033: seventh independent ORG_ADMIN sandbox account.
--
-- The byte-frozen v1 lifecycle remains the only identity/session writer.  V4
-- supplies a derived compatibility membership for that engine, commits it only
-- as revoked bootstrap evidence, and creates the real ORG_ADMIN invitation,
-- membership, and grant in the DEMAND_OWNER account's exact organization.

CREATE OR REPLACE FUNCTION iam.enforce_membership_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.source_invitation_id IS DISTINCT FROM OLD.source_invitation_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_membership_state_transition',
            MESSAGE = 'invalid membership mutation';
    END IF;

    IF iam.internal_sandbox_bootstrap_context_v1()
       AND NULLIF(current_setting(
            'app.bootstrap_role_isolation_transition', true
       ), '') = 'RESTORE'
       AND OLD.status = 'REVOKED'
       AND NEW.status = 'ACTIVE' THEN
        RETURN NEW;
    END IF;

    IF (OLD.status = 'ACTIVE'
            AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
       OR (OLD.status = 'SUSPENDED'
            AND NEW.status NOT IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
       OR (OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_membership_state_transition',
            MESSAGE = 'invalid membership mutation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION iam.enforce_role_grant_binding_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF TG_TABLE_NAME = 'user_role_grants' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.role_code IS DISTINCT FROM OLD.role_code
           OR NEW.source_invitation_id IS DISTINCT FROM OLD.source_invitation_id
           OR NEW.policy_selector_digest IS DISTINCT FROM OLD.policy_selector_digest
           OR NEW.granted_by_kind IS DISTINCT FROM OLD.granted_by_kind
           OR NEW.granted_by_id IS DISTINCT FROM OLD.granted_by_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_role_grant_binding_immutable',
                MESSAGE = 'role grant binding is immutable';
        END IF;
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.membership_id IS DISTINCT FROM OLD.membership_id
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.role_code IS DISTINCT FROM OLD.role_code
           OR NEW.source_invitation_id IS DISTINCT FROM OLD.source_invitation_id
           OR NEW.policy_selector_digest IS DISTINCT FROM OLD.policy_selector_digest
           OR NEW.granted_by_kind IS DISTINCT FROM OLD.granted_by_kind
           OR NEW.granted_by_id IS DISTINCT FROM OLD.granted_by_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_role_grant_binding_immutable',
                MESSAGE = 'role grant binding is immutable';
        END IF;
    END IF;

    IF iam.internal_sandbox_bootstrap_context_v1()
       AND NULLIF(current_setting(
            'app.bootstrap_role_isolation_transition', true
       ), '') = 'RESTORE'
       AND OLD.revoked_at IS NOT NULL
       AND OLD.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
       AND NEW.revoked_at IS NULL
       AND NEW.revocation_reason_code IS NULL
       AND NEW.aggregate_version = OLD.aggregate_version + 1 THEN
        RETURN NEW;
    END IF;

    IF OLD.revoked_at IS NOT NULL
       OR NEW.revoked_at IS NULL
       OR NEW.revocation_reason_code IS NULL
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_role_grant_revocation',
            MESSAGE = 'invalid role grant revocation';
    END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION iam.internal_sandbox_derived_uuid_v2(
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
    'org-admin-bootstrap-command',
    'org-admin-bootstrap-receipt',
    'org-admin-bootstrap-audit',
    'org-admin-bootstrap-organization',
    'org-admin-bootstrap-invitation',
    'org-admin-bootstrap-membership',
    'org-admin-bootstrap-grant'
)
  AND exact_source_id IS NOT NULL
$function$;

ALTER FUNCTION iam.internal_sandbox_derived_uuid_v2(text, uuid)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_derived_uuid_v2(text, uuid)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_independent_role_graph_v4(
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
        item.value AS document,
        item.value->>'account_code' AS account_code,
        (item.value->>'user_id')::uuid AS user_id,
        (item.value#>>'{creator_grant,grant_id}')::uuid AS creator_grant_id,
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
        END AS org_organization_id,
        CASE WHEN jsonb_array_length(item.value->'platform_duty_grants') = 1
            THEN (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
        END AS duty_grant_id,
        CASE WHEN jsonb_array_length(item.value->'platform_duty_grants') = 1
            THEN item.value#>>'{platform_duty_grants,0,duty_code}'
        END AS duty_code
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
),
owner AS (
    SELECT * FROM accounts WHERE account_code = 'demand_owner_01'
),
org_admin AS (
    SELECT * FROM accounts WHERE account_code = 'org_admin_01'
),
active_user_roles AS (
    SELECT role_row.*
    FROM iam.user_role_grants AS role_row
    JOIN accounts AS account ON account.user_id = role_row.user_id
    WHERE role_row.revoked_at IS NULL
),
isolated_creator_roles AS (
    SELECT role_row.*
    FROM iam.user_role_grants AS role_row
    JOIN accounts AS account
      ON account.user_id = role_row.user_id
     AND account.creator_grant_id = role_row.id
    WHERE account.account_code <> 'creator_01'
      AND role_row.role_code = 'CREATOR'
      AND role_row.revoked_at IS NOT NULL
      AND role_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
),
active_duties AS (
    SELECT duty.*
    FROM iam.platform_duty_grants AS duty
    JOIN accounts AS account ON account.user_id = duty.user_id
    WHERE duty.revoked_at IS NULL
),
bootstrap_grants AS (
    SELECT owner.demand_grant_id AS id FROM owner
    UNION ALL
    SELECT org_admin.org_grant_id AS id FROM org_admin
),
active_bootstrap_membership_roles AS (
    SELECT role_row.*
    FROM iam.membership_role_grants AS role_row
    JOIN bootstrap_grants AS exact_grant ON exact_grant.id = role_row.id
    WHERE role_row.revoked_at IS NULL
),
selector AS (
    SELECT sha256(convert_to(
        '{"access_purpose":"ORGANIZATION_MEMBERSHIP",'
        '"scope_type":"ORGANIZATION_ROLE","target_role":"ORG_ADMIN",'
        '"jurisdiction":"ZZ_INTERNAL","locale":"en"}',
        'UTF8'
    )) AS digest
),
temporary AS (
    SELECT
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-organization', org_admin.org_membership_id
        ) AS organization_id,
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-invitation', org_admin.org_invitation_id
        ) AS invitation_id,
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-membership', org_admin.org_membership_id
        ) AS membership_id,
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-grant', org_admin.org_grant_id
        ) AS grant_id
    FROM org_admin
)
SELECT
    (SELECT count(*) FROM accounts) = 7
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
                ])::text,
                'UTF8'
             ))
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
          AND state.manifest_revision IN (
                (exact_manifest->>'revision')::integer,
                (exact_manifest->>'revision')::integer - 1
          )
    ) = 7
    AND (
        SELECT count(*)
        FROM infra.iam_sandbox_bootstrap_accounts AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 7
    AND EXISTS (
        SELECT 1
        FROM infra.iam_sandbox_bootstrap_state AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
          AND state.revision IN (
                (exact_manifest->>'revision')::integer,
                (exact_manifest->>'revision')::integer - 1
          )
          AND state.account_count = 7
          AND state.status = 'ACTIVE'
    )
    AND (
        SELECT count(*)
        FROM iam.users AS exact_user
        JOIN accounts AS account ON account.user_id = exact_user.id
        WHERE exact_user.status = 'ACTIVE'
          AND exact_user.display_handle = 'sandbox_' || account.account_code
    ) = 7
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
    AND (SELECT count(*) FROM isolated_creator_roles) = 6
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
    AND EXISTS (
        SELECT 1
        FROM owner
        JOIN iam.organizations AS organization
          ON organization.id = owner.demand_organization_id
         AND organization.status = 'ACTIVE'
        JOIN iam.access_invitations AS invitation
          ON invitation.id = owner.demand_invitation_id
         AND invitation.organization_id = organization.id
         AND invitation.target_role = 'DEMAND_OWNER'
         AND invitation.status = 'ACCEPTED'
        JOIN iam.memberships AS membership
          ON membership.id = owner.demand_membership_id
         AND membership.organization_id = organization.id
         AND membership.user_id = owner.user_id
         AND membership.source_invitation_id = invitation.id
         AND membership.status = 'ACTIVE'
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.id = owner.demand_grant_id
         AND grant_row.organization_id = organization.id
         AND grant_row.membership_id = membership.id
         AND grant_row.user_id = owner.user_id
         AND grant_row.source_invitation_id = invitation.id
         AND grant_row.role_code = 'DEMAND_OWNER'
         AND grant_row.revoked_at IS NULL
    )
    AND EXISTS (
        SELECT 1
        FROM org_admin
        CROSS JOIN selector
        JOIN infra.iam_sandbox_bootstrap_accounts AS account_state
          ON account_state.bootstrap_id =
                (exact_manifest->>'bootstrap_id')::uuid
         AND account_state.account_code = org_admin.account_code
         AND account_state.user_id = org_admin.user_id
        JOIN infra.iam_sandbox_bootstrap_manifest_bridges AS origin_bridge
          ON origin_bridge.bootstrap_id =
                (exact_manifest->>'bootstrap_id')::uuid
         AND origin_bridge.revision = 1
        JOIN iam.policy_selectors AS policy_selector
          ON policy_selector.selector_digest = selector.digest
         AND policy_selector.canonicalization_version =
                'policy-selector-json-v1'
         AND policy_selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
         AND policy_selector.scope_type = 'ORGANIZATION_ROLE'
         AND policy_selector.target_role = 'ORG_ADMIN'
         AND policy_selector.jurisdiction = 'ZZ_INTERNAL'
         AND policy_selector.locale = 'en'
         AND policy_selector.current_bundle_id =
                (exact_manifest#>>'{policy,org_admin_bundle_id}')::uuid
         AND policy_selector.aggregate_version = 2
         AND policy_selector.created_at = policy_selector.updated_at
        JOIN iam.policy_bundles AS bundle
          ON bundle.id = policy_selector.current_bundle_id
         AND bundle.selector_digest = selector.digest
         AND bundle.status = 'ACTIVE'
         AND bundle.effective_at IS NOT NULL
         AND bundle.effective_until IS NULL
         AND bundle.superseded_by_bundle_id IS NULL
         AND bundle.release_manifest_sha256 =
                origin_bridge.manifest_sha256
         AND bundle.release_signature = origin_bridge.manifest_sha256
         AND bundle.release_signing_key_id =
                'internal-sandbox-bootstrap-v4'
         AND bundle.aggregate_version = 2
         AND bundle.created_at = bundle.updated_at
         AND bundle.effective_at = bundle.created_at
        JOIN iam.policy_bundle_documents AS bundle_document
          ON bundle_document.bundle_id = bundle.id
         AND bundle_document.document_id =
                (exact_manifest#>>'{policy,document_id}')::uuid
         AND bundle_document.position = 1
         AND bundle_document.required
        JOIN audit.audit_events AS publication_audit
          ON publication_audit.command_id = bundle.publication_command_id
         AND publication_audit.actor_kind = 'SYSTEM'
         AND publication_audit.action_code =
                'ApplyInternalSandboxIdentityBootstrap'
         AND publication_audit.target_kind =
                'InternalSandboxIdentityBootstrap'
         AND publication_audit.target_id =
                (exact_manifest->>'bootstrap_id')::uuid
         AND publication_audit.role_code = 'ORG_ADMIN'
         AND publication_audit.purpose_code = 'INTERNAL_SANDBOX'
         AND publication_audit.reason_code = 'ORG_ADMIN_ROLE_GRAPH'
         AND publication_audit.result_code = 'SUCCEEDED'
         AND publication_audit.safe_attributes->>'account_count' = '7'
         AND publication_audit.safe_attributes->>'org_admin_count' = '1'
         AND publication_audit.safe_attributes->>'revision' = '1'
        JOIN iam.access_invitations AS invitation
          ON invitation.id = org_admin.org_invitation_id
         AND invitation.purpose = 'ORGANIZATION_MEMBERSHIP'
         AND invitation.organization_id = org_admin.org_organization_id
         AND invitation.target_scope = 'ORGANIZATION'
         AND invitation.target_role = 'ORG_ADMIN'
         AND invitation.is_initial_admin
         AND invitation.recipient_contact_id =
                account_state.invitation_contact_point_id
         AND invitation.masked_recipient_label = 'sandbox-account'
         AND invitation.policy_selector_digest = selector.digest
         AND invitation.issued_policy_bundle_id =
                (exact_manifest#>>'{policy,org_admin_bundle_id}')::uuid
         AND invitation.status = 'ACCEPTED'
         AND invitation.expires_at =
                invitation.created_at + interval '100 years'
         AND invitation.issuer_kind = 'SYSTEM'
         AND invitation.issuer_user_id IS NULL
         AND invitation.token_nonce = sha256(convert_to(
                'sandbox-org-admin-invitation|' ||
                    org_admin.org_invitation_id::text,
                'UTF8'
             ))
         AND invitation.token_key_id = 'internal-sandbox-bootstrap-v4'
         AND invitation.token_format_version =
                'access-invitation-token-v1'
         AND invitation.accepted_by_user_id = org_admin.user_id
         AND invitation.terminal_at = invitation.created_at
         AND invitation.terminal_reason_code IS NULL
         AND invitation.aggregate_version = 2
         AND invitation.created_at = invitation.updated_at
        JOIN iam.memberships AS membership
          ON membership.id = org_admin.org_membership_id
         AND membership.organization_id = org_admin.org_organization_id
         AND membership.user_id = org_admin.user_id
         AND membership.source_invitation_id = invitation.id
         AND membership.status = 'ACTIVE'
         AND membership.aggregate_version = 1
         AND membership.created_at = membership.updated_at
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.id = org_admin.org_grant_id
         AND grant_row.organization_id = org_admin.org_organization_id
         AND grant_row.membership_id = membership.id
         AND grant_row.user_id = org_admin.user_id
         AND grant_row.source_invitation_id = invitation.id
         AND grant_row.policy_selector_digest = selector.digest
         AND grant_row.role_code = 'ORG_ADMIN'
         AND grant_row.granted_by_kind = 'SYSTEM'
         AND grant_row.granted_by_id = publication_audit.actor_id
         AND grant_row.granted_at = invitation.created_at
         AND grant_row.revoked_at IS NULL
         AND grant_row.revocation_reason_code IS NULL
         AND grant_row.aggregate_version = 1
        WHERE org_admin.org_organization_id = (
            SELECT demand_organization_id FROM owner
        )
          AND (
            SELECT count(*)
            FROM iam.policy_bundle_documents AS exact_document
            WHERE exact_document.bundle_id = bundle.id
          ) = 1
    )
    AND (SELECT count(*) FROM active_bootstrap_membership_roles) = 2
    AND EXISTS (
        SELECT 1
        FROM temporary
        CROSS JOIN org_admin
        JOIN iam.organizations AS organization
          ON organization.id = temporary.organization_id
         AND organization.status = 'ACTIVE'
         AND organization.public_name = 'Sandbox Organization org_admin_01'
        JOIN iam.access_invitations AS invitation
          ON invitation.id = temporary.invitation_id
         AND invitation.organization_id = temporary.organization_id
         AND invitation.target_role = 'DEMAND_OWNER'
         AND invitation.status = 'ACCEPTED'
        JOIN iam.memberships AS membership
          ON membership.id = temporary.membership_id
         AND membership.organization_id = temporary.organization_id
         AND membership.user_id = org_admin.user_id
         AND membership.status = 'REVOKED'
        JOIN iam.membership_role_grants AS grant_row
          ON grant_row.id = temporary.grant_id
         AND grant_row.membership_id = temporary.membership_id
         AND grant_row.user_id = org_admin.user_id
         AND grant_row.role_code = 'DEMAND_OWNER'
         AND grant_row.revoked_at IS NOT NULL
         AND grant_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION'
    )
$function$;

ALTER FUNCTION iam.internal_sandbox_independent_role_graph_v4(jsonb)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_independent_role_graph_v4(jsonb)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_normalize_org_admin_graph_v1(
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
       OR jsonb_array_length(exact_manifest->'accounts') <> 7
       OR jsonb_array_length(exact_normalized_manifest->'accounts') <> 7
       OR exact_normalized_manifest_sha256 IS NULL
       OR octet_length(exact_normalized_manifest_sha256) <> 32
       OR NOT iam.internal_sandbox_independent_role_graph_v4(
            exact_manifest
       ) THEN
        RETURN false;
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
      AND status = 'ACTIVE'
      AND account_count = 7;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN RETURN false; END IF;

    UPDATE infra.iam_sandbox_bootstrap_accounts AS state
    SET authority_shape_sha256 = sha256(convert_to(
            (item.value - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text,
            'UTF8'
        )),
        updated_at = transaction_timestamp()
    FROM jsonb_array_elements(
        exact_normalized_manifest->'accounts'
    ) AS item(value)
    WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND state.account_code = item.value->>'account_code'
      AND state.user_id = (item.value->>'user_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 7 THEN RETURN false; END IF;

    UPDATE iam.platform_duty_grants AS duty
    SET duty_code = 'OPERATIONS_REVIEWER',
        updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
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
    UPDATE iam.user_role_grants AS role_row
    SET revoked_at = NULL,
        revocation_reason_code = NULL,
        aggregate_version = role_row.aggregate_version + 1
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' <> 'creator_01'
      AND role_row.id = (item.value#>>'{creator_grant,grant_id}')::uuid
      AND role_row.user_id = (item.value->>'user_id')::uuid
      AND role_row.role_code = 'CREATOR'
      AND role_row.revoked_at IS NOT NULL
      AND role_row.revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 6 THEN
        PERFORM set_config(
            'app.bootstrap_role_isolation_transition', '', true
        );
        RETURN false;
    END IF;

    UPDATE iam.memberships
    SET status = 'ACTIVE',
        aggregate_version = aggregate_version + 1,
        updated_at = transaction_timestamp()
    WHERE id = temporary_membership_id
      AND status = 'REVOKED';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        PERFORM set_config(
            'app.bootstrap_role_isolation_transition', '', true
        );
        RETURN false;
    END IF;

    UPDATE iam.membership_role_grants
    SET revoked_at = NULL,
        revocation_reason_code = NULL,
        aggregate_version = aggregate_version + 1
    WHERE id = temporary_grant_id
      AND role_code = 'DEMAND_OWNER'
      AND revoked_at IS NOT NULL
      AND revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION';
    GET DIAGNOSTICS affected = ROW_COUNT;
    PERFORM set_config(
        'app.bootstrap_role_isolation_transition', '', true
    );
    RETURN affected = 1;
END
$function$;

ALTER FUNCTION iam.internal_sandbox_normalize_org_admin_graph_v1(
    jsonb, jsonb, bytea
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_normalize_org_admin_graph_v1(
    jsonb, jsonb, bytea
) FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_apply_org_admin_graph_v1(
    exact_manifest jsonb,
    exact_manifest_sha256 bytea,
    isolate_roles boolean,
    exact_system_actor_id uuid,
    exact_command_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra
AS $function$
DECLARE
    fixed_jurisdiction constant text := 'ZZ_INTERNAL';
    fixed_locale constant text := 'en';
    org_admin jsonb;
    org_admin_user_id uuid;
    org_admin_bundle_id uuid;
    org_admin_selector_digest bytea;
    fixed_document_id uuid;
    temporary_membership_id uuid;
    temporary_grant_id uuid;
    affected integer;
BEGIN
    IF NOT iam.internal_sandbox_bootstrap_context_v1()
       OR jsonb_array_length(exact_manifest->'accounts') <> 7
       OR exact_manifest_sha256 IS NULL
       OR octet_length(exact_manifest_sha256) <> 32
       OR isolate_roles IS NULL
       OR exact_system_actor_id IS NULL
       OR exact_command_id IS NULL THEN
        RETURN false;
    END IF;
    SELECT item.value INTO org_admin
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' = 'org_admin_01';
    IF NOT FOUND THEN RETURN false; END IF;

    org_admin_user_id := (org_admin->>'user_id')::uuid;
    org_admin_bundle_id :=
        (exact_manifest#>>'{policy,org_admin_bundle_id}')::uuid;
    fixed_document_id := (exact_manifest#>>'{policy,document_id}')::uuid;
    org_admin_selector_digest := sha256(convert_to(
        '{"access_purpose":"ORGANIZATION_MEMBERSHIP",'
        '"scope_type":"ORGANIZATION_ROLE","target_role":"ORG_ADMIN",'
        '"jurisdiction":"ZZ_INTERNAL","locale":"en"}',
        'UTF8'
    ));
    temporary_membership_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-membership',
        (org_admin#>>'{organization_grant,membership_id}')::uuid
    );
    temporary_grant_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-grant',
        (org_admin#>>'{organization_grant,grant_id}')::uuid
    );

    IF NOT EXISTS (
        SELECT 1 FROM iam.policy_bundles
        WHERE id = org_admin_bundle_id
    ) THEN
        INSERT INTO iam.policy_selectors (
            selector_digest, canonicalization_version, access_purpose,
            scope_type, target_role, jurisdiction, locale, current_bundle_id,
            aggregate_version, created_at, updated_at
        ) VALUES (
            org_admin_selector_digest, 'policy-selector-json-v1',
            'ORGANIZATION_MEMBERSHIP', 'ORGANIZATION_ROLE', 'ORG_ADMIN',
            fixed_jurisdiction, fixed_locale, NULL, 1,
            transaction_timestamp(), transaction_timestamp()
        ) ON CONFLICT (selector_digest) DO NOTHING;

        INSERT INTO iam.policy_bundles (
            id, selector_digest, status, effective_at, effective_until,
            superseded_by_bundle_id, release_manifest_sha256,
            release_signature, release_signing_key_id,
            publication_command_id, aggregate_version, created_at, updated_at
        ) VALUES (
            org_admin_bundle_id, org_admin_selector_digest,
            'DRAFT', NULL, NULL, NULL,
            exact_manifest_sha256, exact_manifest_sha256,
            'internal-sandbox-bootstrap-v4', exact_command_id, 1,
            transaction_timestamp(), transaction_timestamp()
        );

        INSERT INTO iam.policy_bundle_documents (
            bundle_id, document_id, position, required
        ) VALUES (org_admin_bundle_id, fixed_document_id, 1, true);

        UPDATE iam.policy_bundles
        SET status = 'ACTIVE', effective_at = transaction_timestamp(),
            aggregate_version = 2, updated_at = transaction_timestamp()
        WHERE id = org_admin_bundle_id AND status = 'DRAFT';
        UPDATE iam.policy_selectors
        SET current_bundle_id = org_admin_bundle_id,
            aggregate_version = aggregate_version + 1,
            updated_at = transaction_timestamp()
        WHERE selector_digest = org_admin_selector_digest
          AND current_bundle_id IS NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        JOIN iam.policy_bundles AS bundle
          ON bundle.id = selector.current_bundle_id
         AND bundle.selector_digest = selector.selector_digest
        JOIN iam.policy_bundle_documents AS membership
          ON membership.bundle_id = bundle.id
         AND membership.document_id = fixed_document_id
         AND membership.position = 1
         AND membership.required
        WHERE selector.selector_digest = org_admin_selector_digest
          AND selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
          AND selector.scope_type = 'ORGANIZATION_ROLE'
          AND selector.target_role = 'ORG_ADMIN'
          AND selector.jurisdiction = fixed_jurisdiction
          AND selector.locale = fixed_locale
          AND bundle.id = org_admin_bundle_id
          AND bundle.status = 'ACTIVE'
    ) THEN RETURN false; END IF;

    INSERT INTO iam.access_invitations (
        id, purpose, organization_id, target_scope, target_role,
        is_initial_admin, recipient_contact_id, masked_recipient_label,
        policy_selector_digest, issued_policy_bundle_id, status, expires_at,
        issuer_kind, issuer_user_id, token_nonce, token_key_id,
        accepted_by_user_id, terminal_at, terminal_reason_code,
        aggregate_version, created_at, updated_at
    )
    SELECT
        (org_admin#>>'{organization_grant,invitation_id}')::uuid,
        'ORGANIZATION_MEMBERSHIP',
        (org_admin#>>'{organization_grant,organization_id}')::uuid,
        'ORGANIZATION', 'ORG_ADMIN', true,
        state.invitation_contact_point_id, 'sandbox-account',
        org_admin_selector_digest, org_admin_bundle_id, 'ACCEPTED',
        transaction_timestamp() + interval '100 years', 'SYSTEM', NULL,
        sha256(convert_to(
            'sandbox-org-admin-invitation|' ||
            (org_admin#>>'{organization_grant,invitation_id}'), 'UTF8'
        )), 'internal-sandbox-bootstrap-v4', org_admin_user_id,
        transaction_timestamp(), NULL, 2,
        transaction_timestamp(), transaction_timestamp()
    FROM infra.iam_sandbox_bootstrap_accounts AS state
    WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND state.account_code = 'org_admin_01'
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO iam.memberships (
        id, organization_id, user_id, status, source_invitation_id,
        aggregate_version, created_at, updated_at
    ) VALUES (
        (org_admin#>>'{organization_grant,membership_id}')::uuid,
        (org_admin#>>'{organization_grant,organization_id}')::uuid,
        org_admin_user_id, 'ACTIVE',
        (org_admin#>>'{organization_grant,invitation_id}')::uuid,
        1, transaction_timestamp(), transaction_timestamp()
    ) ON CONFLICT (id) DO NOTHING;

    INSERT INTO iam.membership_role_grants (
        id, organization_id, membership_id, user_id, role_code,
        source_invitation_id, policy_selector_digest, granted_by_kind,
        granted_by_id, granted_at, revoked_at, revocation_reason_code,
        aggregate_version
    ) VALUES (
        (org_admin#>>'{organization_grant,grant_id}')::uuid,
        (org_admin#>>'{organization_grant,organization_id}')::uuid,
        (org_admin#>>'{organization_grant,membership_id}')::uuid,
        org_admin_user_id, 'ORG_ADMIN',
        (org_admin#>>'{organization_grant,invitation_id}')::uuid,
        org_admin_selector_digest, 'SYSTEM', exact_system_actor_id,
        transaction_timestamp(), NULL, NULL, 1
    ) ON CONFLICT (id) DO NOTHING;

    UPDATE iam.platform_duty_grants AS duty
    SET duty_code = 'FINANCE_OPERATOR',
        updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE item.value->>'account_code' IN (
            'finance_operator_01', 'finance_operator_02'
      )
      AND duty.id = (item.value#>>'{platform_duty_grants,0,grant_id}')::uuid
      AND duty.user_id = (item.value->>'user_id')::uuid
      AND duty.duty_code = 'OPERATIONS_REVIEWER';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 2 THEN RETURN false; END IF;

    IF isolate_roles THEN
        UPDATE iam.user_role_grants AS role_row
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION',
            aggregate_version = role_row.aggregate_version + 1
        FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
        WHERE item.value->>'account_code' <> 'creator_01'
          AND role_row.id = (item.value#>>'{creator_grant,grant_id}')::uuid
          AND role_row.user_id = (item.value->>'user_id')::uuid
          AND role_row.role_code = 'CREATOR'
          AND role_row.revoked_at IS NULL;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 6 THEN RETURN false; END IF;

        UPDATE iam.membership_role_grants
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ROLE_ISOLATION',
            aggregate_version = aggregate_version + 1
        WHERE id = temporary_grant_id
          AND role_code = 'DEMAND_OWNER'
          AND revoked_at IS NULL;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 1 THEN RETURN false; END IF;

        UPDATE iam.memberships
        SET status = 'REVOKED',
            aggregate_version = aggregate_version + 1,
            updated_at = transaction_timestamp()
        WHERE id = temporary_membership_id
          AND status = 'ACTIVE';
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 1 THEN RETURN false; END IF;
    END IF;

    UPDATE infra.iam_sandbox_bootstrap_state
    SET manifest_sha256 = exact_manifest_sha256,
        updated_at = transaction_timestamp()
    WHERE bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN RETURN false; END IF;

    UPDATE infra.iam_sandbox_bootstrap_accounts AS state
    SET authority_shape_sha256 = sha256(convert_to(
            (item.value - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text,
            'UTF8'
        )),
        updated_at = transaction_timestamp()
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
    WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
      AND state.account_code = item.value->>'account_code'
      AND state.user_id = (item.value->>'user_id')::uuid;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 7 THEN RETURN false; END IF;

    RETURN true;
END
$function$;

ALTER FUNCTION iam.internal_sandbox_apply_org_admin_graph_v1(
    jsonb, bytea, boolean, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_apply_org_admin_graph_v1(
    jsonb, bytea, boolean, uuid, uuid
) FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_manifest_v4_valid(
    exact_manifest jsonb,
    exact_bootstrap_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, iam
AS $function$
WITH accounts AS (
    SELECT item.value AS document
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
),
identifiers AS (
    SELECT exact_bootstrap_id::text AS value
    UNION ALL SELECT exact_manifest#>>'{policy,creator_bundle_id}'
    UNION ALL SELECT exact_manifest#>>'{policy,demand_owner_bundle_id}'
    UNION ALL SELECT exact_manifest#>>'{policy,document_id}'
    UNION ALL SELECT exact_manifest#>>'{policy,org_admin_bundle_id}'
    UNION ALL
    SELECT identifier.value
    FROM accounts AS account
    CROSS JOIN LATERAL (
        VALUES
            (account.document->>'user_id'),
            (account.document#>>'{external_identity,id}'),
            (account.document#>>'{contact_point,id}'),
            (account.document->>'activation_event_id'),
            (account.document->>'revocation_event_id'),
            (account.document#>>'{creator_grant,grant_id}'),
            (account.document#>>'{creator_grant,invitation_id}'),
            (account.document#>>'{demand_owner_grant,grant_id}'),
            (account.document#>>'{demand_owner_grant,invitation_id}'),
            (account.document#>>'{demand_owner_grant,membership_id}'),
            (account.document#>>'{organization_grant,grant_id}'),
            (account.document#>>'{organization_grant,invitation_id}'),
            (account.document#>>'{organization_grant,membership_id}'),
            (account.document#>>'{platform_duty_grants,0,grant_id}')
    ) AS identifier(value)
    WHERE identifier.value IS NOT NULL
    UNION ALL
    SELECT account.document#>>'{demand_owner_grant,organization_id}'
    FROM accounts AS account
    WHERE account.document->>'account_code' = 'demand_owner_01'
),
derived AS (
    SELECT value
    FROM (
        SELECT iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-organization',
            (account.document#>>'{organization_grant,membership_id}')::uuid
        ) AS organization_id,
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-invitation',
            (account.document#>>'{organization_grant,invitation_id}')::uuid
        ) AS invitation_id,
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-membership',
            (account.document#>>'{organization_grant,membership_id}')::uuid
        ) AS membership_id,
        iam.internal_sandbox_derived_uuid_v2(
            'org-admin-bootstrap-grant',
            (account.document#>>'{organization_grant,grant_id}')::uuid
        ) AS grant_id
        FROM accounts AS account
        WHERE account.document->>'account_code' = 'org_admin_01'
    ) AS values_row
    CROSS JOIN LATERAL unnest(ARRAY[
        values_row.organization_id, values_row.invitation_id,
        values_row.membership_id, values_row.grant_id
    ]) AS value
)
SELECT
    iam.sandbox_jsonb_has_exact_keys_v1(
        exact_manifest,
        ARRAY[
            'accounts', 'bootstrap_id', 'environment_id', 'issuer', 'policy',
            'previous_manifest_sha256', 'revision', 'schema_name'
        ]
    )
    AND exact_manifest->>'schema_name'
        = 'desire-internal-sandbox-identity-bootstrap-v1'
    AND exact_manifest->>'environment_id' = 'internal-sandbox'
    AND exact_manifest->>'bootstrap_id' = exact_bootstrap_id::text
    AND exact_manifest->>'issuer' ~ '^https://[^/@?#]+(?:/[^?#]*)?$'
    AND right(exact_manifest->>'issuer', 1) <> '/'
    AND jsonb_typeof(exact_manifest->'revision') = 'number'
    AND (exact_manifest->>'revision')::integer >= 1
    AND (
        (
            (exact_manifest->>'revision')::integer = 1
            AND jsonb_typeof(
                exact_manifest->'previous_manifest_sha256'
            ) = 'null'
        ) OR (
            (exact_manifest->>'revision')::integer > 1
            AND coalesce(
                exact_manifest->>'previous_manifest_sha256', ''
            ) ~ '^[0-9a-f]{64}$'
        )
    )
    AND jsonb_typeof(exact_manifest->'accounts') = 'array'
    AND jsonb_array_length(exact_manifest->'accounts') = 7
    AND iam.sandbox_jsonb_has_exact_keys_v1(
        exact_manifest->'policy',
        ARRAY[
            'creator_bundle_id', 'demand_owner_bundle_id', 'document_id',
            'org_admin_bundle_id'
        ]
    )
    AND (
        SELECT array_agg(document->>'account_code' ORDER BY document->>'account_code')
        FROM accounts
    ) = ARRAY[
        'access_admin_01', 'creator_01', 'demand_owner_01',
        'finance_operator_01', 'finance_operator_02',
        'operations_reviewer_01', 'org_admin_01'
    ]
    AND NOT EXISTS (
        SELECT 1
        FROM accounts AS account
        WHERE NOT iam.sandbox_jsonb_has_exact_keys_v1(
                account.document,
                ARRAY[
                    'account_code', 'activation_event_id', 'contact_point',
                    'creator_grant', 'demand_owner_grant',
                    'external_identity', 'organization_grant',
                    'platform_duty_grants', 'revocation_event_id', 'user_id'
                ]
              )
           OR account.document->>'account_code'
                !~ '^[a-z][a-z0-9_]{2,31}$'
           OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
                account.document->'external_identity',
                ARRAY[
                    'id', 'subject_digest_key_id', 'subject_digest_sha256'
                ]
              )
           OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
                account.document->'contact_point',
                ARRAY[
                    'id', 'recipient_binding_digest_key_id',
                    'recipient_binding_digest_sha256'
                ]
              )
           OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
                account.document->'creator_grant',
                ARRAY['grant_id', 'invitation_id']
              )
           OR coalesce(
                account.document#>>'{external_identity,subject_digest_sha256}',
                ''
              ) !~ '^[0-9a-f]{64}$'
           OR coalesce(
                account.document#>>'{contact_point,recipient_binding_digest_sha256}',
                ''
              ) !~ '^[0-9a-f]{64}$'
           OR coalesce(
                account.document#>>'{external_identity,subject_digest_key_id}',
                ''
              ) !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'
           OR coalesce(
                account.document#>>'{contact_point,recipient_binding_digest_key_id}',
                ''
              ) !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'
           OR jsonb_typeof(account.document->'platform_duty_grants')
                <> 'array'
           OR EXISTS (
                SELECT 1
                FROM jsonb_array_elements(
                    account.document->'platform_duty_grants'
                ) AS duty(value)
                WHERE NOT iam.sandbox_jsonb_has_exact_keys_v1(
                    duty.value, ARRAY['duty_code', 'grant_id']
                )
           )
           OR CASE account.document->>'account_code'
                WHEN 'access_admin_01' THEN NOT (
                    jsonb_typeof(account.document->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account.document->'organization_grant') = 'null'
                    AND jsonb_array_length(
                        account.document->'platform_duty_grants'
                    ) = 1
                    AND account.document#>>'{platform_duty_grants,0,duty_code}'
                        = 'ACCESS_ADMIN'
                )
                WHEN 'creator_01' THEN NOT (
                    jsonb_typeof(account.document->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account.document->'organization_grant') = 'null'
                    AND account.document->'platform_duty_grants' = '[]'::jsonb
                )
                WHEN 'demand_owner_01' THEN NOT (
                    iam.sandbox_jsonb_has_exact_keys_v1(
                        account.document->'demand_owner_grant',
                        ARRAY['grant_id','invitation_id','membership_id','organization_id']
                    )
                    AND jsonb_typeof(account.document->'organization_grant') = 'null'
                    AND account.document->'platform_duty_grants' = '[]'::jsonb
                )
                WHEN 'finance_operator_01' THEN NOT (
                    jsonb_typeof(account.document->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account.document->'organization_grant') = 'null'
                    AND jsonb_array_length(
                        account.document->'platform_duty_grants'
                    ) = 1
                    AND account.document#>>'{platform_duty_grants,0,duty_code}'
                        = 'FINANCE_OPERATOR'
                )
                WHEN 'finance_operator_02' THEN NOT (
                    jsonb_typeof(account.document->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account.document->'organization_grant') = 'null'
                    AND jsonb_array_length(
                        account.document->'platform_duty_grants'
                    ) = 1
                    AND account.document#>>'{platform_duty_grants,0,duty_code}'
                        = 'FINANCE_OPERATOR'
                )
                WHEN 'operations_reviewer_01' THEN NOT (
                    jsonb_typeof(account.document->'demand_owner_grant') = 'null'
                    AND jsonb_typeof(account.document->'organization_grant') = 'null'
                    AND jsonb_array_length(
                        account.document->'platform_duty_grants'
                    ) = 1
                    AND account.document#>>'{platform_duty_grants,0,duty_code}'
                        = 'OPERATIONS_REVIEWER'
                )
                WHEN 'org_admin_01' THEN NOT (
                    jsonb_typeof(account.document->'demand_owner_grant') = 'null'
                    AND iam.sandbox_jsonb_has_exact_keys_v1(
                        account.document->'organization_grant',
                        ARRAY['grant_id','invitation_id','membership_id','organization_id','role_code']
                    )
                    AND account.document#>>'{organization_grant,role_code}' = 'ORG_ADMIN'
                    AND account.document->'platform_duty_grants' = '[]'::jsonb
                )
                ELSE true
              END
    )
    AND (
        SELECT count(DISTINCT (
            document#>>'{external_identity,subject_digest_sha256}'
        )) FROM accounts
    ) = 7
    AND (
        SELECT count(DISTINCT (
            (document#>>'{contact_point,recipient_binding_digest_key_id}')
            || ':' ||
            (document#>>'{contact_point,recipient_binding_digest_sha256}')
        )) FROM accounts
    ) = 7
    AND (
        SELECT document#>>'{demand_owner_grant,organization_id}'
        FROM accounts WHERE document->>'account_code' = 'demand_owner_01'
    ) = (
        SELECT document#>>'{organization_grant,organization_id}'
        FROM accounts WHERE document->>'account_code' = 'org_admin_01'
    )
    AND (SELECT count(*) FROM identifiers) =
        (SELECT count(DISTINCT value) FROM identifiers)
    AND NOT EXISTS (
        SELECT 1 FROM identifiers
        WHERE value::uuid = '00000000-0000-0000-0000-000000000000'::uuid
    )
    AND (SELECT count(*) FROM derived) = 4
    AND (SELECT count(DISTINCT value) FROM derived) = 4
    AND NOT EXISTS (
        SELECT 1 FROM derived
        JOIN identifiers ON identifiers.value::uuid = derived.value
    )
$function$;

ALTER FUNCTION iam.internal_sandbox_manifest_v4_valid(jsonb, uuid)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_manifest_v4_valid(jsonb, uuid)
FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_revoked_role_graph_v4(
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
    SELECT
        item.value AS document,
        item.value->>'account_code' AS account_code,
        (item.value->>'user_id')::uuid AS user_id
    FROM jsonb_array_elements(exact_manifest->'accounts') AS item(value)
),
bootstrap_users AS (
    SELECT user_id FROM accounts
)
SELECT
    exact_manifest_sha256 IS NOT NULL
    AND octet_length(exact_manifest_sha256) = 32
    AND (SELECT count(*) FROM accounts) = 7
    AND EXISTS (
        SELECT 1
        FROM infra.iam_sandbox_bootstrap_state AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
          AND state.manifest_sha256 = exact_manifest_sha256
          AND state.revision = (exact_manifest->>'revision')::integer
          AND state.issuer = exact_manifest->>'issuer'
          AND state.account_count = 7
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
         AND state.current_subject_digest_key_id =
                account.document#>>'{external_identity,subject_digest_key_id}'
         AND state.current_contact_point_id =
                (account.document#>>'{contact_point,id}')::uuid
         AND state.current_recipient_binding_digest = decode(
                account.document#>>'{contact_point,recipient_binding_digest_sha256}',
                'hex'
             )
         AND state.current_recipient_binding_digest_key_id =
                account.document#>>'{contact_point,recipient_binding_digest_key_id}'
         AND state.authority_shape_sha256 = sha256(convert_to(
                (account.document - ARRAY[
                    'activation_event_id', 'contact_point',
                    'external_identity', 'revocation_event_id'
                ])::text,
                'UTF8'
             ))
         AND state.manifest_revision =
                (exact_manifest->>'revision')::integer
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 7
    AND (
        SELECT count(*)
        FROM infra.iam_sandbox_bootstrap_accounts AS state
        WHERE state.bootstrap_id = (exact_manifest->>'bootstrap_id')::uuid
    ) = 7
    AND (
        SELECT count(*)
        FROM iam.users AS exact_user
        JOIN accounts AS account ON account.user_id = exact_user.id
        WHERE exact_user.status = 'SUSPENDED'
          AND exact_user.display_handle = 'sandbox_' || account.account_code
    ) = 7
    AND (
        SELECT count(*)
        FROM iam.external_identities AS identity
        JOIN accounts AS account
          ON identity.id =
                (account.document#>>'{external_identity,id}')::uuid
         AND identity.user_id = account.user_id
        WHERE identity.status = 'REVOKED'
          AND identity.issuer = exact_manifest->>'issuer'
    ) = 7
    AND NOT EXISTS (
        SELECT 1 FROM iam.external_identities AS identity
        JOIN bootstrap_users AS exact_user ON exact_user.user_id = identity.user_id
        WHERE identity.status = 'ACTIVE'
    )
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

ALTER FUNCTION iam.internal_sandbox_revoked_role_graph_v4(jsonb, bytea)
OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam.internal_sandbox_revoked_role_graph_v4(
    jsonb, bytea
) FROM PUBLIC;

CREATE FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v4(
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
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_invocation',
            MESSAGE = 'internal sandbox org admin bootstrap invocation invalid';
    END IF;

    BEGIN
        manifest_document := convert_from(
            exact_canonical_manifest, 'UTF8'
        )::jsonb;
        manifest_revision := (manifest_document->>'revision')::integer;
        IF NOT iam.internal_sandbox_manifest_v4_valid(
            manifest_document, exact_bootstrap_id
        ) THEN
            RAISE EXCEPTION 'closed manifest rejected';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_manifest',
            MESSAGE = 'internal sandbox org admin bootstrap manifest invalid';
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
            CASE item.value->>'account_code'
                WHEN 'finance_operator_01' THEN jsonb_set(
                    item.value - 'organization_grant'::text,
                    '{platform_duty_grants,0,duty_code}',
                    to_jsonb('OPERATIONS_REVIEWER'::text),
                    false
                )
                WHEN 'finance_operator_02' THEN jsonb_set(
                    item.value - 'organization_grant'::text,
                    '{platform_duty_grants,0,duty_code}',
                    to_jsonb('OPERATIONS_REVIEWER'::text),
                    false
                )
                WHEN 'org_admin_01' THEN jsonb_set(
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
                    ),
                    false
                )
                ELSE item.value - 'organization_grant'::text
            END
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
                CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_bridge',
                MESSAGE = 'internal sandbox org admin bootstrap bridge missing';
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
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_normalization',
            MESSAGE = 'internal sandbox org admin bootstrap normalization invalid';
    END IF;

    internal_command_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-command', exact_command_id
    );
    internal_receipt_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-receipt', exact_receipt_id
    );
    internal_audit_event_id := iam.internal_sandbox_derived_uuid_v2(
        'org-admin-bootstrap-audit', exact_audit_event_id
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
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_identifiers',
            MESSAGE = 'internal sandbox org admin bootstrap identifiers invalid';
    END IF;

    PERFORM pg_advisory_xact_lock(1229016369, 33);
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
           AND state_row.account_count = 7
           AND current_normalized_digest = normalized_manifest_digest
           AND exact_action IN ('VERIFY', 'REVOKE_ACCESS')
           AND iam.internal_sandbox_revoked_role_graph_v4(
                manifest_document, exact_manifest_sha256
           ) THEN
            RETURN QUERY SELECT
                'ALREADY_REVOKED'::text, manifest_revision, 7;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_revoked',
            MESSAGE = 'internal sandbox org admin bootstrap was revoked';
    END IF;

    IF state_found
       AND state_row.status = 'ACTIVE'
       AND state_row.manifest_sha256 = exact_manifest_sha256
       AND state_row.revision = manifest_revision
       AND state_row.issuer = manifest_document->>'issuer'
       AND state_row.account_count = 7
       AND exact_action IN ('APPLY', 'VERIFY') THEN
        IF NOT iam.internal_sandbox_independent_role_graph_v4(
            manifest_document
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_graph',
                MESSAGE = 'internal sandbox org admin bootstrap graph drifted';
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
                CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_bridge',
                MESSAGE = 'internal sandbox org admin bootstrap bridge drifted';
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
            IF NOT iam.internal_sandbox_normalize_org_admin_graph_v1(
                manifest_document,
                normalized_manifest,
                current_normalized_digest
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'Z3302',
                    MESSAGE = 'normalized org admin bootstrap graph invalid';
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
                ERRCODE = 'Z3301',
                MESSAGE = 'rollback normalized org admin bootstrap replay';
        EXCEPTION WHEN SQLSTATE 'Z3301' THEN
            NULL;
        END;
        PERFORM set_config('app.command_id', exact_command_id::text, true);
        PERFORM set_config(
            'app.manifest_sha256', encode(exact_manifest_sha256, 'hex'), true
        );
    ELSE
        IF state_found THEN
            IF state_row.status <> 'ACTIVE'
               OR state_row.account_count <> 7
               OR NOT iam.internal_sandbox_independent_role_graph_v4(
                    manifest_document
               ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_graph',
                    MESSAGE = 'internal sandbox org admin bootstrap graph drifted';
            END IF;
            SELECT bridge.normalized_manifest_sha256
            INTO current_normalized_digest
            FROM infra.iam_sandbox_bootstrap_manifest_bridges AS bridge
            WHERE bridge.bootstrap_id = exact_bootstrap_id
              AND bridge.revision = state_row.revision
              AND bridge.manifest_sha256 = state_row.manifest_sha256;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_bridge',
                    MESSAGE = 'internal sandbox org admin bootstrap bridge missing';
            END IF;
            IF NOT iam.internal_sandbox_normalize_org_admin_graph_v1(
                manifest_document,
                normalized_manifest,
                current_normalized_digest
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_restore',
                    MESSAGE = 'internal sandbox org admin bootstrap restore failed';
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
            IF NOT iam.internal_sandbox_apply_org_admin_graph_v1(
                manifest_document,
                exact_manifest_sha256,
                true,
                exact_system_actor_id,
                exact_command_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_isolation',
                    MESSAGE = 'internal sandbox org admin bootstrap isolation failed';
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
            IF NOT iam.internal_sandbox_apply_org_admin_graph_v1(
                manifest_document,
                exact_manifest_sha256,
                false,
                exact_system_actor_id,
                exact_command_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_revoke',
                    MESSAGE = 'internal sandbox org admin bootstrap revoke projection failed';
            END IF;
            IF NOT iam.internal_sandbox_revoked_role_graph_v4(
                manifest_document, exact_manifest_sha256
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_revoke',
                    MESSAGE = 'internal sandbox org admin bootstrap revoked graph invalid';
            END IF;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_outcome',
                MESSAGE = 'internal sandbox org admin bootstrap outcome invalid';
        END IF;
    END IF;

    IF base_revision <> manifest_revision
       OR base_account_count <> 7
       OR base_outcome NOT IN (
            'APPLIED', 'ROTATED', 'REPLAYED', 'VERIFIED', 'REVOKED'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_result',
            MESSAGE = 'internal sandbox org admin bootstrap result invalid';
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
                = 'internal-sandbox-bootstrap-v4'
          AND receipt.idempotency_key_digest = sha256(convert_to(
                exact_action || '|' || encode(exact_manifest_sha256, 'hex'),
                'UTF8'
          ))
        FOR UPDATE;
        IF NOT FOUND
           OR prior_receipt.status <> 'COMPLETED'
           OR prior_receipt.payload_hash_key_id
                <> 'internal-sandbox-bootstrap-v4'
           OR prior_receipt.payload_hash <> exact_manifest_sha256
           OR prior_receipt.target_kind
                <> 'InternalSandboxIdentityBootstrap'
           OR prior_receipt.target_id <> exact_bootstrap_id
           OR prior_receipt.safe_response_body->>'account_count' <> '7'
           OR prior_receipt.safe_response_body->>'manifest_sha256'
                <> encode(exact_manifest_sha256, 'hex')
           OR (prior_receipt.safe_response_body->>'revision')::integer
                <> manifest_revision
           OR prior_receipt.safe_response_body->>'outcome'
                NOT IN ('APPLIED', 'ROTATED') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_replay',
                MESSAGE = 'internal sandbox org admin bootstrap replay invalid';
        END IF;
        RETURN QUERY SELECT base_outcome, manifest_revision, 7;
        RETURN;
    ELSIF base_outcome = 'VERIFIED' THEN
        RETURN QUERY SELECT base_outcome, manifest_revision, 7;
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
        )), 'internal-sandbox-bootstrap-v4', exact_manifest_sha256,
        'internal-sandbox-bootstrap-v4', 'restricted-canonical-json-v1',
        'InternalSandboxIdentityBootstrap', exact_bootstrap_id, 'POST',
        '/v1/deployment/internal-sandbox/identity-bootstrap/' ||
            exact_bootstrap_id::text || '/' || lower(exact_action),
        before_revision, 'COMPLETED', 1,
        jsonb_build_object(
            'account_count', 7,
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
        before_revision, manifest_revision, 'ORG_ADMIN', 'INTERNAL_SANDBOX',
        'ORG_ADMIN_ROLE_GRAPH', NULL, 'SUCCEEDED', exact_command_id,
        exact_correlation_id, exact_command_id, exact_trace_id,
        jsonb_build_object(
            'account_count', 7,
            'manifest_sha256', encode(exact_manifest_sha256, 'hex'),
            'org_admin_count', 1,
            'revision', manifest_revision
        )
    );

    IF base_outcome IN ('APPLIED', 'ROTATED')
       AND NOT iam.internal_sandbox_independent_role_graph_v4(
            manifest_document
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_org_admin_bootstrap_final_graph',
            MESSAGE = 'internal sandbox org admin bootstrap final graph invalid';
    END IF;

    RETURN QUERY SELECT base_outcome, manifest_revision, 7;
END
$function$;

ALTER FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v4(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v4(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v3(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
FROM iam_sandbox_bootstrap;
REVOKE EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v2(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
FROM iam_sandbox_bootstrap;
GRANT EXECUTE ON FUNCTION
    iam_api.manage_internal_sandbox_identity_bootstrap_v4(
        text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
    )
TO iam_sandbox_bootstrap;

GRANT USAGE ON SCHEMA iam_api TO demand_schema_owner;
GRANT EXECUTE ON FUNCTION
    iam_api.resolve_demand_owner_authority_marker_v1(
        uuid, uuid, uuid, text, uuid
    )
TO demand_schema_owner;
REVOKE EXECUTE ON FUNCTION
    iam_api.resolve_demand_owner_authority_marker_v1(
        uuid, uuid, uuid, text, uuid
    )
FROM PUBLIC, demand_review, demand_finance;
