-- IAM 0023: deployment-only, digest-pinned synthetic identity bootstrap.
-- This capability is not an online API role and cannot manufacture a Session,
-- policy acceptance, public registration, or automatic OIDC enrollment.

DO $role_guard$
DECLARE
    role_facts record;
BEGIN
    SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
           rolbypassrls
    INTO role_facts
    FROM pg_catalog.pg_roles
    WHERE rolname = 'iam_sandbox_bootstrap';

    IF NOT FOUND
       OR NOT role_facts.rolcanlogin
       OR role_facts.rolinherit
       OR role_facts.rolsuper
       OR role_facts.rolcreatedb
       OR role_facts.rolcreaterole
       OR role_facts.rolbypassrls
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            JOIN pg_catalog.pg_roles AS member_role
              ON member_role.oid = membership.member
            WHERE member_role.rolname = 'iam_sandbox_bootstrap'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_role',
            MESSAGE = 'internal sandbox bootstrap role is not provisioned';
    END IF;
END
$role_guard$;

CREATE TABLE infra.iam_sandbox_bootstrap_state (
    bootstrap_id uuid NOT NULL,
    manifest_sha256 bytea NOT NULL,
    revision integer NOT NULL,
    issuer varchar(2048) NOT NULL,
    account_count integer NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_iam_sandbox_bootstrap_state PRIMARY KEY (bootstrap_id),
    CONSTRAINT ck_iam_sandbox_bootstrap_state_digest CHECK (
        octet_length(manifest_sha256) = 32
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_state_revision CHECK (revision >= 1),
    CONSTRAINT ck_iam_sandbox_bootstrap_state_accounts CHECK (
        account_count BETWEEN 2 AND 16
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_state_status CHECK (
        status IN ('ACTIVE', 'REVOKED')
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_state_time CHECK (
        updated_at >= created_at
    )
);

CREATE TABLE infra.iam_sandbox_bootstrap_accounts (
    bootstrap_id uuid NOT NULL,
    account_code varchar(32) NOT NULL,
    user_id uuid NOT NULL,
    current_external_identity_id uuid NOT NULL,
    current_subject_digest bytea NOT NULL,
    current_subject_digest_key_id varchar(64) NOT NULL,
    invitation_contact_point_id uuid NOT NULL,
    current_contact_point_id uuid NOT NULL,
    current_recipient_binding_digest bytea NOT NULL,
    current_recipient_binding_digest_key_id varchar(64) NOT NULL,
    activation_event_id uuid NOT NULL,
    revocation_event_id uuid NOT NULL,
    authority_shape_sha256 bytea NOT NULL,
    manifest_revision integer NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_iam_sandbox_bootstrap_accounts PRIMARY KEY (
        bootstrap_id,
        account_code
    ),
    CONSTRAINT fk_iam_sandbox_bootstrap_account_state FOREIGN KEY (bootstrap_id)
        REFERENCES infra.iam_sandbox_bootstrap_state (bootstrap_id)
        ON DELETE RESTRICT,
    CONSTRAINT uq_iam_sandbox_bootstrap_account_user UNIQUE (user_id),
    CONSTRAINT uq_iam_sandbox_bootstrap_account_identity UNIQUE (
        current_external_identity_id
    ),
    CONSTRAINT uq_iam_sandbox_bootstrap_account_contact UNIQUE (
        current_contact_point_id
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_account_code CHECK (
        account_code ~ '^[a-z][a-z0-9_]{2,31}$'
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_account_shape CHECK (
        octet_length(authority_shape_sha256) = 32
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_account_digests CHECK (
        octet_length(current_subject_digest) = 32
        AND octet_length(current_recipient_binding_digest) = 32
        AND length(current_subject_digest_key_id) > 0
        AND length(current_recipient_binding_digest_key_id) > 0
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_account_revision CHECK (
        manifest_revision >= 1
    )
);

CREATE TABLE infra.iam_sandbox_bootstrap_runs (
    command_id uuid NOT NULL,
    bootstrap_id uuid NOT NULL,
    manifest_sha256 bytea NOT NULL,
    revision integer NOT NULL,
    action text NOT NULL,
    outcome text NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT pk_iam_sandbox_bootstrap_runs PRIMARY KEY (command_id),
    CONSTRAINT fk_iam_sandbox_bootstrap_run_state FOREIGN KEY (bootstrap_id)
        REFERENCES infra.iam_sandbox_bootstrap_state (bootstrap_id)
        ON DELETE RESTRICT,
    CONSTRAINT uq_iam_sandbox_bootstrap_run UNIQUE (
        bootstrap_id,
        revision,
        action
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_run_digest CHECK (
        octet_length(manifest_sha256) = 32
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_run_action CHECK (
        action IN ('APPLY', 'REVOKE_ACCESS')
    ),
    CONSTRAINT ck_iam_sandbox_bootstrap_run_outcome CHECK (
        outcome IN ('APPLIED', 'ROTATED', 'REVOKED')
    )
);

ALTER TABLE infra.iam_sandbox_bootstrap_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_sandbox_bootstrap_state FORCE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_sandbox_bootstrap_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_sandbox_bootstrap_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_sandbox_bootstrap_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_sandbox_bootstrap_runs FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE infra.iam_sandbox_bootstrap_state FROM PUBLIC;
REVOKE ALL ON TABLE infra.iam_sandbox_bootstrap_accounts FROM PUBLIC;
REVOKE ALL ON TABLE infra.iam_sandbox_bootstrap_runs FROM PUBLIC;

CREATE FUNCTION iam.internal_sandbox_bootstrap_context_v1()
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT session_user = 'iam_sandbox_bootstrap'
       AND current_user = 'schema_owner'
       AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'INTERNAL_SANDBOX'
       AND NULLIF(current_setting('app.operation', true), '') = ANY (
            ARRAY['APPLY', 'VERIFY', 'REVOKE_ACCESS']
       )
       AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
       AND NULLIF(current_setting('app.manifest_sha256', true), '')
            ~ '^[0-9a-f]{64}$'
$function$;

REVOKE ALL ON FUNCTION iam.internal_sandbox_bootstrap_context_v1() FROM PUBLIC;

CREATE FUNCTION iam.sandbox_jsonb_has_exact_keys_v1(
    candidate jsonb,
    expected_keys text[]
)
RETURNS boolean
LANGUAGE sql
SECURITY INVOKER
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_typeof(candidate) = 'object'
       AND (
            SELECT pg_catalog.array_agg(item ORDER BY item)
            FROM pg_catalog.jsonb_object_keys(candidate) AS item
       ) = (
            SELECT pg_catalog.array_agg(item ORDER BY item)
            FROM pg_catalog.unnest(expected_keys) AS item
       )
$function$;

REVOKE ALL ON FUNCTION iam.sandbox_jsonb_has_exact_keys_v1(jsonb, text[])
FROM PUBLIC;

-- The definer program is the only executable path.  These policies grant its
-- owner access only while the exact temporary LOGIN role and closed action
-- context are both present.
CREATE POLICY rls_sandbox_bootstrap_policy_selectors
ON iam.policy_selectors FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_policy_documents
ON iam.policy_documents FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_policy_bundles
ON iam.policy_bundles FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_policy_bundle_documents
ON iam.policy_bundle_documents FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_users
ON iam.users FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_external_identities
ON iam.external_identities FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_contact_points
ON iam.contact_points FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_organizations
ON iam.organizations FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_access_invitations
ON iam.access_invitations FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_memberships
ON iam.memberships FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_user_role_grants
ON iam.user_role_grants FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_membership_role_grants
ON iam.membership_role_grants FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_platform_duty_grants
ON iam.platform_duty_grants FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_session_families
ON iam.session_families FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_sessions
ON iam.sessions FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_receipts
ON infra.command_receipts FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_audit
ON audit.audit_events FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_outbox
ON infra.outbox_events FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_state
ON infra.iam_sandbox_bootstrap_state FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_accounts
ON infra.iam_sandbox_bootstrap_accounts FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());
CREATE POLICY rls_sandbox_bootstrap_runs
ON infra.iam_sandbox_bootstrap_runs FOR ALL TO schema_owner
USING (iam.internal_sandbox_bootstrap_context_v1())
WITH CHECK (iam.internal_sandbox_bootstrap_context_v1());

CREATE FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v1(
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
    fixed_policy_body constant text :=
        'INTERNAL SANDBOX SYNTHETIC ACCOUNT USE ONLY. NO HUMAN DATA.';
    fixed_jurisdiction constant text := 'ZZ_INTERNAL';
    fixed_locale constant text := 'en';
    root_keys constant text[] := ARRAY[
        'accounts', 'bootstrap_id', 'environment_id', 'issuer', 'policy',
        'previous_manifest_sha256', 'revision', 'schema_name'
    ];
    account_keys constant text[] := ARRAY[
        'account_code', 'activation_event_id', 'contact_point',
        'creator_grant', 'demand_owner_grant', 'external_identity',
        'platform_duty_grants', 'revocation_event_id', 'user_id'
    ];
    manifest_document jsonb;
    accounts_document jsonb;
    policy_document jsonb;
    account_document jsonb;
    external_document jsonb;
    contact_document jsonb;
    creator_document jsonb;
    demand_document jsonb;
    duty_document jsonb;
    state_row infra.iam_sandbox_bootstrap_state%ROWTYPE;
    account_state infra.iam_sandbox_bootstrap_accounts%ROWTYPE;
    manifest_revision integer;
    manifest_account_count integer;
    manifest_issuer text;
    previous_manifest_digest bytea;
    creator_selector_digest bytea;
    owner_selector_digest bytea;
    fixed_document_digest bytea;
    fixed_document_id uuid;
    creator_bundle_id uuid;
    owner_bundle_id uuid;
    manifest_account_code text;
    account_user_id uuid;
    identity_id uuid;
    identity_digest bytea;
    identity_key_id text;
    contact_id uuid;
    contact_digest bytea;
    contact_key_id text;
    activation_event_id uuid;
    revocation_event_id uuid;
    creator_invitation_id uuid;
    creator_grant_id uuid;
    manifest_organization_id uuid;
    manifest_owner_invitation_id uuid;
    manifest_membership_id uuid;
    manifest_owner_grant_id uuid;
    manifest_duty_grant_id uuid;
    manifest_duty_code text;
    authority_shape_digest bytea;
    command_name text;
    action_outcome text;
    before_revision integer;
    rotated boolean;
    rotated_count integer := 0;
    current_user_version bigint;
    current_invitation_id uuid;
    current_organization_id uuid;
    affected integer;
BEGIN
    IF exact_action NOT IN ('APPLY', 'VERIFY', 'REVOKE_ACCESS')
       OR exact_canonical_manifest IS NULL
       OR octet_length(exact_canonical_manifest) NOT BETWEEN 1 AND 131072
       OR exact_manifest_sha256 IS NULL
       OR octet_length(exact_manifest_sha256) <> 32
       OR pg_catalog.sha256(exact_canonical_manifest) <> exact_manifest_sha256
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
            IS DISTINCT FROM pg_catalog.encode(exact_manifest_sha256, 'hex') THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_invocation',
            MESSAGE = 'internal sandbox bootstrap invocation is invalid';
    END IF;

    BEGIN
        manifest_document := pg_catalog.convert_from(
            exact_canonical_manifest,
            'UTF8'
        )::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_manifest',
            MESSAGE = 'internal sandbox bootstrap manifest is invalid';
    END;

    IF NOT iam.sandbox_jsonb_has_exact_keys_v1(manifest_document, root_keys)
       OR manifest_document->>'schema_name'
            <> 'desire-internal-sandbox-identity-bootstrap-v1'
       OR manifest_document->>'environment_id' <> 'internal-sandbox'
       OR manifest_document->>'bootstrap_id' <> exact_bootstrap_id::text
       OR pg_catalog.jsonb_typeof(manifest_document->'revision') <> 'number'
       OR pg_catalog.jsonb_typeof(manifest_document->'accounts') <> 'array'
       OR pg_catalog.jsonb_typeof(manifest_document->'policy') <> 'object'
       OR manifest_document->>'issuer' !~ '^https://[^/@?#]+(?:/[^?#]*)?$'
       OR right(manifest_document->>'issuer', 1) = '/' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_manifest',
            MESSAGE = 'internal sandbox bootstrap manifest is invalid';
    END IF;

    manifest_revision := (manifest_document->>'revision')::integer;
    accounts_document := manifest_document->'accounts';
    policy_document := manifest_document->'policy';
    manifest_account_count := pg_catalog.jsonb_array_length(accounts_document);
    manifest_issuer := manifest_document->>'issuer';
    IF manifest_revision < 1
       OR manifest_account_count NOT BETWEEN 2 AND 16
       OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
            policy_document,
            ARRAY['creator_bundle_id', 'demand_owner_bundle_id', 'document_id']
       )
       OR (
            manifest_revision = 1
            AND pg_catalog.jsonb_typeof(
                manifest_document->'previous_manifest_sha256'
            ) <> 'null'
       )
       OR (
            manifest_revision > 1
            AND coalesce(
                manifest_document->>'previous_manifest_sha256',
                ''
            ) !~ '^[0-9a-f]{64}$'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_manifest',
            MESSAGE = 'internal sandbox bootstrap manifest is invalid';
    END IF;
    previous_manifest_digest := CASE
        WHEN manifest_revision = 1 THEN NULL
        ELSE pg_catalog.decode(
            manifest_document->>'previous_manifest_sha256',
            'hex'
        )
    END;

    BEGIN
        fixed_document_id := (policy_document->>'document_id')::uuid;
        creator_bundle_id := (policy_document->>'creator_bundle_id')::uuid;
        owner_bundle_id := (policy_document->>'demand_owner_bundle_id')::uuid;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_manifest',
            MESSAGE = 'internal sandbox bootstrap manifest is invalid';
    END;
    IF fixed_document_id = zero_uuid
       OR creator_bundle_id = zero_uuid
       OR owner_bundle_id = zero_uuid
       OR fixed_document_id = creator_bundle_id
       OR fixed_document_id = owner_bundle_id
       OR creator_bundle_id = owner_bundle_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_identifiers',
            MESSAGE = 'internal sandbox bootstrap identifiers are invalid';
    END IF;

    creator_selector_digest := pg_catalog.sha256(pg_catalog.convert_to(
        '{"access_purpose":"CREATOR_ENROLLMENT","scope_type":"USER_ROLE",'
        '"target_role":"CREATOR","jurisdiction":"ZZ_INTERNAL","locale":"en"}',
        'UTF8'
    ));
    owner_selector_digest := pg_catalog.sha256(pg_catalog.convert_to(
        '{"access_purpose":"ORGANIZATION_MEMBERSHIP",'
        '"scope_type":"ORGANIZATION_ROLE","target_role":"DEMAND_OWNER",'
        '"jurisdiction":"ZZ_INTERNAL","locale":"en"}',
        'UTF8'
    ));
    fixed_document_digest := pg_catalog.sha256(
        pg_catalog.convert_to(fixed_policy_body, 'UTF8')
    );

    -- Validate the closed account surface before taking any domain lock/write.
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
        WHERE NOT iam.sandbox_jsonb_has_exact_keys_v1(item.value, account_keys)
           OR item.value->>'account_code' !~ '^[a-z][a-z0-9_]{2,31}$'
           OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
                item.value->'external_identity',
                ARRAY['id', 'subject_digest_key_id', 'subject_digest_sha256']
           )
           OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
                item.value->'contact_point',
                ARRAY[
                    'id', 'recipient_binding_digest_key_id',
                    'recipient_binding_digest_sha256'
                ]
           )
           OR NOT iam.sandbox_jsonb_has_exact_keys_v1(
                item.value->'creator_grant',
                ARRAY['grant_id', 'invitation_id']
           )
           OR pg_catalog.jsonb_typeof(item.value->'platform_duty_grants')
                <> 'array'
           OR pg_catalog.jsonb_array_length(item.value->'platform_duty_grants') > 2
           OR coalesce(item.value#>>'{external_identity,subject_digest_sha256}', '')
                !~ '^[0-9a-f]{64}$'
           OR coalesce(item.value#>>'{contact_point,recipient_binding_digest_sha256}', '')
                !~ '^[0-9a-f]{64}$'
           OR coalesce(item.value#>>'{external_identity,subject_digest_key_id}', '')
                !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'
           OR coalesce(item.value#>>'{contact_point,recipient_binding_digest_key_id}', '')
                !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'
           OR (
                pg_catalog.jsonb_typeof(item.value->'demand_owner_grant')
                    <> 'null'
                AND NOT iam.sandbox_jsonb_has_exact_keys_v1(
                    item.value->'demand_owner_grant',
                    ARRAY[
                        'grant_id', 'invitation_id', 'membership_id',
                        'organization_id'
                    ]
                )
           )
           OR EXISTS (
                SELECT 1
                FROM pg_catalog.jsonb_array_elements(
                    item.value->'platform_duty_grants'
                ) AS duty(value)
                WHERE NOT iam.sandbox_jsonb_has_exact_keys_v1(
                        duty.value,
                        ARRAY['duty_code', 'grant_id']
                      )
                   OR duty.value->>'duty_code' NOT IN (
                        'ACCESS_ADMIN', 'OPERATIONS_REVIEWER'
                   )
           )
    ) OR (
        SELECT count(DISTINCT item.value->>'account_code')
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
    ) <> manifest_account_count OR (
        SELECT count(DISTINCT (
            item.value#>>'{external_identity,subject_digest_sha256}'
        ))
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
    ) <> manifest_account_count OR (
        SELECT count(DISTINCT (
            (item.value #>> '{contact_point,recipient_binding_digest_key_id}')
            || ':' ||
            (item.value #>> '{contact_point,recipient_binding_digest_sha256}')
        ))
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
    ) <> manifest_account_count OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
        WHERE pg_catalog.jsonb_typeof(item.value->'demand_owner_grant') = 'object'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
        CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(
            item.value->'platform_duty_grants'
        ) AS duty(value)
        WHERE duty.value->>'duty_code' = 'ACCESS_ADMIN'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
        CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(
            item.value->'platform_duty_grants'
        ) AS duty(value)
        WHERE duty.value->>'duty_code' = 'OPERATIONS_REVIEWER'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_accounts',
            MESSAGE = 'internal sandbox bootstrap accounts are invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(1229016369, 23);
    SELECT * INTO state_row
    FROM infra.iam_sandbox_bootstrap_state AS state
    WHERE state.bootstrap_id = exact_bootstrap_id
    FOR UPDATE;

    IF FOUND AND state_row.status = 'REVOKED' THEN
        IF state_row.manifest_sha256 = exact_manifest_sha256
           AND state_row.revision = manifest_revision
           AND state_row.issuer = manifest_issuer
           AND state_row.account_count = manifest_account_count
           AND exact_action IN ('VERIFY', 'REVOKE_ACCESS') THEN
            RETURN QUERY SELECT
                'ALREADY_REVOKED'::text,
                manifest_revision,
                manifest_account_count;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_revoked',
            MESSAGE = 'internal sandbox bootstrap was revoked';
    END IF;

    IF FOUND
       AND state_row.manifest_sha256 = exact_manifest_sha256
       AND state_row.revision = manifest_revision
       AND state_row.issuer = manifest_issuer
       AND state_row.account_count = manifest_account_count
       AND exact_action = 'APPLY' THEN
        action_outcome := 'REPLAYED';
    ELSIF exact_action = 'APPLY' AND NOT FOUND THEN
        IF manifest_revision <> 1 OR previous_manifest_digest IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_bootstrap_revision',
                MESSAGE = 'internal sandbox bootstrap revision is invalid';
        END IF;
        action_outcome := 'APPLIED';
        before_revision := NULL;
    ELSIF exact_action = 'APPLY' THEN
        IF state_row.status <> 'ACTIVE'
           OR manifest_revision <> state_row.revision + 1
           OR previous_manifest_digest <> state_row.manifest_sha256
           OR manifest_issuer <> state_row.issuer
           OR manifest_account_count <> state_row.account_count
           OR (
                SELECT count(*)
                FROM infra.iam_sandbox_bootstrap_accounts AS existing_account
                WHERE existing_account.bootstrap_id = exact_bootstrap_id
                  AND NOT EXISTS (
                      SELECT 1
                      FROM pg_catalog.jsonb_array_elements(
                          accounts_document
                      ) AS item(value)
                      WHERE item.value->>'account_code'
                          = existing_account.account_code
                  )
           ) <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_bootstrap_revision',
                MESSAGE = 'internal sandbox bootstrap revision is invalid';
        END IF;
        action_outcome := 'ROTATED';
        before_revision := state_row.revision;
    ELSIF NOT FOUND
       OR state_row.manifest_sha256 <> exact_manifest_sha256
       OR state_row.revision <> manifest_revision
       OR state_row.issuer <> manifest_issuer
       OR state_row.account_count <> manifest_account_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            CONSTRAINT = 'ck_internal_sandbox_bootstrap_state',
            MESSAGE = 'internal sandbox bootstrap state is invalid';
    ELSE
        action_outcome := CASE
            WHEN exact_action = 'VERIFY' THEN 'VERIFIED'
            ELSE 'REVOKED'
        END;
        before_revision := state_row.revision;
    END IF;

    IF action_outcome = 'APPLIED' THEN
        INSERT INTO iam.policy_selectors (
            selector_digest, canonicalization_version, access_purpose,
            scope_type, target_role, jurisdiction, locale, current_bundle_id,
            aggregate_version, created_at, updated_at
        ) VALUES
        (
            creator_selector_digest, 'policy-selector-json-v1',
            'CREATOR_ENROLLMENT', 'USER_ROLE', 'CREATOR', fixed_jurisdiction,
            fixed_locale, NULL, 1, transaction_timestamp(),
            transaction_timestamp()
        ),
        (
            owner_selector_digest, 'policy-selector-json-v1',
            'ORGANIZATION_MEMBERSHIP', 'ORGANIZATION_ROLE', 'DEMAND_OWNER',
            fixed_jurisdiction, fixed_locale, NULL, 1,
            transaction_timestamp(), transaction_timestamp()
        );

        INSERT INTO iam.policy_documents (
            id, kind, locale, semantic_version, canonical_body,
            content_sha256, legal_effect, jurisdiction, status, effective_at,
            superseded_by_document_id, publication_command_id, created_at,
            updated_at
        ) VALUES (
            fixed_document_id, 'TERMS', fixed_locale,
            '1.0.0-internal-sandbox', fixed_policy_body,
            fixed_document_digest, 'NOTICE_ACKNOWLEDGEMENT',
            fixed_jurisdiction, 'ACTIVE', transaction_timestamp(), NULL,
            exact_command_id, transaction_timestamp(), transaction_timestamp()
        );

        INSERT INTO iam.policy_bundles (
            id, selector_digest, status, effective_at, effective_until,
            superseded_by_bundle_id, release_manifest_sha256,
            release_signature, release_signing_key_id,
            publication_command_id, aggregate_version, created_at, updated_at
        ) VALUES
        (
            creator_bundle_id, creator_selector_digest, 'DRAFT', NULL, NULL,
            NULL, exact_manifest_sha256, exact_manifest_sha256,
            'internal-sandbox-bootstrap-v1', exact_command_id, 1,
            transaction_timestamp(), transaction_timestamp()
        ),
        (
            owner_bundle_id, owner_selector_digest, 'DRAFT', NULL, NULL,
            NULL, exact_manifest_sha256, exact_manifest_sha256,
            'internal-sandbox-bootstrap-v1', exact_command_id, 1,
            transaction_timestamp(), transaction_timestamp()
        );
        INSERT INTO iam.policy_bundle_documents (
            bundle_id, document_id, position, required
        ) VALUES
            (creator_bundle_id, fixed_document_id, 1, true),
            (owner_bundle_id, fixed_document_id, 1, true);
        UPDATE iam.policy_bundles
        SET status = 'ACTIVE', effective_at = transaction_timestamp(),
            aggregate_version = 2, updated_at = transaction_timestamp()
        WHERE id IN (creator_bundle_id, owner_bundle_id);
        UPDATE iam.policy_selectors
        SET current_bundle_id = CASE
                WHEN selector_digest = creator_selector_digest
                    THEN creator_bundle_id
                ELSE owner_bundle_id
            END,
            aggregate_version = 2,
            updated_at = transaction_timestamp()
        WHERE selector_digest IN (
            creator_selector_digest,
            owner_selector_digest
        );

        INSERT INTO infra.iam_sandbox_bootstrap_state (
            bootstrap_id, manifest_sha256, revision, issuer, account_count,
            status, created_at, updated_at
        ) VALUES (
            exact_bootstrap_id, exact_manifest_sha256, manifest_revision,
            manifest_issuer, manifest_account_count, 'ACTIVE',
            transaction_timestamp(), transaction_timestamp()
        );
    ELSE
        IF NOT EXISTS (
            SELECT 1
            FROM iam.policy_documents AS document
            WHERE document.id = fixed_document_id
              AND document.kind = 'TERMS'
              AND document.locale = fixed_locale
              AND document.semantic_version = '1.0.0-internal-sandbox'
              AND document.canonical_body = fixed_policy_body
              AND document.content_sha256 = fixed_document_digest
              AND document.legal_effect = 'NOTICE_ACKNOWLEDGEMENT'
              AND document.jurisdiction = fixed_jurisdiction
              AND document.status = 'ACTIVE'
              AND document.effective_at IS NOT NULL
        ) OR NOT EXISTS (
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
            WHERE selector.selector_digest = creator_selector_digest
              AND selector.access_purpose = 'CREATOR_ENROLLMENT'
              AND selector.scope_type = 'USER_ROLE'
              AND selector.target_role = 'CREATOR'
              AND selector.jurisdiction = fixed_jurisdiction
              AND selector.locale = fixed_locale
              AND bundle.id = creator_bundle_id
              AND bundle.status = 'ACTIVE'
              AND bundle.effective_at <= transaction_timestamp()
              AND bundle.effective_until IS NULL
        ) OR NOT EXISTS (
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
            WHERE selector.selector_digest = owner_selector_digest
              AND selector.access_purpose = 'ORGANIZATION_MEMBERSHIP'
              AND selector.scope_type = 'ORGANIZATION_ROLE'
              AND selector.target_role = 'DEMAND_OWNER'
              AND selector.jurisdiction = fixed_jurisdiction
              AND selector.locale = fixed_locale
              AND bundle.id = owner_bundle_id
              AND bundle.status = 'ACTIVE'
              AND bundle.effective_at <= transaction_timestamp()
              AND bundle.effective_until IS NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_bootstrap_policy_graph',
                MESSAGE = 'internal sandbox bootstrap policy graph drifted';
        END IF;
    END IF;

    FOR account_document IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
        ORDER BY item.value->>'account_code'
    LOOP
        external_document := account_document->'external_identity';
        contact_document := account_document->'contact_point';
        creator_document := account_document->'creator_grant';
        demand_document := account_document->'demand_owner_grant';
        BEGIN
            manifest_account_code := account_document->>'account_code';
            account_user_id := (account_document->>'user_id')::uuid;
            identity_id := (external_document->>'id')::uuid;
            identity_digest := pg_catalog.decode(
                external_document->>'subject_digest_sha256', 'hex'
            );
            identity_key_id := external_document->>'subject_digest_key_id';
            contact_id := (contact_document->>'id')::uuid;
            contact_digest := pg_catalog.decode(
                contact_document->>'recipient_binding_digest_sha256', 'hex'
            );
            contact_key_id := contact_document->>'recipient_binding_digest_key_id';
            creator_invitation_id := (creator_document->>'invitation_id')::uuid;
            creator_grant_id := (creator_document->>'grant_id')::uuid;
            activation_event_id := (account_document->>'activation_event_id')::uuid;
            revocation_event_id := (account_document->>'revocation_event_id')::uuid;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                CONSTRAINT = 'ck_internal_sandbox_bootstrap_identifiers',
                MESSAGE = 'internal sandbox bootstrap identifiers are invalid';
        END;
        IF account_user_id = zero_uuid OR identity_id = zero_uuid
           OR contact_id = zero_uuid OR creator_invitation_id = zero_uuid
           OR creator_grant_id = zero_uuid OR activation_event_id = zero_uuid
           OR revocation_event_id = zero_uuid THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                CONSTRAINT = 'ck_internal_sandbox_bootstrap_identifiers',
                MESSAGE = 'internal sandbox bootstrap identifiers are invalid';
        END IF;

        authority_shape_digest := pg_catalog.sha256(pg_catalog.convert_to(
            (account_document - ARRAY[
                'activation_event_id', 'contact_point', 'external_identity',
                'revocation_event_id'
            ])::text,
            'UTF8'
        ));

        IF action_outcome = 'APPLIED' THEN
            INSERT INTO iam.users (
                id, status, display_handle, aggregate_version, created_at,
                updated_at
            ) VALUES (
                account_user_id, 'ACTIVE',
                'sandbox_' || manifest_account_code, 1,
                transaction_timestamp(), transaction_timestamp()
            );
            INSERT INTO iam.external_identities (
                id, user_id, issuer, subject_digest, subject_digest_key_id,
                verified_at, status, created_at
            ) VALUES (
                identity_id, account_user_id, manifest_issuer,
                identity_digest, identity_key_id, transaction_timestamp(),
                'ACTIVE', transaction_timestamp()
            );
            INSERT INTO iam.contact_points (
                id, user_id, contact_type, locator_ciphertext,
                locator_encryption_key_id, locator_encryption_algorithm,
                binding_digest, binding_digest_key_id, verified_at,
                retention_until, created_at, updated_at
            ) VALUES (
                contact_id, account_user_id, 'EMAIL', NULL, NULL, NULL,
                contact_digest, contact_key_id, transaction_timestamp(), NULL,
                transaction_timestamp(), transaction_timestamp()
            );
            INSERT INTO iam.access_invitations (
                id, purpose, organization_id, target_scope, target_role,
                is_initial_admin, recipient_contact_id, masked_recipient_label,
                policy_selector_digest, issued_policy_bundle_id, status,
                expires_at, issuer_kind, issuer_user_id, token_nonce,
                token_key_id, accepted_by_user_id, terminal_at,
                terminal_reason_code, aggregate_version, created_at, updated_at
            ) VALUES (
                creator_invitation_id, 'CREATOR_ENROLLMENT', NULL, 'USER',
                'CREATOR', false, contact_id, 'sandbox-account',
                creator_selector_digest, creator_bundle_id, 'ACCEPTED',
                transaction_timestamp() + interval '100 years', 'SYSTEM', NULL,
                pg_catalog.sha256(pg_catalog.convert_to(
                    'sandbox-bootstrap-invitation|' || creator_invitation_id::text,
                    'UTF8'
                )), 'internal-sandbox-bootstrap-v1', account_user_id,
                transaction_timestamp(), NULL, 2, transaction_timestamp(),
                transaction_timestamp()
            );
            INSERT INTO iam.user_role_grants (
                id, user_id, role_code, source_invitation_id,
                policy_selector_digest, granted_by_kind, granted_by_id,
                granted_at, revoked_at, revocation_reason_code,
                aggregate_version
            ) VALUES (
                creator_grant_id, account_user_id, 'CREATOR',
                creator_invitation_id, creator_selector_digest, 'SYSTEM',
                exact_system_actor_id, transaction_timestamp(), NULL, NULL, 1
            );

            IF pg_catalog.jsonb_typeof(demand_document) = 'object' THEN
                manifest_organization_id :=
                    (demand_document->>'organization_id')::uuid;
                manifest_owner_invitation_id :=
                    (demand_document->>'invitation_id')::uuid;
                manifest_membership_id :=
                    (demand_document->>'membership_id')::uuid;
                manifest_owner_grant_id :=
                    (demand_document->>'grant_id')::uuid;
                INSERT INTO iam.organizations (
                    id, organization_type, public_name, jurisdiction, status,
                    client_reference_namespace, client_reference,
                    aggregate_version, created_at, updated_at
                ) VALUES (
                    manifest_organization_id, 'BUSINESS',
                    'Sandbox Organization ' || manifest_account_code,
                    fixed_jurisdiction, 'ACTIVE',
                    'internal-sandbox-bootstrap', manifest_account_code, 2,
                    transaction_timestamp(), transaction_timestamp()
                );
                INSERT INTO iam.access_invitations (
                    id, purpose, organization_id, target_scope, target_role,
                    is_initial_admin, recipient_contact_id,
                    masked_recipient_label, policy_selector_digest,
                    issued_policy_bundle_id, status, expires_at, issuer_kind,
                    issuer_user_id, token_nonce, token_key_id,
                    accepted_by_user_id, terminal_at, terminal_reason_code,
                    aggregate_version, created_at, updated_at
                ) VALUES (
                    manifest_owner_invitation_id, 'ORGANIZATION_MEMBERSHIP',
                    manifest_organization_id, 'ORGANIZATION',
                    'DEMAND_OWNER', false,
                    contact_id, 'sandbox-account', owner_selector_digest,
                    owner_bundle_id, 'ACCEPTED',
                    transaction_timestamp() + interval '100 years',
                    'SYSTEM', NULL,
                    pg_catalog.sha256(pg_catalog.convert_to(
                        'sandbox-bootstrap-invitation|' ||
                            manifest_owner_invitation_id::text,
                        'UTF8'
                    )), 'internal-sandbox-bootstrap-v1', account_user_id,
                    transaction_timestamp(), NULL, 2,
                    transaction_timestamp(), transaction_timestamp()
                );
                INSERT INTO iam.memberships (
                    id, organization_id, user_id, status,
                    source_invitation_id, aggregate_version, created_at,
                    updated_at
                ) VALUES (
                    manifest_membership_id, manifest_organization_id,
                    account_user_id, 'ACTIVE',
                    manifest_owner_invitation_id, 1, transaction_timestamp(),
                    transaction_timestamp()
                );
                INSERT INTO iam.membership_role_grants (
                    id, organization_id, membership_id, user_id, role_code,
                    source_invitation_id, policy_selector_digest,
                    granted_by_kind, granted_by_id, granted_at, revoked_at,
                    revocation_reason_code, aggregate_version
                ) VALUES (
                    manifest_owner_grant_id, manifest_organization_id,
                    manifest_membership_id, account_user_id, 'DEMAND_OWNER',
                    manifest_owner_invitation_id,
                    owner_selector_digest, 'SYSTEM', exact_system_actor_id,
                    transaction_timestamp(), NULL, NULL, 1
                );
            END IF;

            FOR duty_document IN
                SELECT item.value
                FROM pg_catalog.jsonb_array_elements(
                    account_document->'platform_duty_grants'
                ) AS item(value)
                ORDER BY item.value->>'duty_code'
            LOOP
                manifest_duty_grant_id :=
                    (duty_document->>'grant_id')::uuid;
                manifest_duty_code := duty_document->>'duty_code';
                INSERT INTO iam.platform_duty_grants (
                    id, user_id, duty_code, granted_by_kind, granted_by_id,
                    granted_at, expires_at, revoked_at,
                    revocation_reason_code, aggregate_version, created_at,
                    updated_at
                ) VALUES (
                    manifest_duty_grant_id, account_user_id,
                    manifest_duty_code, 'SYSTEM',
                    exact_system_actor_id, transaction_timestamp(), NULL, NULL,
                    NULL, 1, transaction_timestamp(), transaction_timestamp()
                );
            END LOOP;

            INSERT INTO infra.iam_sandbox_bootstrap_accounts (
                bootstrap_id, account_code, user_id,
                current_external_identity_id, current_subject_digest,
                current_subject_digest_key_id, invitation_contact_point_id,
                current_contact_point_id, current_recipient_binding_digest,
                current_recipient_binding_digest_key_id, activation_event_id,
                revocation_event_id,
                authority_shape_sha256, manifest_revision, updated_at
            ) VALUES (
                exact_bootstrap_id, manifest_account_code, account_user_id,
                identity_id, identity_digest, identity_key_id, contact_id,
                contact_id, contact_digest, contact_key_id,
                activation_event_id, revocation_event_id,
                authority_shape_digest, manifest_revision,
                transaction_timestamp()
            );
        ELSE
            SELECT * INTO account_state
            FROM infra.iam_sandbox_bootstrap_accounts AS existing_account
            WHERE existing_account.bootstrap_id = exact_bootstrap_id
              AND existing_account.account_code = manifest_account_code
            FOR UPDATE;
            IF NOT FOUND
               OR account_state.user_id <> account_user_id
               OR account_state.authority_shape_sha256 <> authority_shape_digest
               OR (
                    action_outcome <> 'ROTATED'
                    AND (
                        account_state.current_external_identity_id <> identity_id
                        OR account_state.current_subject_digest <> identity_digest
                        OR account_state.current_subject_digest_key_id
                            <> identity_key_id
                        OR account_state.current_contact_point_id <> contact_id
                        OR account_state.current_recipient_binding_digest
                            <> contact_digest
                        OR account_state.current_recipient_binding_digest_key_id
                            <> contact_key_id
                    )
               )
               OR NOT EXISTS (
                    SELECT 1 FROM iam.users AS exact_user
                    WHERE exact_user.id = account_user_id
                      AND exact_user.status = 'ACTIVE'
                      AND exact_user.display_handle
                            = 'sandbox_' || manifest_account_code
               )
               OR NOT EXISTS (
                    SELECT 1
                    FROM iam.external_identities AS exact_identity
                    WHERE exact_identity.id
                            = account_state.current_external_identity_id
                      AND exact_identity.user_id = account_user_id
                      AND exact_identity.issuer = manifest_issuer
                      AND exact_identity.subject_digest
                            = account_state.current_subject_digest
                      AND exact_identity.subject_digest_key_id
                            = account_state.current_subject_digest_key_id
                      AND exact_identity.status = 'ACTIVE'
               )
               OR NOT EXISTS (
                    SELECT 1 FROM iam.contact_points AS exact_contact
                    WHERE exact_contact.id
                            = account_state.current_contact_point_id
                      AND exact_contact.user_id = account_user_id
                      AND exact_contact.contact_type = 'EMAIL'
                      AND exact_contact.locator_ciphertext IS NULL
                      AND exact_contact.binding_digest
                            = account_state.current_recipient_binding_digest
                      AND exact_contact.binding_digest_key_id
                            = account_state.current_recipient_binding_digest_key_id
               )
               OR NOT EXISTS (
                    SELECT 1
                    FROM iam.access_invitations AS invitation
                    JOIN iam.user_role_grants AS role_grant
                      ON role_grant.source_invitation_id = invitation.id
                    WHERE invitation.id = creator_invitation_id
                      AND invitation.status = 'ACCEPTED'
                      AND invitation.accepted_by_user_id = account_user_id
                      AND invitation.recipient_contact_id
                            = account_state.invitation_contact_point_id
                      AND invitation.policy_selector_digest
                            = creator_selector_digest
                      AND invitation.issued_policy_bundle_id = creator_bundle_id
                      AND role_grant.id = creator_grant_id
                      AND role_grant.user_id = account_user_id
                      AND role_grant.role_code = 'CREATOR'
                      AND role_grant.revoked_at IS NULL
               ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    CONSTRAINT = 'ck_internal_sandbox_bootstrap_graph',
                    MESSAGE = 'internal sandbox bootstrap graph drifted';
            END IF;

            IF pg_catalog.jsonb_typeof(demand_document) = 'object' THEN
                manifest_organization_id :=
                    (demand_document->>'organization_id')::uuid;
                manifest_owner_invitation_id :=
                    (demand_document->>'invitation_id')::uuid;
                manifest_membership_id :=
                    (demand_document->>'membership_id')::uuid;
                manifest_owner_grant_id :=
                    (demand_document->>'grant_id')::uuid;
                IF NOT EXISTS (
                    SELECT 1
                    FROM iam.organizations AS organization
                    JOIN iam.memberships AS membership
                      ON membership.organization_id = organization.id
                    JOIN iam.membership_role_grants AS owner_grant
                      ON owner_grant.organization_id = organization.id
                     AND owner_grant.membership_id = membership.id
                    JOIN iam.access_invitations AS invitation
                      ON invitation.id = owner_grant.source_invitation_id
                    WHERE organization.id = manifest_organization_id
                      AND organization.status = 'ACTIVE'
                      AND organization.public_name
                            = 'Sandbox Organization ' || manifest_account_code
                      AND membership.id = manifest_membership_id
                      AND membership.user_id = account_user_id
                      AND membership.status = 'ACTIVE'
                      AND owner_grant.id = manifest_owner_grant_id
                      AND owner_grant.user_id = account_user_id
                      AND owner_grant.role_code = 'DEMAND_OWNER'
                      AND owner_grant.revoked_at IS NULL
                      AND invitation.id = manifest_owner_invitation_id
                      AND invitation.status = 'ACCEPTED'
                      AND invitation.accepted_by_user_id = account_user_id
                      AND invitation.issued_policy_bundle_id = owner_bundle_id
                      AND invitation.recipient_contact_id
                            = account_state.invitation_contact_point_id
                ) THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '55000',
                        CONSTRAINT = 'ck_internal_sandbox_bootstrap_graph',
                        MESSAGE = 'internal sandbox bootstrap graph drifted';
                END IF;
            END IF;

            FOR duty_document IN
                SELECT item.value
                FROM pg_catalog.jsonb_array_elements(
                    account_document->'platform_duty_grants'
                ) AS item(value)
            LOOP
                manifest_duty_grant_id :=
                    (duty_document->>'grant_id')::uuid;
                manifest_duty_code := duty_document->>'duty_code';
                IF NOT EXISTS (
                    SELECT 1
                    FROM iam.platform_duty_grants AS duty
                    WHERE duty.id = manifest_duty_grant_id
                      AND duty.user_id = account_user_id
                      AND duty.duty_code = manifest_duty_code
                      AND duty.revoked_at IS NULL
                      AND (
                        duty.expires_at IS NULL
                        OR duty.expires_at > transaction_timestamp()
                      )
                ) THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '55000',
                        CONSTRAINT = 'ck_internal_sandbox_bootstrap_graph',
                        MESSAGE = 'internal sandbox bootstrap graph drifted';
                END IF;
            END LOOP;

            IF action_outcome = 'ROTATED' THEN
                rotated := identity_id
                        <> account_state.current_external_identity_id
                    OR contact_id <> account_state.current_contact_point_id;
                IF identity_id = account_state.current_external_identity_id THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM iam.external_identities AS exact_identity
                        WHERE exact_identity.id = identity_id
                          AND exact_identity.subject_digest = identity_digest
                          AND exact_identity.subject_digest_key_id = identity_key_id
                    ) THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '55000',
                            CONSTRAINT = 'ck_internal_sandbox_bootstrap_rotation',
                            MESSAGE = 'internal sandbox bootstrap rotation is invalid';
                    END IF;
                ELSE
                    UPDATE iam.external_identities
                    SET status = 'REVOKED'
                    WHERE id = account_state.current_external_identity_id
                      AND user_id = account_user_id
                      AND status = 'ACTIVE';
                    GET DIAGNOSTICS affected = ROW_COUNT;
                    IF affected <> 1 THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '55000',
                            CONSTRAINT = 'ck_internal_sandbox_bootstrap_rotation',
                            MESSAGE = 'internal sandbox bootstrap rotation is invalid';
                    END IF;
                    INSERT INTO iam.external_identities (
                        id, user_id, issuer, subject_digest,
                        subject_digest_key_id, verified_at, status, created_at
                    ) VALUES (
                        identity_id, account_user_id, manifest_issuer,
                        identity_digest, identity_key_id,
                        transaction_timestamp(), 'ACTIVE',
                        transaction_timestamp()
                    );
                END IF;
                IF contact_id = account_state.current_contact_point_id THEN
                    IF NOT EXISTS (
                        SELECT 1 FROM iam.contact_points AS exact_contact
                        WHERE exact_contact.id = contact_id
                          AND exact_contact.binding_digest = contact_digest
                          AND exact_contact.binding_digest_key_id = contact_key_id
                    ) THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '55000',
                            CONSTRAINT = 'ck_internal_sandbox_bootstrap_rotation',
                            MESSAGE = 'internal sandbox bootstrap rotation is invalid';
                    END IF;
                ELSE
                    INSERT INTO iam.contact_points (
                        id, user_id, contact_type, locator_ciphertext,
                        locator_encryption_key_id, locator_encryption_algorithm,
                        binding_digest, binding_digest_key_id, verified_at,
                        retention_until, created_at, updated_at
                    ) VALUES (
                        contact_id, account_user_id, 'EMAIL', NULL, NULL, NULL,
                        contact_digest, contact_key_id, transaction_timestamp(),
                        NULL, transaction_timestamp(), transaction_timestamp()
                    );
                END IF;
                IF rotated THEN
                    rotated_count := rotated_count + 1;
                END IF;
                UPDATE infra.iam_sandbox_bootstrap_accounts AS target_account
                SET current_external_identity_id = identity_id,
                    current_subject_digest = identity_digest,
                    current_subject_digest_key_id = identity_key_id,
                    current_contact_point_id = contact_id,
                    current_recipient_binding_digest = contact_digest,
                    current_recipient_binding_digest_key_id = contact_key_id,
                    activation_event_id =
                        (account_document->>'activation_event_id')::uuid,
                    revocation_event_id =
                        (account_document->>'revocation_event_id')::uuid,
                    manifest_revision =
                        (manifest_document->>'revision')::integer,
                    updated_at = transaction_timestamp()
                WHERE target_account.bootstrap_id = exact_bootstrap_id
                  AND target_account.account_code = manifest_account_code;
            END IF;
        END IF;
    END LOOP;

    IF action_outcome = 'REPLAYED' THEN
        RETURN QUERY SELECT action_outcome, manifest_revision,
            manifest_account_count;
        RETURN;
    END IF;

    IF action_outcome = 'VERIFIED' THEN
        RETURN QUERY SELECT action_outcome, manifest_revision,
            manifest_account_count;
        RETURN;
    END IF;

    IF action_outcome = 'ROTATED' THEN
        IF rotated_count < 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                CONSTRAINT = 'ck_internal_sandbox_bootstrap_rotation',
                MESSAGE = 'internal sandbox bootstrap rotation has no change';
        END IF;
        -- A subject/contact key rotation invalidates every extant Session for
        -- these synthetic users; it never creates a replacement Session.
        UPDATE iam.sessions AS session
        SET status = 'REVOKED', revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_IDENTITY_ROTATED',
            updated_at = transaction_timestamp(),
            aggregate_version = session.aggregate_version + 1
        WHERE session.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1
              FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = session.user_id
          );
        UPDATE iam.session_families AS family
        SET status = 'REVOKED', revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_IDENTITY_ROTATED',
            updated_at = transaction_timestamp(),
            aggregate_version = family.aggregate_version + 1
        WHERE family.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1
              FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = family.user_id
          );
        UPDATE infra.iam_sandbox_bootstrap_state
        SET manifest_sha256 = exact_manifest_sha256,
            revision = manifest_revision,
            updated_at = transaction_timestamp()
        WHERE bootstrap_id = exact_bootstrap_id;
    END IF;

    IF action_outcome = 'REVOKED' THEN
        -- Validate completed above, then close every bootstrap-created access
        -- edge and Session atomically.  Accepted invitations remain immutable
        -- terminal evidence and cannot be reused.
        UPDATE iam.sessions AS session
        SET status = 'REVOKED', revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ACCESS_REVOKED',
            updated_at = transaction_timestamp(),
            aggregate_version = session.aggregate_version + 1
        WHERE session.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = session.user_id
          );
        UPDATE iam.session_families AS family
        SET status = 'REVOKED', revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ACCESS_REVOKED',
            updated_at = transaction_timestamp(),
            aggregate_version = family.aggregate_version + 1
        WHERE family.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = family.user_id
          );
        UPDATE iam.external_identities AS identity
        SET status = 'REVOKED'
        WHERE identity.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = identity.user_id
          );
        UPDATE iam.user_role_grants AS role_grant
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ACCESS_REVOKED',
            aggregate_version = role_grant.aggregate_version + 1
        WHERE role_grant.revoked_at IS NULL
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = role_grant.user_id
          );
        UPDATE iam.membership_role_grants AS role_grant
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ACCESS_REVOKED',
            aggregate_version = role_grant.aggregate_version + 1
        WHERE role_grant.revoked_at IS NULL
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = role_grant.user_id
          );
        UPDATE iam.memberships AS membership
        SET status = 'REVOKED', updated_at = transaction_timestamp(),
            aggregate_version = membership.aggregate_version + 1
        WHERE membership.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = membership.user_id
          );
        UPDATE iam.platform_duty_grants AS duty
        SET revoked_at = transaction_timestamp(),
            revocation_reason_code = 'BOOTSTRAP_ACCESS_REVOKED',
            updated_at = transaction_timestamp(),
            aggregate_version = duty.aggregate_version + 1
        WHERE duty.revoked_at IS NULL
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = duty.user_id
          );
        UPDATE iam.users AS exact_user
        SET status = 'SUSPENDED', updated_at = transaction_timestamp(),
            aggregate_version = exact_user.aggregate_version + 1
        WHERE exact_user.status = 'ACTIVE'
          AND EXISTS (
              SELECT 1 FROM infra.iam_sandbox_bootstrap_accounts AS account
              WHERE account.bootstrap_id = exact_bootstrap_id
                AND account.user_id = exact_user.id
          );
        UPDATE infra.iam_sandbox_bootstrap_state
        SET status = 'REVOKED', updated_at = transaction_timestamp()
        WHERE bootstrap_id = exact_bootstrap_id;
    END IF;

    command_name := CASE exact_action
        WHEN 'APPLY' THEN 'ApplyInternalSandboxIdentityBootstrap'
        ELSE 'RevokeInternalSandboxIdentityBootstrapAccess'
    END;
    INSERT INTO infra.command_receipts (
        id, principal_kind, principal_id, command_name, command_version,
        idempotency_key_digest, idempotency_key_digest_key_id, payload_hash,
        payload_hash_key_id, canonicalization_version, target_kind, target_id,
        http_method, canonical_path, if_match_version, status,
        response_schema_version, safe_response_body, reconstruction_metadata,
        created_at, retain_until, completed_at
    ) VALUES (
        exact_receipt_id, 'SYSTEM', exact_system_actor_id, command_name, 1,
        pg_catalog.sha256(pg_catalog.convert_to(
            exact_action || '|' || pg_catalog.encode(exact_manifest_sha256, 'hex'),
            'UTF8'
        )), 'internal-sandbox-bootstrap-v1', exact_manifest_sha256,
        'internal-sandbox-bootstrap-v1', 'restricted-canonical-json-v1',
        'InternalSandboxIdentityBootstrap', exact_bootstrap_id, 'POST',
        '/v1/deployment/internal-sandbox/identity-bootstrap/' ||
            exact_bootstrap_id::text || '/' || lower(exact_action),
        before_revision, 'COMPLETED', 1,
        pg_catalog.jsonb_build_object(
            'account_count', manifest_account_count,
            'manifest_sha256', pg_catalog.encode(exact_manifest_sha256, 'hex'),
            'outcome', action_outcome,
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
        exact_system_actor_id, NULL, command_name,
        'InternalSandboxIdentityBootstrap', exact_bootstrap_id, NULL,
        CASE WHEN action_outcome = 'APPLIED' THEN NULL ELSE 'ACTIVE' END,
        CASE WHEN action_outcome = 'REVOKED' THEN 'REVOKED' ELSE 'ACTIVE' END,
        before_revision, manifest_revision, NULL, 'INTERNAL_SANDBOX',
        CASE
            WHEN action_outcome = 'ROTATED' THEN 'KEY_ROTATION'
            WHEN action_outcome = 'REVOKED' THEN 'DEPLOYMENT_REVOKE'
            ELSE 'DEPLOYMENT_BOOTSTRAP'
        END,
        NULL, 'SUCCEEDED', exact_command_id, exact_correlation_id,
        exact_command_id, exact_trace_id,
        pg_catalog.jsonb_build_object(
            'account_count', manifest_account_count,
            'manifest_sha256', pg_catalog.encode(exact_manifest_sha256, 'hex'),
            'revision', manifest_revision
        )
    );

    -- Use only already-published IAM v1 event types.  Every sandbox account is
    -- invitation-backed CREATOR, so initial activation is truthful; rotation
    -- and revoke emit the closed session/user lifecycle facts respectively.
    FOR account_document IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(accounts_document) AS item(value)
        ORDER BY item.value->>'account_code'
    LOOP
        account_user_id := (account_document->>'user_id')::uuid;
        creator_invitation_id :=
            (account_document#>>'{creator_grant,invitation_id}')::uuid;
        IF action_outcome = 'APPLIED' THEN
            activation_event_id :=
                (account_document->>'activation_event_id')::uuid;
            INSERT INTO infra.outbox_events (
                event_id, event_type, schema_version, occurred_at,
                aggregate_type, aggregate_id, aggregate_version, actor_kind,
                actor_id, original_actor_id, correlation_id, causation_id,
                trace_id, organization_id, payload, delivery_status,
                attempt_count, available_at, lease_owner, lease_until,
                published_at, last_error_code, created_at
            ) VALUES (
                activation_event_id, 'UserActivated', 1,
                transaction_timestamp(), 'User', account_user_id, 1, 'SYSTEM',
                exact_system_actor_id, NULL, exact_correlation_id,
                exact_command_id, exact_trace_id, NULL,
                pg_catalog.jsonb_build_object(
                    'user_id', account_user_id::text,
                    'status', 'ACTIVE',
                    'access_invitation_id', creator_invitation_id::text
                ), 'PENDING', 0, transaction_timestamp(), NULL, NULL, NULL,
                NULL, transaction_timestamp()
            );
        ELSIF action_outcome = 'ROTATED' THEN
            activation_event_id :=
                (account_document->>'activation_event_id')::uuid;
            INSERT INTO infra.outbox_events (
                event_id, event_type, schema_version, occurred_at,
                aggregate_type, aggregate_id, aggregate_version, actor_kind,
                actor_id, original_actor_id, correlation_id, causation_id,
                trace_id, organization_id, payload, delivery_status,
                attempt_count, available_at, lease_owner, lease_until,
                published_at, last_error_code, created_at
            ) VALUES (
                activation_event_id, 'SessionsRevoked', 1,
                transaction_timestamp(), 'User', account_user_id, 1,
                'SYSTEM', exact_system_actor_id, NULL, exact_correlation_id,
                exact_command_id, exact_trace_id, NULL,
                pg_catalog.jsonb_build_object(
                    'user_id', account_user_id::text,
                    'scope', 'ALL_ACTIVE_SESSION_FAMILIES'
                ), 'PENDING', 0, transaction_timestamp(), NULL, NULL, NULL,
                NULL, transaction_timestamp()
            );
        ELSE
            revocation_event_id :=
                (account_document->>'revocation_event_id')::uuid;
            SELECT exact_user.aggregate_version INTO current_user_version
            FROM iam.users AS exact_user
            WHERE exact_user.id = account_user_id;
            INSERT INTO infra.outbox_events (
                event_id, event_type, schema_version, occurred_at,
                aggregate_type, aggregate_id, aggregate_version, actor_kind,
                actor_id, original_actor_id, correlation_id, causation_id,
                trace_id, organization_id, payload, delivery_status,
                attempt_count, available_at, lease_owner, lease_until,
                published_at, last_error_code, created_at
            ) VALUES (
                revocation_event_id, 'UserSuspended', 1,
                transaction_timestamp(), 'User', account_user_id,
                current_user_version, 'SYSTEM', exact_system_actor_id, NULL,
                exact_correlation_id, exact_command_id, exact_trace_id, NULL,
                pg_catalog.jsonb_build_object(
                    'user_id', account_user_id::text,
                    'status', 'SUSPENDED'
                ), 'PENDING', 0, transaction_timestamp(), NULL, NULL, NULL,
                NULL, transaction_timestamp()
            );
        END IF;
    END LOOP;

    INSERT INTO infra.iam_sandbox_bootstrap_runs (
        command_id, bootstrap_id, manifest_sha256, revision, action, outcome,
        occurred_at
    ) VALUES (
        exact_command_id, exact_bootstrap_id, exact_manifest_sha256,
        manifest_revision, exact_action, action_outcome,
        transaction_timestamp()
    );

    RETURN QUERY SELECT action_outcome, manifest_revision,
        manifest_account_count;
END
$function$;

ALTER FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v1(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) OWNER TO schema_owner;
REVOKE ALL ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v1(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) FROM PUBLIC;
GRANT USAGE ON SCHEMA iam_api TO iam_sandbox_bootstrap;
GRANT EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v1(
    text, bytea, bytea, uuid, uuid, uuid, uuid, uuid, uuid, uuid
) TO iam_sandbox_bootstrap;

DO $assertions$
DECLARE
    relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'iam_sandbox_bootstrap_state',
        'iam_sandbox_bootstrap_accounts',
        'iam_sandbox_bootstrap_runs'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'infra'
              AND relation.relname = relation_name
              AND relation.relkind = 'r'
              AND relation.relrowsecurity
              AND relation.relforcerowsecurity
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'sandbox bootstrap RLS assertion failed';
        END IF;
    END LOOP;

    IF NOT pg_catalog.has_function_privilege(
        'iam_sandbox_bootstrap',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v1(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_app',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v1(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_onboarding',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v1(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'iam_system',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v1(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) OR pg_catalog.has_function_privilege(
        'public',
        'iam_api.manage_internal_sandbox_identity_bootstrap_v1(text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sandbox bootstrap EXECUTE assertion failed';
    END IF;

    IF pg_catalog.has_table_privilege(
        'iam_sandbox_bootstrap',
        'iam.users',
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) OR pg_catalog.has_table_privilege(
        'iam_sandbox_bootstrap',
        'iam.external_identities',
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) OR pg_catalog.has_table_privilege(
        'iam_sandbox_bootstrap',
        'infra.iam_sandbox_bootstrap_state',
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sandbox bootstrap direct table grant assertion failed';
    END IF;
END
$assertions$;
