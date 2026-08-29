DO $iam_contract_guard$
DECLARE
    relation_name text;
    missing_constraint text;
    expected_rls_count integer := 25;
    actual_rls_count integer;
BEGIN
    IF current_user <> 'schema_owner'
       OR current_setting('server_version_num')::integer / 10000 <> 18 THEN
        RAISE EXCEPTION USING
            ERRCODE = '0A000',
            CONSTRAINT = 'ck_iam_contract_execution_context',
            MESSAGE = 'IAM contract migration context is invalid';
    END IF;

    IF (
        SELECT count(*)
        FROM pg_catalog.pg_roles
        WHERE rolname = ANY (ARRAY[
            'schema_owner',
            'iam_migration_runner',
            'iam_app',
            'iam_session_authenticator',
            'iam_onboarding',
            'iam_system',
            'iam_self_summary_reader',
            'iam_outbox_worker',
            'iam_key_policy_operator',
            'audit_reader',
            'break_glass'
        ])
          AND NOT rolsuper
          AND NOT rolcreatedb
          AND NOT rolcreaterole
          AND NOT rolbypassrls
          AND NOT rolinherit
    ) <> 11 THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_contract_role_attributes',
            MESSAGE = 'IAM role attributes drifted';
    END IF;

    FOREACH relation_name IN ARRAY ARRAY[
        'infra.schema_migrations',
        'iam.policy_selectors',
        'iam.policy_documents',
        'iam.policy_bundles',
        'iam.policy_bundle_documents',
        'iam.consent_offers',
        'iam.consent_offer_data_categories',
        'iam.users',
        'iam.external_identities',
        'iam.contact_points',
        'iam.organizations',
        'iam.access_invitations',
        'iam.memberships',
        'iam.user_role_grants',
        'iam.membership_role_grants',
        'iam.auth_transactions',
        'iam.session_families',
        'iam.sessions',
        'iam.policy_acceptances',
        'iam.consent_grants',
        'iam.consent_grant_data_categories',
        'iam.consent_withdrawals',
        'infra.command_receipts',
        'infra.iam_receipt_key_policy',
        'audit.audit_events',
        'infra.outbox_events',
        'iam_api.resolve_cookie_session_v1',
        'iam_api.invitation_public_preview_v1',
        'iam_api.public_policy_documents_v1',
        'iam_api.public_consent_offers_v1',
        'iam_api.acceptance_me_snapshot'
    ]
    LOOP
        IF pg_catalog.to_regclass(relation_name) IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '42P01',
                CONSTRAINT = 'ck_iam_contract_required_relation',
                MESSAGE = 'required IAM relation is unavailable';
        END IF;
    END LOOP;

    SELECT count(*) INTO actual_rls_count
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE (namespace.nspname, relation.relname) IN (
        ('iam', 'policy_selectors'),
        ('iam', 'policy_documents'),
        ('iam', 'policy_bundles'),
        ('iam', 'policy_bundle_documents'),
        ('iam', 'consent_offers'),
        ('iam', 'consent_offer_data_categories'),
        ('iam', 'users'),
        ('iam', 'external_identities'),
        ('iam', 'contact_points'),
        ('iam', 'organizations'),
        ('iam', 'access_invitations'),
        ('iam', 'memberships'),
        ('iam', 'user_role_grants'),
        ('iam', 'membership_role_grants'),
        ('iam', 'auth_transactions'),
        ('iam', 'session_families'),
        ('iam', 'sessions'),
        ('iam', 'policy_acceptances'),
        ('iam', 'consent_grants'),
        ('iam', 'consent_grant_data_categories'),
        ('iam', 'consent_withdrawals'),
        ('infra', 'command_receipts'),
        ('infra', 'iam_receipt_key_policy'),
        ('audit', 'audit_events'),
        ('infra', 'outbox_events')
    )
      AND relation.relrowsecurity
      AND relation.relforcerowsecurity;

    IF actual_rls_count <> expected_rls_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_contract_force_rls',
            MESSAGE = 'IAM FORCE RLS contract is incomplete';
    END IF;

    IF (
        SELECT count(*)
        FROM pg_catalog.pg_trigger AS trigger_row
        WHERE NOT trigger_row.tgisinternal
          AND trigger_row.tgname IN (
              'trg_policy_publication_consistent',
              'trg_activation_matches_accepted_invitation',
              'trg_evidence_matches_session_auth',
              'trg_consent_grant_matches_offer',
              'trg_session_family_consistent',
              'trg_receipt_completed_at_commit'
          )
          AND trigger_row.tgconstraint <> 0
          AND trigger_row.tgdeferrable
          AND trigger_row.tginitdeferred
    ) <> 16 THEN
        RAISE EXCEPTION USING
            ERRCODE = '42704',
            CONSTRAINT = 'ck_iam_contract_deferred_triggers',
            MESSAGE = 'deferred IAM constraint trigger contract is incomplete';
    END IF;

    SELECT required_item.name INTO missing_constraint
    FROM unnest(ARRAY[
        'uq_policy_selector_facts',
        'ux_policy_bundle_active_selector',
        'fk_invitation_issued_bundle_selector',
        'ck_invitation_target_shape',
        'uq_user_role_source_invitation',
        'uq_membership_role_source_invitation',
        'fk_user_role_grant_source',
        'fk_membership_role_source',
        'uq_session_family_generation',
        'uq_session_predecessor',
        'ux_session_one_active_family',
        'ux_consent_grant_active_authority',
        'uq_command_receipt_identity',
        'uq_outbox_command_event'
    ]) AS required_item(name)
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint AS constraint_row
        WHERE constraint_row.conname = required_item.name
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS index_row
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = index_row.relnamespace
        WHERE index_row.relkind = 'i'
          AND index_row.relname = required_item.name
          AND namespace.nspname IN ('iam', 'infra')
    )
    LIMIT 1;

    IF missing_constraint IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42704',
            CONSTRAINT = 'ck_iam_contract_required_constraint',
            MESSAGE = 'required IAM constraint is unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_index AS index_row
        JOIN pg_catalog.pg_class AS index_relation
          ON index_relation.oid = index_row.indexrelid
        WHERE index_relation.relname = 'ux_consent_grant_active_authority'
          AND index_row.indisunique
          AND index_row.indnullsnotdistinct
          AND index_row.indpred IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42704',
            CONSTRAINT = 'ck_iam_contract_consent_authority',
            MESSAGE = 'consent authority uniqueness is unavailable';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid IN (
            'iam.user_role_grants'::pg_catalog.regclass,
            'iam.membership_role_grants'::pg_catalog.regclass,
            'iam.access_invitations'::pg_catalog.regclass
        )
          AND attribute.attname = 'policy_selector_digest'
          AND NOT attribute.attnotnull
    ) OR (
        SELECT count(*)
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid IN (
            'iam.user_role_grants'::pg_catalog.regclass,
            'iam.membership_role_grants'::pg_catalog.regclass,
            'iam.access_invitations'::pg_catalog.regclass
        )
          AND attribute.attname = 'policy_selector_digest'
          AND attribute.attnotnull
          AND NOT attribute.attisdropped
    ) <> 3 THEN
        RAISE EXCEPTION USING
            ERRCODE = '42703',
            CONSTRAINT = 'ck_iam_contract_stored_selector',
            MESSAGE = 'stored policy selector columns are incomplete';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = procedure.proowner
        WHERE namespace.nspname = 'iam_api'
          AND procedure.proname = 'read_me_self_summary'
          AND procedure.pronargs = 0
          AND procedure.prosecdef
          AND procedure.provolatile = 's'
          AND procedure.proparallel = 'r'
          AND owner_role.rolname = 'iam_self_summary_reader'
          AND EXISTS (
              SELECT 1
              FROM unnest(procedure.proconfig) AS configuration(setting)
              WHERE replace(configuration.setting, ' ', '')
                    = 'search_path=pg_catalog,iam,pg_temp'
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42883',
            CONSTRAINT = 'ck_iam_contract_self_summary_function',
            MESSAGE = 'self summary function contract is invalid';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = procedure.proowner
        WHERE namespace.nspname = 'infra'
          AND procedure.proname = 'enforce_receipt_key_policy_retention'
          AND procedure.pronargs = 0
          AND procedure.prosecdef
          AND owner_role.rolname = 'schema_owner'
          AND EXISTS (
              SELECT 1
              FROM unnest(procedure.proconfig) AS configuration(setting)
              WHERE replace(configuration.setting, ' ', '')
                    = 'search_path=pg_catalog,infra'
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42883',
            CONSTRAINT = 'ck_iam_contract_key_retention_function',
            MESSAGE = 'receipt key retention function contract is invalid';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = procedure.proowner
        WHERE procedure.oid = 'iam.replayed_session_matches_family(uuid)'::pg_catalog.regprocedure
          AND procedure.prorettype = 'boolean'::pg_catalog.regtype
          AND procedure.prosecdef
          AND procedure.provolatile = 's'
          AND procedure.proparallel = 'r'
          AND owner_role.rolname = 'schema_owner'
          AND EXISTS (
              SELECT 1
              FROM unnest(procedure.proconfig) AS configuration(setting)
              WHERE replace(configuration.setting, ' ', '')
                    = 'search_path=pg_catalog,iam'
          )
          AND pg_catalog.has_function_privilege(
              'iam_session_authenticator',
              procedure.oid,
              'EXECUTE'
          )
          AND NOT pg_catalog.has_function_privilege(
              'public',
              procedure.oid,
              'EXECUTE'
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42883',
            CONSTRAINT = 'ck_iam_contract_replay_validator_function',
            MESSAGE = 'session replay validator function contract is invalid';
    END IF;

    IF (
        SELECT count(*)
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'iam_api'
          AND relation.relname IN (
              'resolve_cookie_session_v1',
              'invitation_public_preview_v1',
              'public_policy_documents_v1',
              'public_consent_offers_v1',
              'acceptance_me_snapshot'
          )
          AND relation.relkind = 'v'
          AND relation.reloptions @> ARRAY['security_barrier=true', 'security_invoker=true']
    ) <> 5 THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_contract_safe_views',
            MESSAGE = 'IAM safe view attributes are incomplete';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname IN ('iam', 'iam_api', 'infra', 'audit')
          AND procedure.prosecdef
          AND NOT (
              (namespace.nspname = 'iam_api' AND procedure.proname = 'read_me_self_summary')
              OR procedure.oid
                  = 'iam.replayed_session_matches_family(uuid)'::pg_catalog.regprocedure
              OR (
                  namespace.nspname = 'infra'
                  AND procedure.proname = 'enforce_receipt_key_policy_retention'
              )
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_contract_security_definer_allowlist',
            MESSAGE = 'unexpected SECURITY DEFINER function exists';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation.relowner
        WHERE namespace.nspname IN ('iam', 'iam_api', 'infra', 'audit')
          AND owner_role.rolname IN (
              'iam_app',
              'iam_session_authenticator',
              'iam_onboarding',
              'iam_system',
              'iam_outbox_worker',
              'iam_key_policy_operator'
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_contract_online_owner',
            MESSAGE = 'online role owns an IAM relation';
    END IF;
END
$iam_contract_guard$;

CREATE TABLE infra.iam_schema_contracts (
    component varchar(64) NOT NULL,
    schema_head_version integer NOT NULL,
    min_app_compatible_version integer NOT NULL,
    max_app_compatible_version integer NOT NULL,
    api_contract_sha256 bytea NOT NULL,
    event_contract_sha256 bytea NOT NULL,
    migration_manifest_sha256 bytea NOT NULL,
    combined_contract_sha256 bytea NOT NULL,
    generated_at timestamptz NOT NULL,
    CONSTRAINT pk_iam_schema_contracts PRIMARY KEY (component),
    CONSTRAINT ck_iam_schema_contract_component CHECK (component = 'iam'),
    CONSTRAINT ck_iam_schema_contract_version_range CHECK (
        0 <= min_app_compatible_version
        AND min_app_compatible_version <= schema_head_version
        AND schema_head_version <= max_app_compatible_version
    ),
    CONSTRAINT ck_iam_schema_contract_hashes CHECK (
        octet_length(api_contract_sha256) = 32
        AND octet_length(event_contract_sha256) = 32
        AND octet_length(migration_manifest_sha256) = 32
        AND octet_length(combined_contract_sha256) = 32
    )
);

REVOKE ALL ON TABLE infra.iam_schema_contracts FROM PUBLIC;
REVOKE ALL ON TABLE infra.iam_schema_contracts FROM
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system;

CREATE VIEW infra.iam_schema_compatibility
WITH (security_barrier = true)
AS
SELECT
    contract.component,
    (
        SELECT max(migration.version)
        FROM infra.schema_migrations AS migration
        WHERE migration.component = contract.component
    ) AS current_schema_version,
    contract.schema_head_version,
    contract.min_app_compatible_version,
    contract.max_app_compatible_version,
    contract.combined_contract_sha256
FROM infra.iam_schema_contracts AS contract
WHERE contract.component = 'iam';

REVOKE ALL ON TABLE infra.iam_schema_compatibility FROM PUBLIC;
GRANT SELECT ON infra.iam_schema_compatibility TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system;
