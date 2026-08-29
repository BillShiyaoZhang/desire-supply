DO $iam_role_guard$
DECLARE
    expected record;
    actual record;
BEGIN
    IF current_setting('server_version_num')::integer / 10000 <> 18 THEN
        RAISE EXCEPTION USING
            ERRCODE = '0A000',
            CONSTRAINT = 'ck_iam_postgres_major',
            MESSAGE = 'unsupported PostgreSQL major';
    END IF;

    FOR expected IN
        SELECT *
        FROM (VALUES
            ('schema_owner', false, false),
            ('iam_migration_runner', true, false),
            ('iam_app', true, false),
            ('iam_session_authenticator', true, false),
            ('iam_onboarding', true, false),
            ('iam_system', true, false),
            ('iam_self_summary_reader', false, false),
            ('iam_outbox_worker', true, false),
            ('iam_key_policy_operator', false, false),
            ('audit_reader', false, false),
            ('break_glass', false, false)
        ) AS required(role_name, expected_login, expected_inherit)
    LOOP
        SELECT
            rolcanlogin,
            rolinherit,
            rolsuper,
            rolcreatedb,
            rolcreaterole,
            rolbypassrls
        INTO actual
        FROM pg_catalog.pg_roles
        WHERE rolname = expected.role_name;

        IF NOT FOUND
           OR actual.rolcanlogin IS DISTINCT FROM expected.expected_login
           OR actual.rolinherit IS DISTINCT FROM expected.expected_inherit
           OR actual.rolsuper
           OR actual.rolcreatedb
           OR actual.rolcreaterole
           OR actual.rolbypassrls THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                CONSTRAINT = 'ck_iam_role_attributes',
                MESSAGE = 'IAM database role attributes are not provisioned';
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS granted_role
          ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS member_role
          ON member_role.oid = membership.member
        WHERE granted_role.rolname = 'schema_owner'
          AND member_role.rolname = 'iam_migration_runner'
          AND membership.inherit_option = false
          AND membership.set_option = true
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_migration_membership',
            MESSAGE = 'migration role membership is not provisioned';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS granted_role
          ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS member_role
          ON member_role.oid = membership.member
        WHERE granted_role.rolname = 'iam_self_summary_reader'
          AND member_role.rolname = 'schema_owner'
          AND membership.set_option = true
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_function_owner_membership',
            MESSAGE = 'function owner membership is not provisioned';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS granted_role
          ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS member_role
          ON member_role.oid = membership.member
        WHERE member_role.rolname = ANY (ARRAY[
            'iam_app',
            'iam_session_authenticator',
            'iam_onboarding',
            'iam_system',
            'iam_outbox_worker'
        ])
          AND granted_role.rolname = ANY (ARRAY[
            'schema_owner',
            'iam_self_summary_reader',
            'iam_key_policy_operator'
        ])
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            CONSTRAINT = 'ck_iam_runtime_role_isolation',
            MESSAGE = 'runtime role has forbidden role membership';
    END IF;
END
$iam_role_guard$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA iam AUTHORIZATION schema_owner;
CREATE SCHEMA iam_api AUTHORIZATION schema_owner;
CREATE SCHEMA infra AUTHORIZATION schema_owner;
CREATE SCHEMA audit AUTHORIZATION schema_owner;

REVOKE ALL ON SCHEMA iam, iam_api, infra, audit FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA iam
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA iam
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA iam
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA iam_api
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA iam_api
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA iam_api
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA infra
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA infra
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA infra
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA audit
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA audit
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner IN SCHEMA audit
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;

CREATE TABLE infra.schema_migrations (
    component varchar(64) NOT NULL,
    version integer NOT NULL,
    phase text NOT NULL,
    name varchar(160) NOT NULL,
    checksum_sha256 bytea NOT NULL,
    applied_at timestamptz NOT NULL,
    duration_ms integer NOT NULL,
    runner_version varchar(64) NOT NULL,
    applied_by_session_role varchar(128) NOT NULL,
    applied_as_role varchar(128) NOT NULL,
    postgres_server_version_num integer NOT NULL,
    CONSTRAINT pk_schema_migrations PRIMARY KEY (component, version),
    CONSTRAINT uq_schema_migrations_component_name UNIQUE (component, name),
    CONSTRAINT ck_schema_migration_component CHECK (component = 'iam'),
    CONSTRAINT ck_schema_migration_version CHECK (version >= 0),
    CONSTRAINT ck_schema_migration_phase CHECK (
        phase IN ('expand', 'migrate', 'contract')
    ),
    CONSTRAINT ck_schema_migration_checksum CHECK (
        octet_length(checksum_sha256) = 32
    ),
    CONSTRAINT ck_schema_migration_duration CHECK (duration_ms >= 0),
    CONSTRAINT ck_schema_migration_runner CHECK (
        length(runner_version) > 0
        AND applied_by_session_role = 'iam_migration_runner'
        AND applied_as_role = 'schema_owner'
    ),
    CONSTRAINT ck_schema_migration_server CHECK (
        postgres_server_version_num >= 180000
        AND postgres_server_version_num < 190000
    )
);

REVOKE ALL ON TABLE infra.schema_migrations FROM PUBLIC;
