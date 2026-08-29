-- Platform duties are independent of account and organization membership roles.
-- Downstream contexts must additionally require exact, time-bound assignments.

CREATE TABLE iam.platform_duty_grants (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    duty_code text NOT NULL,
    granted_by_kind text NOT NULL,
    granted_by_id uuid NOT NULL,
    granted_at timestamptz NOT NULL,
    expires_at timestamptz NULL,
    revoked_at timestamptz NULL,
    revocation_reason_code varchar(64) NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_platform_duty_grants PRIMARY KEY (id),
    CONSTRAINT uq_platform_duty_grant_id_version UNIQUE (id, aggregate_version),
    CONSTRAINT fk_platform_duty_grant_user FOREIGN KEY (user_id)
        REFERENCES iam.users (id) ON DELETE RESTRICT,
    CONSTRAINT ck_platform_duty_code CHECK (
        duty_code IN (
            'ACCESS_ADMIN',
            'OPERATIONS_REVIEWER',
            'FINANCE_OPERATOR',
            'TRUST_OFFICER',
            'APPEAL_REVIEWER'
        )
    ),
    CONSTRAINT ck_platform_duty_grantor CHECK (
        granted_by_kind IN ('USER', 'SYSTEM')
    ),
    CONSTRAINT ck_platform_duty_revocation CHECK (
        (revoked_at IS NULL AND revocation_reason_code IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_platform_duty_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_platform_duty_time CHECK (
        created_at <= granted_at
        AND updated_at >= created_at
        AND (expires_at IS NULL OR expires_at > granted_at)
        AND (revoked_at IS NULL OR revoked_at >= granted_at)
    )
);

CREATE UNIQUE INDEX ux_platform_duty_grant_active
    ON iam.platform_duty_grants (user_id, duty_code)
    WHERE revoked_at IS NULL;

CREATE INDEX ix_platform_duty_grant_authorization
    ON iam.platform_duty_grants (duty_code, user_id, expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE iam.platform_duty_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.platform_duty_grants FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE iam.platform_duty_grants FROM PUBLIC;
REVOKE ALL ON TABLE iam.platform_duty_grants FROM iam_app, iam_system;

GRANT SELECT ON iam.platform_duty_grants TO iam_app;
GRANT SELECT, INSERT, UPDATE ON iam.platform_duty_grants TO iam_system;

CREATE POLICY rls_platform_duty_self_select
ON iam.platform_duty_grants
FOR SELECT TO iam_app
USING (
    session_user = 'iam_app'
    AND current_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_platform_duty_system
ON iam.platform_duty_grants
FOR ALL TO iam_system
USING (
    session_user = 'iam_system'
    AND current_user = 'iam_system'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND user_id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
)
WITH CHECK (
    session_user = 'iam_system'
    AND current_user = 'iam_system'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND user_id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
);

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'iam'
      AND relation.relname = 'platform_duty_grants'
      AND (
          relation.relkind <> 'r'
          OR NOT relation.relrowsecurity
          OR NOT relation.relforcerowsecurity
      );
    IF invalid_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'platform duty RLS assertion failed';
    END IF;

    IF pg_catalog.has_table_privilege(
        'iam_app',
        'iam.platform_duty_grants',
        'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) OR NOT pg_catalog.has_table_privilege(
        'iam_app',
        'iam.platform_duty_grants',
        'SELECT'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'platform duty runtime grants assertion failed';
    END IF;
END
$assert$;
