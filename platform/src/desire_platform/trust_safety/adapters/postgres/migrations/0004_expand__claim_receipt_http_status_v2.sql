SET LOCAL search_path = pg_catalog, trust;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $migration_guard$
BEGIN
    IF session_user IS DISTINCT FROM 'trust_migration_runner'
       OR current_user IS DISTINCT FROM 'trust_schema_owner'
       OR current_setting('server_version_num')::integer < 180000
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'TRUST_MIGRATION_CONTEXT_INVALID';
    END IF;
END
$migration_guard$;

DO $reader_acl_baseline$
DECLARE
    acl_is_exact boolean;
BEGIN
    SELECT
        procedure.proowner = (
            SELECT role.oid
            FROM pg_roles AS role
            WHERE role.rolname = 'trust_schema_owner'
        )
        AND count(*) = 3
        AND count(DISTINCT privilege.grantee) = 3
        AND bool_and(
            privilege.privilege_type = 'EXECUTE'
            AND privilege.grantor = procedure.proowner
            AND NOT privilege.is_grantable
            AND privilege.grantee IN (
                procedure.proowner,
                (
                    SELECT role.oid
                    FROM pg_roles AS role
                    WHERE role.rolname = 'trust_self'
                ),
                (
                    SELECT role.oid
                    FROM pg_roles AS role
                    WHERE role.rolname = 'trust_officer'
                )
            )
        )
    INTO STRICT acl_is_exact
    FROM pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(
            procedure.proacl,
            acldefault('f', procedure.proowner)
        )
    ) AS privilege
    WHERE procedure.oid = (
        'trust_api.read_completed_command_receipt_v1('
        'uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[]'
        ')'
        ::regprocedure
    )
    GROUP BY procedure.proowner;
    IF acl_is_exact IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_READER_ACL_BASELINE_MISMATCH';
    END IF;
END
$reader_acl_baseline$;

ALTER TABLE trust_meta.schema_contracts
DROP CONSTRAINT ck_trust_schema_contract_versions;
DELETE FROM trust_meta.schema_contracts;
ALTER TABLE trust_meta.schema_contracts
ADD CONSTRAINT ck_trust_schema_contract_versions CHECK (
    schema_head_version = 4
    AND min_app_compatible_version = 4
    AND max_app_compatible_version = 4
    AND required_iam_schema_version = 36
    AND required_demand_schema_version = 8
);

CREATE FUNCTION trust.normalize_claim_receipt_http_status_v2()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, trust
AS $function$
BEGIN
    IF current_user IS DISTINCT FROM 'trust_schema_owner' THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'TRUST_RECEIPT_COMPLETION_CONTEXT_INVALID';
    END IF;
    IF OLD.status = 'IN_PROGRESS'
       AND NEW.status = 'COMPLETED'
       AND NEW.response_http_status = 200
       AND (
            (
                NEW.command_name = 'CLAIM_CASE'
                AND NEW.event_types = ARRAY['TrustCaseClaimed']::text[]
            )
            OR (
                NEW.command_name = 'CLAIM_HOLD_RELEASE'
                AND NEW.event_types
                    = ARRAY['TrustHoldReleaseClaimed']::text[]
            )
       )
    THEN
        NEW.response_http_status := 201;
    END IF;
    RETURN NEW;
END
$function$;

REVOKE ALL ON FUNCTION trust.normalize_claim_receipt_http_status_v2()
FROM PUBLIC;

CREATE TRIGGER command_receipts_claim_http_status_v2
BEFORE UPDATE ON trust.command_receipts
FOR EACH ROW
EXECUTE FUNCTION trust.normalize_claim_receipt_http_status_v2();

DO $replace_reader$
DECLARE
    reader_definition text;
    reader_baseline_sha256 constant bytea := decode(
        '46dd40efb9b41922a4febf4a089364de82704c56899781c537f95f918c225264',
        'hex'
    );
    old_status_case constant text := $reader_old_status_case$
        WHEN exact_command_name IN (
            'SUBMIT_REPORT',
            'PLACE_HOLD',
            'PUBLISH_OUTCOME'
        ) THEN 201
$reader_old_status_case$;
    new_status_case constant text := $reader_new_status_case$
        WHEN exact_command_name IN (
            'SUBMIT_REPORT',
            'CLAIM_CASE',
            'PLACE_HOLD',
            'CLAIM_HOLD_RELEASE',
            'PUBLISH_OUTCOME'
        ) THEN 201
$reader_new_status_case$;
    old_status_guard constant text := $reader_old_status_guard$
    IF existing.response_http_status <> expected_http_status
       OR existing.response_schema_name <> 'TrustCommandResult'
$reader_old_status_guard$;
    new_status_guard constant text := $reader_new_status_guard$
    IF (
            existing.response_http_status <> expected_http_status
            AND NOT (
                exact_command_name IN (
                    'CLAIM_CASE', 'CLAIM_HOLD_RELEASE'
                )
                AND existing.response_http_status = 200
            )
       )
       OR existing.response_schema_name <> 'TrustCommandResult'
$reader_new_status_guard$;
BEGIN
    SELECT pg_get_functiondef(
        'trust_api.read_completed_command_receipt_v1('
        'uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[]'
        ')'
        ::regprocedure
    )
    INTO STRICT reader_definition;

    IF sha256(convert_to(reader_definition, 'UTF8'))
            IS DISTINCT FROM reader_baseline_sha256
       OR (
        length(reader_definition) - length(replace(
            reader_definition,
            old_status_case,
            ''
        ))
    ) / length(old_status_case) <> 1
       OR (
        length(reader_definition) - length(replace(
            reader_definition,
            old_status_guard,
            ''
        ))
       ) / length(old_status_guard) <> 1
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_READER_BASELINE_MISMATCH';
    END IF;

    reader_definition := replace(
        reader_definition,
        old_status_case,
        new_status_case
    );
    reader_definition := replace(
        reader_definition,
        old_status_guard,
        new_status_guard
    );
    EXECUTE reader_definition;
END
$replace_reader$;

REVOKE ALL ON FUNCTION trust_api.read_completed_command_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint, text[], bytea[], text[], bytea[]
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trust_api.read_completed_command_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint, text[], bytea[], text[], bytea[]
) TO trust_self;
GRANT EXECUTE ON FUNCTION trust_api.read_completed_command_receipt_v1(
    uuid, uuid, uuid, text, uuid, bigint, text[], bytea[], text[], bytea[]
) TO trust_officer;

DO $reader_acl_postcondition$
DECLARE
    acl_is_exact boolean;
BEGIN
    SELECT
        procedure.proowner = (
            SELECT role.oid
            FROM pg_roles AS role
            WHERE role.rolname = 'trust_schema_owner'
        )
        AND count(*) = 3
        AND count(DISTINCT privilege.grantee) = 3
        AND bool_and(
            privilege.privilege_type = 'EXECUTE'
            AND privilege.grantor = procedure.proowner
            AND NOT privilege.is_grantable
            AND privilege.grantee IN (
                procedure.proowner,
                (
                    SELECT role.oid
                    FROM pg_roles AS role
                    WHERE role.rolname = 'trust_self'
                ),
                (
                    SELECT role.oid
                    FROM pg_roles AS role
                    WHERE role.rolname = 'trust_officer'
                )
            )
        )
    INTO STRICT acl_is_exact
    FROM pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(
            procedure.proacl,
            acldefault('f', procedure.proowner)
        )
    ) AS privilege
    WHERE procedure.oid = (
        'trust_api.read_completed_command_receipt_v1('
        'uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[]'
        ')'
        ::regprocedure
    )
    GROUP BY procedure.proowner;
    IF acl_is_exact IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'TRUST_RECEIPT_READER_ACL_BASELINE_MISMATCH';
    END IF;
END
$reader_acl_postcondition$;
