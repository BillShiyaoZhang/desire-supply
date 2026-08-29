-- Production discovery and immutable Creator Profile inputs for Matching.

CREATE TABLE profile.match_capture_batches (
    match_run_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    authorization_digest bytea NOT NULL,
    capture_contract_version integer NOT NULL,
    status text NOT NULL,
    captured_at timestamptz NOT NULL,
    authorization_valid_until timestamptz NOT NULL,
    candidate_count integer NOT NULL,
    allowlist_sha256 bytea NOT NULL,
    CONSTRAINT pk_profile_match_capture_batches PRIMARY KEY (
        match_run_id,
        workload_id
    ),
    CONSTRAINT uq_profile_match_capture_run UNIQUE (match_run_id),
    CONSTRAINT uq_profile_match_capture_workload UNIQUE (workload_id),
    CONSTRAINT ck_profile_match_capture_batch_contract CHECK (
        capture_contract_version = 1
        AND status = 'COMPLETED'
    ),
    CONSTRAINT ck_profile_match_capture_batch_hashes CHECK (
        octet_length(authorization_digest) = 32
        AND authorization_digest <> decode(repeat('00', 32), 'hex')
        AND octet_length(allowlist_sha256) = 32
    ),
    CONSTRAINT ck_profile_match_capture_batch_count CHECK (
        candidate_count BETWEEN 0 AND 500
    ),
    CONSTRAINT ck_profile_match_capture_batch_time CHECK (
        authorization_valid_until > captured_at
    )
);

CREATE TABLE profile.match_input_snapshots (
    match_run_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    snapshot_ordinal integer NOT NULL,
    authorization_digest bytea NOT NULL,
    capture_contract_version integer NOT NULL,
    captured_at timestamptz NOT NULL,
    creator_user_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_version_id uuid NOT NULL,
    version_no bigint NOT NULL,
    profile_schema_version integer NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    canonical_content bytea NOT NULL,
    content jsonb NOT NULL,
    content_sha256 bytea NOT NULL,
    CONSTRAINT pk_profile_match_input_snapshots PRIMARY KEY (
        match_run_id,
        workload_id,
        profile_id
    ),
    CONSTRAINT uq_profile_match_input_snapshot_ordinal UNIQUE (
        match_run_id,
        workload_id,
        snapshot_ordinal
    ),
    CONSTRAINT uq_profile_match_input_snapshot_version UNIQUE (
        match_run_id,
        workload_id,
        profile_version_id
    ),
    CONSTRAINT fk_profile_match_input_batch FOREIGN KEY (
        match_run_id,
        workload_id
    ) REFERENCES profile.match_capture_batches (
        match_run_id,
        workload_id
    ) ON DELETE RESTRICT,
    CONSTRAINT fk_profile_match_input_root FOREIGN KEY (
        profile_id,
        creator_user_id
    ) REFERENCES profile.creator_profiles (
        id,
        owner_user_id
    ) ON DELETE RESTRICT,
    CONSTRAINT fk_profile_match_input_version FOREIGN KEY (
        profile_id,
        profile_version_id
    ) REFERENCES profile.profile_versions (
        profile_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT ck_profile_match_input_snapshot_ordinal CHECK (
        snapshot_ordinal BETWEEN 1 AND 500
    ),
    CONSTRAINT ck_profile_match_input_snapshot_contract CHECK (
        capture_contract_version = 1
        AND profile_schema_version = 1
        AND canonicalization_version = 'profile-version-json-v1'
    ),
    CONSTRAINT ck_profile_match_input_snapshot_shape CHECK (
        version_no >= 1
        AND jsonb_typeof(content) = 'object'
        AND octet_length(canonical_content) BETWEEN 1 AND 524288
        AND octet_length(content_sha256) = 32
        AND octet_length(authorization_digest) = 32
    )
);

ALTER TABLE profile.match_capture_authorizations
ADD CONSTRAINT fk_profile_match_authorization_batch FOREIGN KEY (
    match_run_id,
    workload_id
) REFERENCES profile.match_capture_batches (
    match_run_id,
    workload_id
) ON DELETE RESTRICT NOT VALID;

CREATE FUNCTION profile.enforce_match_capture_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, profile
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514',
        CONSTRAINT = 'trg_profile_match_capture_immutable',
        MESSAGE = 'Profile match capture facts are immutable';
END
$function$;

CREATE TRIGGER trg_profile_match_capture_batch_immutable
BEFORE UPDATE OR DELETE ON profile.match_capture_batches
FOR EACH ROW EXECUTE FUNCTION profile.enforce_match_capture_immutable();

CREATE TRIGGER trg_profile_match_input_snapshot_immutable
BEFORE UPDATE OR DELETE ON profile.match_input_snapshots
FOR EACH ROW EXECUTE FUNCTION profile.enforce_match_capture_immutable();

CREATE TRIGGER trg_profile_match_authorization_immutable
BEFORE UPDATE OR DELETE ON profile.match_capture_authorizations
FOR EACH ROW EXECUTE FUNCTION profile.enforce_match_capture_immutable();

ALTER TABLE profile.match_capture_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.match_capture_batches FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.match_input_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.match_input_snapshots FORCE ROW LEVEL SECURITY;

DROP POLICY rls_profile_match_authorization
ON profile.match_capture_authorizations;
DROP POLICY rls_profile_match_authorization_definer
ON profile.match_capture_authorizations;
DROP POLICY rls_creator_profile_matcher
ON profile.creator_profiles;
DROP POLICY rls_creator_profile_matcher_definer
ON profile.creator_profiles;
DROP POLICY rls_profile_version_matcher
ON profile.profile_versions;

CREATE POLICY rls_profile_match_capture_batch_definer_v1
ON profile.match_capture_batches
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND (
        match_run_id = NULLIF(
            current_setting('app.match_run_id', true),
            ''
        )::uuid
        OR workload_id = NULLIF(
            current_setting('app.workload_id', true),
            ''
        )::uuid
    )
)
WITH CHECK (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND match_run_id = NULLIF(
        current_setting('app.match_run_id', true),
        ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true),
        ''
    )::uuid
    AND authorization_digest = decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )
);

CREATE POLICY rls_profile_match_input_snapshot_definer_v1
ON profile.match_input_snapshots
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND match_run_id = NULLIF(
        current_setting('app.match_run_id', true),
        ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true),
        ''
    )::uuid
    AND authorization_digest = decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )
)
WITH CHECK (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND match_run_id = NULLIF(
        current_setting('app.match_run_id', true),
        ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true),
        ''
    )::uuid
    AND authorization_digest = decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )
);

CREATE POLICY rls_profile_match_authorization_definer_v2
ON profile.match_capture_authorizations
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND match_run_id = NULLIF(
        current_setting('app.match_run_id', true),
        ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true),
        ''
    )::uuid
    AND authorization_digest = decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )
)
WITH CHECK (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND match_run_id = NULLIF(
        current_setting('app.match_run_id', true),
        ''
    )::uuid
    AND workload_id = NULLIF(
        current_setting('app.workload_id', true),
        ''
    )::uuid
    AND authorization_digest = decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )
);

CREATE POLICY rls_creator_profile_match_capture_definer_v2
ON profile.creator_profiles
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
    AND octet_length(decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )) = 32
);

CREATE POLICY rls_profile_version_match_capture_definer_v2
ON profile.profile_versions
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
    AND octet_length(decode(
        NULLIF(
            current_setting('app.match_authorization_digest', true),
            ''
        ),
        'hex'
    )) = 32
);

CREATE POLICY rls_creator_profile_match_capture_lock_definer_v2
ON profile.creator_profiles
FOR UPDATE TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
)
WITH CHECK (false);

CREATE POLICY rls_profile_version_match_capture_lock_definer_v2
ON profile.profile_versions
FOR UPDATE TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_CAPTURE'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
)
WITH CHECK (false);

CREATE FUNCTION profile_api.discover_and_capture_creator_profile_match_inputs_v1(
    p_match_run_id uuid,
    p_workload_id uuid,
    p_authorization_digest bytea
)
RETURNS TABLE (
    match_run_id uuid,
    workload_id uuid,
    capture_contract_version integer,
    capture_status text,
    captured_at timestamptz,
    candidate_count integer,
    allowlist_sha256 bytea,
    authorization_valid_until timestamptz,
    replayed boolean,
    snapshot_ordinal integer,
    creator_user_id uuid,
    profile_id uuid,
    profile_version_id uuid,
    version_no bigint,
    taxonomy_bundle_id uuid,
    canonical_content bytea,
    content jsonb,
    content_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, profile, iam_api
AS $function$
DECLARE
    v_collision_count integer;
    v_existing profile.match_capture_batches%ROWTYPE;
    v_candidate_profile_ids uuid[];
    v_candidate_count integer;
    v_allowlist_sha256 bytea;
    v_captured_at timestamptz;
    v_authorization_valid_until timestamptz;
    v_valid_source_count integer;
    v_snapshot_count integer;
    v_authorization_count integer;
    v_replayed boolean := false;
BEGIN
    IF session_user IS DISTINCT FROM 'profile_matcher'
       OR current_user IS DISTINCT FROM 'profile_schema_owner'
       OR current_setting('transaction_isolation') IS DISTINCT FROM
            'repeatable read'
       OR current_setting('transaction_read_only') IS DISTINCT FROM 'off'
       OR p_match_run_id IS NULL
       OR p_match_run_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_workload_id IS NULL
       OR p_workload_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_authorization_digest IS NULL
       OR octet_length(p_authorization_digest) <> 32
       OR p_authorization_digest = decode(repeat('00', 32), 'hex')
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'PROFILE_MATCH_CAPTURE'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CAPTURE_MATCH_INPUTS'
       OR NULLIF(current_setting('app.match_run_id', true), '')::uuid
            IS DISTINCT FROM p_match_run_id
       OR NULLIF(current_setting('app.workload_id', true), '')::uuid
            IS DISTINCT FROM p_workload_id
       OR decode(
            NULLIF(
                current_setting('app.match_authorization_digest', true),
                ''
            ),
            'hex'
          ) IS DISTINCT FROM p_authorization_digest
       OR NOT EXISTS (
            SELECT 1
            FROM profile.schema_compatibility AS compatibility
            WHERE compatibility.component = 'profile'
              AND compatibility.current_schema_version = 4
              AND compatibility.schema_head_version = 4
              AND compatibility.min_app_compatible_version = 4
              AND compatibility.max_app_compatible_version = 4
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'Profile match capture denied';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'profile-match-run:' || p_match_run_id::text,
            0
        )
    );
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'profile-match-workload:' || p_workload_id::text,
            0
        )
    );

    SELECT count(*)
    INTO v_collision_count
    FROM profile.match_capture_batches AS batch
    WHERE batch.match_run_id = p_match_run_id
       OR batch.workload_id = p_workload_id;
    IF v_collision_count > 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'ck_profile_match_capture_binding',
            MESSAGE = 'Profile match capture binding mismatch';
    END IF;

    SELECT batch.*
    INTO v_existing
    FROM profile.match_capture_batches AS batch
    WHERE batch.match_run_id = p_match_run_id
       OR batch.workload_id = p_workload_id
    FOR UPDATE;
    IF FOUND THEN
        IF v_existing.match_run_id IS DISTINCT FROM p_match_run_id
           OR v_existing.workload_id IS DISTINCT FROM p_workload_id
           OR v_existing.authorization_digest IS DISTINCT FROM
                p_authorization_digest
           OR v_existing.capture_contract_version IS DISTINCT FROM 1
           OR v_existing.status IS DISTINCT FROM 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'ck_profile_match_capture_binding',
                MESSAGE = 'Profile match capture binding mismatch';
        END IF;
        v_candidate_count := v_existing.candidate_count;
        v_allowlist_sha256 := v_existing.allowlist_sha256;
        v_captured_at := v_existing.captured_at;
        v_authorization_valid_until :=
            v_existing.authorization_valid_until;
        v_replayed := true;
    ELSE
        SELECT COALESCE(
            array_agg(candidate.profile_id ORDER BY candidate.profile_id),
            ARRAY[]::uuid[]
        )
        INTO v_candidate_profile_ids
        FROM (
            SELECT root.id AS profile_id
            FROM profile.creator_profiles AS root
            JOIN profile.profile_versions AS version
              ON version.profile_id = root.id
             AND version.id = root.current_published_version_id
            WHERE root.status = 'ACTIVE'
              AND version.status = 'PUBLISHED'
              AND iam_api.is_creator_match_eligible_v1(root.owner_user_id)
            ORDER BY root.id
            FOR SHARE OF root, version
        ) AS candidate;
        v_candidate_count := cardinality(v_candidate_profile_ids);
        IF v_candidate_count > 500 THEN
            RAISE EXCEPTION USING ERRCODE = '54000',
                MESSAGE = 'Profile match candidate ceiling exceeded';
        END IF;

        v_allowlist_sha256 := pg_catalog.sha256(
            pg_catalog.convert_to(
                'profile-match-allowlist-v1|' ||
                v_candidate_count::text || '|' ||
                COALESCE(array_to_string(v_candidate_profile_ids, ','), ''),
                'UTF8'
            )
        );
        v_captured_at := transaction_timestamp();
        v_authorization_valid_until :=
            v_captured_at + interval '15 minutes';

        SELECT count(*)
        INTO v_valid_source_count
        FROM profile.creator_profiles AS root
        JOIN profile.profile_versions AS version
          ON version.profile_id = root.id
         AND version.id = root.current_published_version_id
        WHERE root.id = ANY(v_candidate_profile_ids)
          AND root.status = 'ACTIVE'
          AND version.status = 'PUBLISHED'
          AND version.schema_version = 1
          AND version.canonicalization_version = 'profile-version-json-v1'
          AND pg_catalog.sha256(version.canonical_content)
                = version.content_sha256
          AND pg_catalog.convert_from(
                version.canonical_content,
                'UTF8'
              )::jsonb = version.content;
        IF v_valid_source_count IS DISTINCT FROM v_candidate_count THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'ck_profile_match_capture_source_canonical',
                MESSAGE = 'Profile match capture source is invalid';
        END IF;

        INSERT INTO profile.match_capture_batches (
            match_run_id,
            workload_id,
            authorization_digest,
            capture_contract_version,
            status,
            captured_at,
            authorization_valid_until,
            candidate_count,
            allowlist_sha256
        ) VALUES (
            p_match_run_id,
            p_workload_id,
            p_authorization_digest,
            1,
            'COMPLETED',
            v_captured_at,
            v_authorization_valid_until,
            v_candidate_count,
            v_allowlist_sha256
        );

        INSERT INTO profile.match_capture_authorizations (
            match_run_id,
            workload_id,
            candidate_profile_id,
            authorization_digest,
            valid_from,
            valid_until,
            created_at
        )
        SELECT
            p_match_run_id,
            p_workload_id,
            candidate.profile_id,
            p_authorization_digest,
            v_captured_at,
            v_authorization_valid_until,
            v_captured_at
        FROM unnest(v_candidate_profile_ids)
            WITH ORDINALITY AS candidate(profile_id, ordinal)
        ORDER BY candidate.ordinal;

        INSERT INTO profile.match_input_snapshots (
            match_run_id,
            workload_id,
            snapshot_ordinal,
            authorization_digest,
            capture_contract_version,
            captured_at,
            creator_user_id,
            profile_id,
            profile_version_id,
            version_no,
            profile_schema_version,
            canonicalization_version,
            taxonomy_bundle_id,
            canonical_content,
            content,
            content_sha256
        )
        SELECT
            p_match_run_id,
            p_workload_id,
            candidate.ordinal::integer,
            p_authorization_digest,
            1,
            v_captured_at,
            root.owner_user_id,
            root.id,
            version.id,
            version.version_no,
            version.schema_version,
            version.canonicalization_version,
            version.taxonomy_bundle_id,
            version.canonical_content,
            version.content,
            version.content_sha256
        FROM unnest(v_candidate_profile_ids)
            WITH ORDINALITY AS candidate(profile_id, ordinal)
        JOIN profile.creator_profiles AS root
          ON root.id = candidate.profile_id
        JOIN profile.profile_versions AS version
          ON version.profile_id = root.id
         AND version.id = root.current_published_version_id
        ORDER BY candidate.ordinal;
    END IF;

    SELECT count(*)
    INTO v_snapshot_count
    FROM profile.match_input_snapshots AS snapshot
    WHERE snapshot.match_run_id = p_match_run_id
      AND snapshot.workload_id = p_workload_id;
    SELECT count(*)
    INTO v_authorization_count
    FROM profile.match_capture_authorizations AS authz
    WHERE authz.match_run_id = p_match_run_id
      AND authz.workload_id = p_workload_id;
    IF v_snapshot_count IS DISTINCT FROM v_candidate_count
       OR v_authorization_count IS DISTINCT FROM v_candidate_count
       OR v_allowlist_sha256 IS DISTINCT FROM pg_catalog.sha256(
            pg_catalog.convert_to(
                'profile-match-allowlist-v1|' ||
                v_candidate_count::text || '|' ||
                COALESCE(
                    (
                        SELECT string_agg(
                            snapshot.profile_id::text,
                            ',' ORDER BY snapshot.snapshot_ordinal
                        )
                        FROM profile.match_input_snapshots AS snapshot
                        WHERE snapshot.match_run_id = p_match_run_id
                          AND snapshot.workload_id = p_workload_id
                    ),
                    ''
                ),
                'UTF8'
            )
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'ck_profile_match_capture_snapshot_set',
            MESSAGE = 'Profile match capture snapshot set drift';
    END IF;

    IF v_candidate_count = 0 THEN
        RETURN QUERY SELECT
            p_match_run_id,
            p_workload_id,
            1,
            'COMPLETED'::text,
            v_captured_at,
            0,
            v_allowlist_sha256,
            v_authorization_valid_until,
            v_replayed,
            NULL::integer,
            NULL::uuid,
            NULL::uuid,
            NULL::uuid,
            NULL::bigint,
            NULL::uuid,
            NULL::bytea,
            NULL::jsonb,
            NULL::bytea;
    ELSE
        RETURN QUERY
        SELECT
            p_match_run_id,
            p_workload_id,
            1,
            'COMPLETED'::text,
            v_captured_at,
            v_candidate_count,
            v_allowlist_sha256,
            v_authorization_valid_until,
            v_replayed,
            snapshot.snapshot_ordinal,
            snapshot.creator_user_id,
            snapshot.profile_id,
            snapshot.profile_version_id,
            snapshot.version_no,
            snapshot.taxonomy_bundle_id,
            snapshot.canonical_content,
            snapshot.content,
            snapshot.content_sha256
        FROM profile.match_input_snapshots AS snapshot
        WHERE snapshot.match_run_id = p_match_run_id
          AND snapshot.workload_id = p_workload_id
        ORDER BY snapshot.snapshot_ordinal;
    END IF;
END
$function$;

ALTER FUNCTION profile_api.discover_and_capture_creator_profile_match_inputs_v1(
    uuid,
    uuid,
    bytea
) OWNER TO profile_schema_owner;
REVOKE ALL ON FUNCTION profile_api.is_capture_candidate_eligible_v1(
    uuid,
    uuid,
    uuid,
    uuid,
    bytea
) FROM profile_matcher;
REVOKE ALL ON FUNCTION profile_api.discover_and_capture_creator_profile_match_inputs_v1(
    uuid,
    uuid,
    bytea
) FROM PUBLIC;

REVOKE ALL ON profile.creator_profiles,
    profile.profile_versions,
    profile.profile_version_evidence,
    profile.match_capture_authorizations
FROM profile_matcher;
REVOKE SELECT ON profile.schema_compatibility FROM profile_matcher;
REVOKE USAGE ON SCHEMA profile FROM profile_matcher;
GRANT USAGE ON SCHEMA profile_api TO profile_matcher;
GRANT EXECUTE ON FUNCTION profile_api.discover_and_capture_creator_profile_match_inputs_v1(
    uuid,
    uuid,
    bytea
) TO profile_matcher;

DO $assert$
DECLARE
    invalid_count integer;
BEGIN
    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = procedure.proowner
    WHERE namespace.nspname = 'profile_api'
      AND procedure.proname =
            'discover_and_capture_creator_profile_match_inputs_v1'
      AND (
        owner_role.rolname <> 'profile_schema_owner'
        OR NOT procedure.prosecdef
        OR procedure.provolatile <> 'v'
        OR procedure.proparallel <> 'u'
        OR procedure.proconfig IS DISTINCT FROM ARRAY[
            'search_path=pg_catalog, profile, iam_api'
        ]::text[]
        OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_schema_privilege(
            'profile_matcher',
            'profile_api',
            'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            'profile_matcher',
            'profile',
            'USAGE'
       )
       OR NOT pg_catalog.has_function_privilege(
            'profile_matcher',
            'profile_api.discover_and_capture_creator_profile_match_inputs_v1(uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_app',
            'profile_api.discover_and_capture_creator_profile_match_inputs_v1(uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_matcher',
            'profile_api.is_capture_candidate_eligible_v1(uuid,uuid,uuid,uuid,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_function_privilege(
            'profile_matcher',
            'iam_api.is_creator_match_eligible_v1(uuid)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Profile match capture boundary assertion failed';
    END IF;

    SELECT count(*) INTO invalid_count
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'profile'
      AND relation.relname IN (
        'match_capture_batches',
        'match_input_snapshots',
        'match_capture_authorizations'
      )
      AND (
        NOT relation.relrowsecurity
        OR NOT relation.relforcerowsecurity
        OR pg_catalog.has_table_privilege(
            'profile_matcher',
            relation.oid,
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
      );
    IF invalid_count <> 0 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Profile match capture table assertion failed';
    END IF;
END
$assert$;
