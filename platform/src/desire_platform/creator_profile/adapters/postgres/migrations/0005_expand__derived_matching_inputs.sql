-- Profile-owned privacy derivation for the frozen deterministic matcher v1 input.

CREATE TABLE profile.derived_match_capture_receipts (
    match_run_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    authorization_digest bytea NOT NULL,
    demand_match_context_bytes bytea NOT NULL,
    demand_match_context_sha256 bytea NOT NULL,
    organization_id uuid NOT NULL,
    demand_id uuid NOT NULL,
    demand_version_id uuid NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    capture_contract_version integer NOT NULL,
    status text NOT NULL,
    captured_at timestamptz NOT NULL,
    authorization_valid_until timestamptz NOT NULL,
    candidate_count integer NOT NULL,
    allowlist_sha256 bytea NOT NULL,
    CONSTRAINT pk_profile_derived_match_capture PRIMARY KEY (
        match_run_id,
        workload_id
    ),
    CONSTRAINT uq_profile_derived_match_capture_run UNIQUE (match_run_id),
    CONSTRAINT ck_profile_derived_match_capture_contract CHECK (
        capture_contract_version = 2 AND status = 'COMPLETED'
    ),
    CONSTRAINT ck_profile_derived_match_capture_hashes CHECK (
        octet_length(authorization_digest) = 32
        AND authorization_digest <> decode(repeat('00', 32), 'hex')
        AND octet_length(demand_match_context_sha256) = 32
        AND octet_length(allowlist_sha256) = 32
        AND octet_length(demand_match_context_bytes) BETWEEN 1 AND 65536
    ),
    CONSTRAINT ck_profile_derived_match_capture_count CHECK (
        candidate_count BETWEEN 0 AND 500
    ),
    CONSTRAINT ck_profile_derived_match_capture_time CHECK (
        authorization_valid_until > captured_at
    )
);

CREATE TABLE profile.derived_match_raw_snapshots (
    match_run_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    snapshot_ordinal integer NOT NULL,
    creator_user_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_version_id uuid NOT NULL,
    version_no bigint NOT NULL,
    taxonomy_bundle_id uuid NOT NULL,
    canonical_profile_version_bytes bytea NOT NULL,
    profile_content jsonb NOT NULL,
    profile_content_sha256 bytea NOT NULL,
    taxonomy_bundle_sha256 bytea NOT NULL,
    taxonomy_bundle_version bigint NOT NULL,
    iam_creator_user_version bigint NOT NULL,
    iam_creator_grant_id uuid NOT NULL,
    iam_creator_grant_version bigint NOT NULL,
    iam_source_invitation_id uuid NOT NULL,
    iam_source_invitation_version bigint NOT NULL,
    iam_policy_selector_digest bytea NOT NULL,
    iam_policy_selector_version bigint NOT NULL,
    iam_policy_bundle_id uuid NOT NULL,
    iam_policy_bundle_version bigint NOT NULL,
    iam_required_acceptance_set_sha256 bytea NOT NULL,
    iam_eligibility_evidence_sha256 bytea NOT NULL,
    source_evidence_facts jsonb NOT NULL,
    source_evidence_set_sha256 bytea NOT NULL,
    private_floor_evidence_digest bytea NOT NULL,
    CONSTRAINT pk_profile_derived_match_raw_snapshot PRIMARY KEY (
        match_run_id,
        workload_id,
        profile_id
    ),
    CONSTRAINT uq_profile_derived_match_raw_ordinal UNIQUE (
        match_run_id,
        workload_id,
        snapshot_ordinal
    ),
    CONSTRAINT fk_profile_derived_match_raw_receipt FOREIGN KEY (
        match_run_id,
        workload_id
    ) REFERENCES profile.derived_match_capture_receipts (
        match_run_id,
        workload_id
    ) ON DELETE RESTRICT,
    CONSTRAINT fk_profile_derived_match_raw_root FOREIGN KEY (
        profile_id,
        creator_user_id
    ) REFERENCES profile.creator_profiles (id, owner_user_id) ON DELETE RESTRICT,
    CONSTRAINT fk_profile_derived_match_raw_version FOREIGN KEY (
        profile_id,
        profile_version_id
    ) REFERENCES profile.profile_versions (profile_id, id) ON DELETE RESTRICT,
    CONSTRAINT ck_profile_derived_match_raw_ordinal CHECK (
        snapshot_ordinal BETWEEN 1 AND 500
    ),
    CONSTRAINT ck_profile_derived_match_raw_shape CHECK (
        version_no >= 1
        AND octet_length(canonical_profile_version_bytes) BETWEEN 1 AND 524288
        AND jsonb_typeof(profile_content) = 'object'
        AND jsonb_typeof(source_evidence_facts) = 'array'
        AND octet_length(profile_content_sha256) = 32
        AND octet_length(taxonomy_bundle_sha256) = 32
        AND taxonomy_bundle_version >= 1
        AND iam_creator_user_version >= 1
        AND iam_creator_grant_version >= 1
        AND iam_source_invitation_version >= 1
        AND iam_policy_selector_version >= 1
        AND iam_policy_bundle_version >= 1
        AND octet_length(iam_policy_selector_digest) = 32
        AND octet_length(iam_required_acceptance_set_sha256) = 32
        AND octet_length(iam_eligibility_evidence_sha256) = 32
        AND octet_length(source_evidence_set_sha256) = 32
        AND octet_length(private_floor_evidence_digest) = 32
    )
);

CREATE TABLE profile.derived_match_input_snapshots (
    match_run_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    snapshot_ordinal integer NOT NULL,
    profile_id uuid NOT NULL,
    derived_schema_version integer NOT NULL,
    derived_canonicalization_version varchar(64) NOT NULL,
    canonical_derived_input_bytes bytea NOT NULL,
    derived_input jsonb NOT NULL,
    derived_input_sha256 bytea NOT NULL,
    evidence_version_digest bytea NOT NULL,
    CONSTRAINT pk_profile_derived_match_input PRIMARY KEY (
        match_run_id,
        workload_id,
        profile_id
    ),
    CONSTRAINT uq_profile_derived_match_input_ordinal UNIQUE (
        match_run_id,
        workload_id,
        snapshot_ordinal
    ),
    CONSTRAINT fk_profile_derived_match_input_raw FOREIGN KEY (
        match_run_id,
        workload_id,
        profile_id
    ) REFERENCES profile.derived_match_raw_snapshots (
        match_run_id,
        workload_id,
        profile_id
    ) ON DELETE RESTRICT,
    CONSTRAINT ck_profile_derived_match_input_contract CHECK (
        derived_schema_version = 1
        AND derived_canonicalization_version = 'profile-match-input-json-v1'
    ),
    CONSTRAINT ck_profile_derived_match_input_shape CHECK (
        snapshot_ordinal BETWEEN 1 AND 500
        AND octet_length(canonical_derived_input_bytes) BETWEEN 1 AND 524288
        AND jsonb_typeof(derived_input) = 'object'
        AND octet_length(derived_input_sha256) = 32
        AND octet_length(evidence_version_digest) = 32
    )
);

CREATE TRIGGER trg_profile_derived_match_capture_immutable
BEFORE UPDATE OR DELETE ON profile.derived_match_capture_receipts
FOR EACH ROW EXECUTE FUNCTION profile.enforce_match_capture_immutable();
CREATE TRIGGER trg_profile_derived_match_raw_immutable
BEFORE UPDATE OR DELETE ON profile.derived_match_raw_snapshots
FOR EACH ROW EXECUTE FUNCTION profile.enforce_match_capture_immutable();
CREATE TRIGGER trg_profile_derived_match_input_immutable
BEFORE UPDATE OR DELETE ON profile.derived_match_input_snapshots
FOR EACH ROW EXECUTE FUNCTION profile.enforce_match_capture_immutable();

ALTER TABLE profile.derived_match_capture_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.derived_match_capture_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.derived_match_raw_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.derived_match_raw_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE profile.derived_match_input_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile.derived_match_input_snapshots FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_profile_derived_match_receipt_definer_v1
ON profile.derived_match_capture_receipts
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND (
        match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
        OR workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    )
)
WITH CHECK (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
    AND authorization_digest = decode(
        NULLIF(current_setting('app.authorization_digest', true), ''), 'hex'
    )
    AND demand_match_context_sha256 = decode(
        NULLIF(current_setting('app.demand_match_context_sha256', true), ''),
        'hex'
    )
);

CREATE POLICY rls_profile_derived_match_raw_definer_v1
ON profile.derived_match_raw_snapshots
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
)
WITH CHECK (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
);

CREATE POLICY rls_profile_derived_match_input_definer_v1
ON profile.derived_match_input_snapshots
FOR ALL TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
)
WITH CHECK (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND match_run_id = NULLIF(current_setting('app.match_run_id', true), '')::uuid
    AND workload_id = NULLIF(current_setting('app.workload_id', true), '')::uuid
);

CREATE POLICY rls_creator_profile_match_derivation_definer_v1
ON profile.creator_profiles
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
    AND octet_length(decode(NULLIF(
        current_setting('app.authorization_digest', true), ''
    ), 'hex')) = 32
    AND octet_length(decode(NULLIF(
        current_setting('app.demand_match_context_sha256', true), ''
    ), 'hex')) = 32
);

CREATE POLICY rls_profile_version_match_derivation_definer_v1
ON profile.profile_versions
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND NULLIF(current_setting('app.match_run_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.workload_id', true), '') IS NOT NULL
);

CREATE POLICY rls_creator_profile_match_derivation_lock_v1
ON profile.creator_profiles
FOR UPDATE TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
)
WITH CHECK (false);

CREATE POLICY rls_profile_version_match_derivation_lock_v1
ON profile.profile_versions
FOR UPDATE TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
)
WITH CHECK (false);

CREATE POLICY rls_profile_taxonomy_match_derivation_v1
ON profile.taxonomy_bundle_markers
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND id::text = NULLIF(current_setting(
        'app.profile_match_taxonomy_bundle_id', true
    ), '')
);

CREATE POLICY rls_profile_evidence_match_derivation_v1
ON profile.capability_evidence
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND owner_user_id::text = NULLIF(current_setting(
        'app.profile_match_candidate_user_id', true
    ), '')
);

CREATE POLICY rls_profile_version_evidence_match_derivation_v1
ON profile.profile_version_evidence
FOR SELECT TO profile_schema_owner
USING (
    session_user = 'profile_matcher'
    AND current_user = 'profile_schema_owner'
    AND NULLIF(current_setting('app.scope_kind', true), '')
        = 'PROFILE_MATCH_DERIVATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'CAPTURE_DERIVED_MATCH_INPUTS'
    AND profile_id::text = NULLIF(current_setting(
        'app.profile_match_candidate_profile_id', true
    ), '')
);

CREATE FUNCTION profile.canonical_json_v1(candidate jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY INVOKER
PARALLEL SAFE
SET search_path = pg_catalog, profile
AS $function$
DECLARE
    rendered text;
BEGIN
    CASE jsonb_typeof(candidate)
    WHEN 'object' THEN
        SELECT '{' || COALESCE(string_agg(
            to_jsonb(member.key)::text || ':' ||
            profile.canonical_json_v1(member.value),
            ',' ORDER BY member.key COLLATE "C"
        ), '') || '}'
        INTO rendered
        FROM jsonb_each(candidate) AS member(key, value);
    WHEN 'array' THEN
        SELECT '[' || COALESCE(string_agg(
            profile.canonical_json_v1(member.value),
            ',' ORDER BY member.ordinal
        ), '') || ']'
        INTO rendered
        FROM jsonb_array_elements(candidate)
            WITH ORDINALITY AS member(value, ordinal);
    WHEN 'string' THEN
        rendered := to_jsonb(candidate #>> '{}')::text;
    ELSE
        rendered := candidate::text;
    END CASE;
    RETURN rendered;
END
$function$;

CREATE OR REPLACE FUNCTION profile_api.discover_and_capture_creator_profile_match_inputs_v1(
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
              AND compatibility.current_schema_version = 5
              AND compatibility.schema_head_version = 5
              AND compatibility.min_app_compatible_version = 5
              AND compatibility.max_app_compatible_version = 5
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

CREATE FUNCTION profile_api.discover_and_capture_derived_creator_match_inputs_v1(
    exact_match_run_id uuid,
    exact_workload_id uuid,
    exact_authorization_digest bytea,
    exact_demand_match_context_bytes bytea,
    exact_demand_match_context_sha256 bytea
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
    canonical_profile_version_bytes bytea,
    profile_content jsonb,
    profile_content_sha256 bytea,
    derived_schema_version integer,
    derived_canonicalization_version text,
    canonical_derived_input_bytes bytea,
    derived_input jsonb,
    derived_input_sha256 bytea,
    evidence_version_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, profile, iam_api
AS $function$
DECLARE
    zero_uuid constant uuid := '00000000-0000-0000-0000-000000000000';
    zero_digest constant bytea := decode(repeat('00', 32), 'hex');
    context_document jsonb;
    context_keys text[];
    context_organization_id uuid;
    context_demand_id uuid;
    context_demand_version_id uuid;
    context_taxonomy_bundle_id uuid;
    context_currency text;
    context_minimum_amount bigint;
    context_maximum_amount bigint;
    context_allowed_regions jsonb;
    context_required_languages jsonb;
    context_required_work_mode text;
    context_sensitivity text;
    context_ai_use text;
    existing profile.derived_match_capture_receipts%ROWTYPE;
    eligible_candidate_count integer;
    candidate_profile_ids uuid[] := ARRAY[]::uuid[];
    candidate_facts jsonb := '[]'::jsonb;
    candidate_count_local integer := 0;
    candidate record;
    iam_fact record;
    iam_row_found boolean;
    captured_at_local timestamptz;
    authorization_valid_until_local timestamptz;
    allowlist_sha256_local bytea;
    replayed_local boolean := false;
    source record;
    ordinal_local integer;
    content_document jsonb;
    source_evidence_facts_local jsonb;
    source_evidence_set_sha256_local bytea;
    referenced_evidence_count integer;
    bound_evidence_count integer;
    private_floor_evidence_digest_local bytea;
    evidence_version_digest_local bytea;
    derived_document jsonb;
    canonical_derived_bytes_local bytea;
    derived_input_sha256_local bytea;
    iam_json jsonb;
    taxonomy_bundle_sha256_local bytea;
    taxonomy_bundle_version_local bigint;
    snapshot_count integer;
BEGIN
    IF session_user IS DISTINCT FROM 'profile_matcher'
       OR current_user IS DISTINCT FROM 'profile_schema_owner'
       OR current_setting('transaction_isolation') IS DISTINCT FROM
            'repeatable read'
       OR current_setting('transaction_read_only') IS DISTINCT FROM 'off'
       OR exact_match_run_id IS NULL OR exact_match_run_id = zero_uuid
       OR exact_workload_id IS NULL OR exact_workload_id = zero_uuid
       OR exact_authorization_digest IS NULL
       OR octet_length(exact_authorization_digest) <> 32
       OR exact_authorization_digest = zero_digest
       OR exact_demand_match_context_bytes IS NULL
       OR octet_length(exact_demand_match_context_bytes) NOT BETWEEN 1 AND 65536
       OR exact_demand_match_context_sha256 IS NULL
       OR octet_length(exact_demand_match_context_sha256) <> 32
       OR pg_catalog.sha256(exact_demand_match_context_bytes)
            IS DISTINCT FROM exact_demand_match_context_sha256
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'PROFILE_MATCH_DERIVATION'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'CAPTURE_DERIVED_MATCH_INPUTS'
       OR NULLIF(current_setting('app.match_run_id', true), '')::uuid
            IS DISTINCT FROM exact_match_run_id
       OR NULLIF(current_setting('app.workload_id', true), '')::uuid
            IS DISTINCT FROM exact_workload_id
       OR decode(NULLIF(current_setting('app.authorization_digest', true), ''),
            'hex') IS DISTINCT FROM exact_authorization_digest
       OR decode(NULLIF(current_setting(
            'app.demand_match_context_sha256', true
          ), ''), 'hex') IS DISTINCT FROM exact_demand_match_context_sha256
       OR NOT EXISTS (
            SELECT 1 FROM profile.schema_compatibility AS compatibility
            WHERE compatibility.component = 'profile'
              AND compatibility.current_schema_version = 5
              AND compatibility.schema_head_version = 5
              AND compatibility.min_app_compatible_version = 5
              AND compatibility.max_app_compatible_version = 5
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'Profile derived match capture denied';
    END IF;

    BEGIN
        context_document := pg_catalog.convert_from(
            exact_demand_match_context_bytes, 'UTF8'
        )::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'Demand match context is not canonical UTF-8 JSON';
    END;
    SELECT array_agg(key ORDER BY key COLLATE "C") INTO context_keys
    FROM jsonb_object_keys(context_document) AS item(key);
    IF jsonb_typeof(context_document) IS DISTINCT FROM 'object'
       OR context_keys IS DISTINCT FROM ARRAY[
            'ai_use_code','allowed_region_codes','canonicalization_version',
            'currency','data_sensitivity_code','demand_id','demand_version_id',
            'maximum_amount_minor','minimum_amount_minor','organization_id',
            'required_language_codes','required_work_mode_code','schema_version',
            'taxonomy_bundle_id'
          ]::text[]
       OR context_document->'schema_version' IS DISTINCT FROM '1'::jsonb
       OR context_document->>'canonicalization_version'
            IS DISTINCT FROM 'profile-match-demand-context-json-v1'
       OR pg_catalog.convert_to(
            profile.canonical_json_v1(context_document), 'UTF8'
          ) IS DISTINCT FROM exact_demand_match_context_bytes THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'Demand match context contract is invalid';
    END IF;
    BEGIN
        context_organization_id := (context_document->>'organization_id')::uuid;
        context_demand_id := (context_document->>'demand_id')::uuid;
        context_demand_version_id :=
            (context_document->>'demand_version_id')::uuid;
        context_taxonomy_bundle_id :=
            (context_document->>'taxonomy_bundle_id')::uuid;
        context_minimum_amount :=
            (context_document->>'minimum_amount_minor')::bigint;
        context_maximum_amount :=
            (context_document->>'maximum_amount_minor')::bigint;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'Demand match context scalar is invalid';
    END;
    context_currency := context_document->>'currency';
    context_allowed_regions := context_document->'allowed_region_codes';
    context_required_languages := context_document->'required_language_codes';
    context_required_work_mode := context_document->>'required_work_mode_code';
    context_sensitivity := context_document->>'data_sensitivity_code';
    context_ai_use := context_document->>'ai_use_code';
    IF context_organization_id = zero_uuid
       OR context_demand_id = zero_uuid
       OR context_demand_version_id = zero_uuid
       OR context_taxonomy_bundle_id = zero_uuid
       OR context_document->>'organization_id'
            IS DISTINCT FROM context_organization_id::text
       OR context_document->>'demand_id' IS DISTINCT FROM context_demand_id::text
       OR context_document->>'demand_version_id'
            IS DISTINCT FROM context_demand_version_id::text
       OR context_document->>'taxonomy_bundle_id'
            IS DISTINCT FROM context_taxonomy_bundle_id::text
       OR context_currency !~ '^[A-Z]{3}$'
       OR context_minimum_amount NOT BETWEEN 0 AND 9007199254740991
       OR context_maximum_amount NOT BETWEEN 0 AND 9007199254740991
       OR context_minimum_amount > context_maximum_amount
       OR jsonb_typeof(context_allowed_regions) IS DISTINCT FROM 'array'
       OR jsonb_typeof(context_required_languages) IS DISTINCT FROM 'array'
       OR jsonb_array_length(context_allowed_regions) > 100
       OR jsonb_array_length(context_required_languages) > 100
       OR context_required_work_mode !~ '^[A-Z][A-Z0-9_.:-]{1,63}$'
       OR context_sensitivity NOT IN ('PUBLIC','INTERNAL','HIGH','RESTRICTED')
       OR context_ai_use NOT IN ('PROHIBITED','OPTIONAL','REQUIRED')
       OR EXISTS (
            SELECT 1 FROM jsonb_array_elements_text(context_allowed_regions)
                WITH ORDINALITY AS code(value, ordinal)
            WHERE code.value !~ '^[A-Z][A-Z0-9_.:-]{1,63}$'
               OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text(context_allowed_regions)
                        WITH ORDINALITY AS prior(value, ordinal)
                    WHERE prior.ordinal < code.ordinal
                      AND prior.value >= code.value COLLATE "C"
               )
       )
       OR EXISTS (
            SELECT 1 FROM jsonb_array_elements_text(context_required_languages)
                WITH ORDINALITY AS code(value, ordinal)
            WHERE code.value !~ '^[A-Z][A-Z0-9_.:-]{1,63}$'
               OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text(context_required_languages)
                        WITH ORDINALITY AS prior(value, ordinal)
                    WHERE prior.ordinal < code.ordinal
                      AND prior.value >= code.value COLLATE "C"
               )
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'Demand match context value is invalid';
    END IF;
    PERFORM pg_catalog.set_config(
        'app.profile_match_taxonomy_bundle_id',
        context_taxonomy_bundle_id::text,
        true
    );

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'profile-derived-match-run:' || exact_match_run_id::text, 0
    ));
    SELECT receipt.* INTO existing
    FROM profile.derived_match_capture_receipts AS receipt
    WHERE receipt.match_run_id = exact_match_run_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing.match_run_id IS DISTINCT FROM exact_match_run_id
           OR existing.workload_id IS DISTINCT FROM exact_workload_id
           OR existing.authorization_digest
                IS DISTINCT FROM exact_authorization_digest
           OR existing.demand_match_context_sha256
                IS DISTINCT FROM exact_demand_match_context_sha256
           OR existing.demand_match_context_bytes
                IS DISTINCT FROM exact_demand_match_context_bytes
           OR existing.capture_contract_version IS DISTINCT FROM 2
           OR existing.status IS DISTINCT FROM 'COMPLETED' THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'ck_profile_derived_match_capture_binding',
                MESSAGE = 'Profile derived match capture binding mismatch';
        END IF;
        candidate_count_local := existing.candidate_count;
        captured_at_local := existing.captured_at;
        authorization_valid_until_local := existing.authorization_valid_until;
        allowlist_sha256_local := existing.allowlist_sha256;
        replayed_local := true;
    ELSE
        captured_at_local := transaction_timestamp();
        authorization_valid_until_local :=
            captured_at_local + interval '15 minutes';
        SELECT count(*)::integer
          INTO eligible_candidate_count
          FROM profile.creator_profiles AS root
          JOIN profile.profile_versions AS version
            ON version.profile_id = root.id
           AND version.id = root.current_published_version_id
         WHERE root.status = 'ACTIVE'
           AND version.status = 'PUBLISHED'
           AND iam_api.is_creator_match_eligible_v1(root.owner_user_id);
        IF eligible_candidate_count > 500 THEN
            RAISE EXCEPTION USING ERRCODE = '54000',
                MESSAGE = 'Profile derived match candidate ceiling exceeded';
        END IF;
        FOR candidate IN
            SELECT root.id AS profile_id, root.owner_user_id
            FROM profile.creator_profiles AS root
            JOIN profile.profile_versions AS version
              ON version.profile_id = root.id
             AND version.id = root.current_published_version_id
            WHERE root.status = 'ACTIVE' AND version.status = 'PUBLISHED'
            ORDER BY root.id
            FOR SHARE OF root, version
        LOOP
            iam_row_found := false;
            FOR iam_fact IN
                SELECT *
                FROM iam_api.resolve_profile_match_creator_eligibility_v1(
                    candidate.owner_user_id,
                    exact_match_run_id,
                    exact_workload_id,
                    exact_authorization_digest,
                    exact_demand_match_context_sha256
                )
            LOOP
                iam_row_found := true;
                EXIT;
            END LOOP;
            IF NOT iam_row_found THEN
                RAISE EXCEPTION USING ERRCODE = '42501',
                    MESSAGE = 'IAM creator eligibility resolution denied';
            END IF;
            IF iam_fact.candidate_user_id
                    IS DISTINCT FROM candidate.owner_user_id THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'IAM creator eligibility identity drift';
            END IF;
            IF iam_fact.eligible THEN
                IF iam_fact.creator_user_version IS NULL
                   OR iam_fact.creator_grant_id IS NULL
                   OR iam_fact.creator_grant_version IS NULL
                   OR iam_fact.source_invitation_id IS NULL
                   OR iam_fact.source_invitation_version IS NULL
                   OR iam_fact.policy_selector_digest IS NULL
                   OR octet_length(iam_fact.policy_selector_digest) <> 32
                   OR iam_fact.policy_selector_version IS NULL
                   OR iam_fact.policy_bundle_id IS NULL
                   OR iam_fact.policy_bundle_version IS NULL
                   OR iam_fact.required_policy_acceptance_set_sha256 IS NULL
                   OR octet_length(
                        iam_fact.required_policy_acceptance_set_sha256
                      ) <> 32
                   OR iam_fact.eligibility_evidence_sha256 IS NULL
                   OR octet_length(iam_fact.eligibility_evidence_sha256) <> 32
                   OR iam_fact.valid_until IS NULL
                   OR iam_fact.valid_until <= captured_at_local THEN
                    RAISE EXCEPTION USING ERRCODE = '23514',
                        MESSAGE = 'IAM creator eligibility evidence is invalid';
                END IF;
                candidate_count_local := candidate_count_local + 1;
                IF candidate_count_local > 500 THEN
                    RAISE EXCEPTION USING ERRCODE = '54000',
                        MESSAGE = 'Profile match candidate ceiling exceeded';
                END IF;
                candidate_profile_ids := array_append(
                    candidate_profile_ids, candidate.profile_id
                );
                candidate_facts := candidate_facts || jsonb_build_array(
                    jsonb_build_object(
                        'profile_id', candidate.profile_id::text,
                        'creator_user_version', iam_fact.creator_user_version,
                        'creator_grant_id', iam_fact.creator_grant_id::text,
                        'creator_grant_version', iam_fact.creator_grant_version,
                        'source_invitation_id', iam_fact.source_invitation_id::text,
                        'source_invitation_version',
                            iam_fact.source_invitation_version,
                        'policy_selector_digest', encode(
                            iam_fact.policy_selector_digest, 'hex'
                        ),
                        'policy_selector_version',
                            iam_fact.policy_selector_version,
                        'policy_bundle_id', iam_fact.policy_bundle_id::text,
                        'policy_bundle_version', iam_fact.policy_bundle_version,
                        'required_acceptance_set_sha256', encode(
                            iam_fact.required_policy_acceptance_set_sha256, 'hex'
                        ),
                        'eligibility_evidence_sha256', encode(
                            iam_fact.eligibility_evidence_sha256, 'hex'
                        ),
                        'valid_until', iam_fact.valid_until
                    )
                );
                authorization_valid_until_local := LEAST(
                    authorization_valid_until_local, iam_fact.valid_until
                );
            END IF;
        END LOOP;

        allowlist_sha256_local := pg_catalog.sha256(pg_catalog.convert_to(
            'profile-derived-match-allowlist-v1|' ||
            candidate_count_local::text || '|' ||
            COALESCE(array_to_string(candidate_profile_ids, ','), ''),
            'UTF8'
        ));
        INSERT INTO profile.derived_match_capture_receipts (
            match_run_id, workload_id, authorization_digest,
            demand_match_context_bytes, demand_match_context_sha256,
            organization_id, demand_id, demand_version_id, taxonomy_bundle_id,
            capture_contract_version, status, captured_at,
            authorization_valid_until, candidate_count, allowlist_sha256
        ) VALUES (
            exact_match_run_id, exact_workload_id, exact_authorization_digest,
            exact_demand_match_context_bytes, exact_demand_match_context_sha256,
            context_organization_id, context_demand_id,
            context_demand_version_id, context_taxonomy_bundle_id,
            2, 'COMPLETED', captured_at_local,
            authorization_valid_until_local, candidate_count_local,
            allowlist_sha256_local
        );

        FOR source IN
            SELECT listed.ordinal::integer AS ordinal,
                   root.owner_user_id AS creator_user_id,
                   root.id AS profile_id,
                   version.id AS profile_version_id,
                   version.version_no,
                   version.taxonomy_bundle_id,
                   version.schema_version,
                   version.canonicalization_version,
                   version.canonical_content,
                   version.content,
                   version.content_sha256
            FROM unnest(candidate_profile_ids)
                WITH ORDINALITY AS listed(profile_id, ordinal)
            JOIN profile.creator_profiles AS root ON root.id = listed.profile_id
            JOIN profile.profile_versions AS version
              ON version.profile_id = root.id
             AND version.id = root.current_published_version_id
            ORDER BY listed.ordinal
        LOOP
            ordinal_local := source.ordinal;
            PERFORM pg_catalog.set_config(
                'app.profile_match_candidate_user_id',
                source.creator_user_id::text,
                true
            );
            PERFORM pg_catalog.set_config(
                'app.profile_match_candidate_profile_id',
                source.profile_id::text,
                true
            );
            IF source.schema_version IS DISTINCT FROM 1
               OR source.canonicalization_version
                    IS DISTINCT FROM 'profile-version-json-v1'
               OR source.taxonomy_bundle_id
                    IS DISTINCT FROM context_taxonomy_bundle_id
               OR pg_catalog.sha256(source.canonical_content)
                    IS DISTINCT FROM source.content_sha256
               OR pg_catalog.convert_from(
                    source.canonical_content, 'UTF8'
                  )::jsonb IS DISTINCT FROM source.content THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'ck_profile_derived_match_source',
                    MESSAGE = 'Profile derived source is invalid';
            END IF;
            content_document := source.content->'content';
            IF jsonb_typeof(content_document) IS DISTINCT FROM 'object' THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'ck_profile_derived_match_source',
                    MESSAGE = 'Profile derived content is invalid';
            END IF;
            SELECT marker.bundle_sha256, marker.aggregate_version
            INTO taxonomy_bundle_sha256_local, taxonomy_bundle_version_local
            FROM profile.taxonomy_bundle_markers AS marker
            WHERE marker.id = source.taxonomy_bundle_id
              AND marker.status = 'ACTIVE';
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'ck_profile_derived_taxonomy_binding',
                    MESSAGE = 'Profile derived taxonomy binding is invalid';
            END IF;

            SELECT COALESCE(jsonb_agg(jsonb_build_object(
                'evidence_id', snapshot.evidence_id::text,
                'snapshot_version', snapshot.evidence_version,
                'snapshot_status', snapshot.safe_status,
                'snapshot_sha256', encode(snapshot.evidence_sha256, 'hex'),
                'current_version', evidence.aggregate_version,
                'current_status', evidence.status,
                'current_sha256', encode(evidence.evidence_sha256, 'hex'),
                'verified_at', evidence.verified_at,
                'expires_at', evidence.expires_at
            ) ORDER BY snapshot.evidence_id), '[]'::jsonb)
            INTO source_evidence_facts_local
            FROM profile.profile_version_evidence AS snapshot
            JOIN profile.capability_evidence AS evidence
              ON evidence.id = snapshot.evidence_id
             AND evidence.owner_user_id = source.creator_user_id
            WHERE snapshot.profile_id = source.profile_id
              AND snapshot.profile_version_id = source.profile_version_id;
            source_evidence_set_sha256_local := pg_catalog.sha256(
                pg_catalog.convert_to(
                    'profile-source-evidence-set-v1|' ||
                    profile.canonical_json_v1(source_evidence_facts_local),
                    'UTF8'
                )
            );
            SELECT count(DISTINCT (item.value #>> '{}')::uuid)
            INTO referenced_evidence_count
            FROM jsonb_path_query(
                content_document, 'strict $.**.evidence_ids[*]'
            ) AS item(value);
            SELECT count(DISTINCT snapshot.evidence_id)
            INTO bound_evidence_count
            FROM profile.profile_version_evidence AS snapshot
            JOIN profile.capability_evidence AS evidence
              ON evidence.id = snapshot.evidence_id
             AND evidence.owner_user_id = source.creator_user_id
            WHERE snapshot.profile_id = source.profile_id
              AND snapshot.profile_version_id = source.profile_version_id
              AND snapshot.evidence_id IN (
                    SELECT DISTINCT (item.value #>> '{}')::uuid
                    FROM jsonb_path_query(
                        content_document, 'strict $.**.evidence_ids[*]'
                    ) AS item(value)
              );
            IF referenced_evidence_count IS DISTINCT FROM bound_evidence_count THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'ck_profile_derived_evidence_binding',
                    MESSAGE = 'Profile evidence binding is incomplete';
            END IF;

            SELECT fact.value INTO iam_json
            FROM jsonb_array_elements(candidate_facts) AS fact(value)
            WHERE fact.value->>'profile_id' = source.profile_id::text;
            IF iam_json IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'Profile IAM capture fact is missing';
            END IF;
            private_floor_evidence_digest_local := pg_catalog.sha256(
                pg_catalog.convert_to(
                    'profile-private-floor-comparison-v1|' ||
                    source.profile_id::text || '|' ||
                    source.profile_version_id::text || '|' ||
                    source.content_sha256::text || '|' ||
                    COALESCE(content_document->'compensation'->>'currency', '') ||
                    '|' || COALESCE(
                        content_document->'compensation'
                            ->>'minimum_project_amount_minor', ''
                    ) || '|' || context_currency || '|' ||
                    context_minimum_amount::text || '|' ||
                    context_maximum_amount::text || '|' ||
                    encode(source_evidence_set_sha256_local, 'hex') || '|' ||
                    encode(exact_demand_match_context_sha256, 'hex'),
                    'UTF8'
                )
            );
            evidence_version_digest_local := pg_catalog.sha256(
                pg_catalog.convert_to(
                    'profile-match-evidence-version-v1|' ||
                    'profile_head=5|derivation_contract=1|' ||
                    'creator_user_id=' || source.creator_user_id::text || '|' ||
                    'profile_id=' || source.profile_id::text || '|' ||
                    'profile_version_id=' || source.profile_version_id::text || '|' ||
                    'profile_content_sha256=' ||
                        encode(source.content_sha256, 'hex') || '|' ||
                    'taxonomy_bundle_id=' || source.taxonomy_bundle_id::text || '|' ||
                    'taxonomy_bundle_version=' ||
                        taxonomy_bundle_version_local::text || '|' ||
                    'taxonomy_bundle_sha256=' ||
                        encode(taxonomy_bundle_sha256_local, 'hex') || '|' ||
                    'iam_creator_user_version=' ||
                        (iam_json->>'creator_user_version') || '|' ||
                    'iam_creator_grant_id=' ||
                        (iam_json->>'creator_grant_id') || '|' ||
                    'iam_creator_grant_version=' ||
                        (iam_json->>'creator_grant_version') || '|' ||
                    'iam_source_invitation_id=' ||
                        (iam_json->>'source_invitation_id') || '|' ||
                    'iam_source_invitation_version=' ||
                        (iam_json->>'source_invitation_version') || '|' ||
                    'iam_policy_selector_digest=' ||
                        (iam_json->>'policy_selector_digest') || '|' ||
                    'iam_policy_selector_version=' ||
                        (iam_json->>'policy_selector_version') || '|' ||
                    'iam_policy_bundle_id=' ||
                        (iam_json->>'policy_bundle_id') || '|' ||
                    'iam_policy_bundle_version=' ||
                        (iam_json->>'policy_bundle_version') || '|' ||
                    'iam_required_acceptance_set_sha256=' ||
                        (iam_json->>'required_acceptance_set_sha256') || '|' ||
                    'iam_eligibility_evidence_sha256=' ||
                        (iam_json->>'eligibility_evidence_sha256') || '|' ||
                    'source_evidence_set_sha256=' ||
                        encode(source_evidence_set_sha256_local, 'hex') || '|' ||
                    'organization_id=' || context_organization_id::text || '|' ||
                    'demand_id=' || context_demand_id::text || '|' ||
                    'demand_version_id=' || context_demand_version_id::text || '|' ||
                    'demand_context_sha256=' ||
                        encode(exact_demand_match_context_sha256, 'hex'),
                    'UTF8'
                )
            );

            SELECT jsonb_build_object(
                'creator_user_id', source.creator_user_id::text,
                'profile_id', source.profile_id::text,
                'profile_version_id', source.profile_version_id::text,
                'profile_content_sha256', encode(source.content_sha256, 'hex'),
                'evidence_version_digest',
                    encode(evidence_version_digest_local, 'hex'),
                'status', 'ACTIVE',
                'interest_problem_type_codes', COALESCE((
                    SELECT jsonb_agg(code ORDER BY code COLLATE "C") FROM (
                        SELECT DISTINCT item->>'problem_code' AS code
                        FROM jsonb_array_elements(
                            content_document->'interests'
                        ) AS interest(item)
                    ) AS codes
                ), '[]'::jsonb),
                'interest_domain_codes', COALESCE((
                    SELECT jsonb_agg(code ORDER BY code COLLATE "C") FROM (
                        SELECT DISTINCT item->>'domain_code' AS code
                        FROM jsonb_array_elements(
                            content_document->'interests'
                        ) AS interest(item)
                    ) AS codes
                ), '[]'::jsonb),
                'interest_task_codes', COALESCE((
                    SELECT jsonb_agg(code ORDER BY code COLLATE "C") FROM (
                        SELECT DISTINCT item->>'task_code' AS code
                        FROM jsonb_array_elements(
                            content_document->'interests'
                        ) AS interest(item)
                    ) AS codes
                ), '[]'::jsonb),
                'interest_intensity', COALESCE((
                    SELECT max((item->>'strength')::integer)
                    FROM jsonb_array_elements(
                        content_document->'interests'
                    ) AS interest(item)
                ), 0),
                'prohibited_domain_codes', COALESCE((
                    SELECT jsonb_agg(code ORDER BY code COLLATE "C") FROM (
                        SELECT DISTINCT item->>'code' AS code
                        FROM jsonb_array_elements(COALESCE(
                            content_document->'boundaries'
                                ->'prohibited_domains', '[]'::jsonb
                        )) AS boundary(item)
                    ) AS codes
                ), '[]'::jsonb),
                'prohibited_task_codes', COALESCE((
                    SELECT jsonb_agg(code ORDER BY code COLLATE "C") FROM (
                        SELECT DISTINCT item->>'code' AS code
                        FROM jsonb_array_elements(COALESCE(
                            content_document->'boundaries'
                                ->'prohibited_tasks', '[]'::jsonb
                        )) AS boundary(item)
                    ) AS codes
                ), '[]'::jsonb),
                'skills', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object(
                        'skill_code', skill.item->>'skill_code',
                        'proficiency_level',
                            (skill.item->>'proficiency')::integer,
                        'evidence_trust_level', CASE
                            WHEN skill.item->>'source_kind' = 'SELF_ASSERTED'
                                THEN 1
                            WHEN skill.item->>'source_kind' = 'VERIFIED_EVIDENCE'
                                 AND jsonb_array_length(
                                    skill.item->'evidence_ids'
                                 ) > 0
                                 AND NOT EXISTS (
                                    SELECT 1
                                    FROM jsonb_array_elements_text(
                                        skill.item->'evidence_ids'
                                    ) AS reference(evidence_id)
                                    JOIN profile.profile_version_evidence AS snap
                                      ON snap.profile_version_id =
                                            source.profile_version_id
                                     AND snap.evidence_id =
                                            reference.evidence_id::uuid
                                    JOIN profile.capability_evidence AS evidence
                                      ON evidence.id = snap.evidence_id
                                    WHERE snap.safe_status <> 'VERIFIED'
                                       OR evidence.status <> 'VERIFIED'
                                       OR evidence.expires_at IS NOT NULL
                                          AND evidence.expires_at
                                                <= captured_at_local
                                 ) THEN 4
                            WHEN skill.item->>'source_kind' = 'VERIFIED_EVIDENCE'
                                 AND jsonb_array_length(
                                    skill.item->'evidence_ids'
                                 ) > 0
                                 AND NOT EXISTS (
                                    SELECT 1
                                    FROM jsonb_array_elements_text(
                                        skill.item->'evidence_ids'
                                    ) AS reference(evidence_id)
                                    JOIN profile.profile_version_evidence AS snap
                                      ON snap.profile_version_id =
                                            source.profile_version_id
                                     AND snap.evidence_id =
                                            reference.evidence_id::uuid
                                    JOIN profile.capability_evidence AS evidence
                                      ON evidence.id = snap.evidence_id
                                    WHERE snap.safe_status IN ('REJECTED','REVOKED')
                                       OR evidence.status IN ('REJECTED','REVOKED')
                                 ) THEN 2
                            ELSE 0 END,
                        'evidence_bucket', CASE
                            WHEN skill.item->>'source_kind' = 'SELF_ASSERTED'
                                THEN 'SELF_ASSERTED'
                            WHEN skill.item->>'source_kind' = 'VERIFIED_EVIDENCE'
                                 AND jsonb_array_length(
                                    skill.item->'evidence_ids'
                                 ) > 0
                                 AND NOT EXISTS (
                                    SELECT 1
                                    FROM jsonb_array_elements_text(
                                        skill.item->'evidence_ids'
                                    ) AS reference(evidence_id)
                                    JOIN profile.profile_version_evidence AS snap
                                      ON snap.profile_version_id =
                                            source.profile_version_id
                                     AND snap.evidence_id =
                                            reference.evidence_id::uuid
                                    JOIN profile.capability_evidence AS evidence
                                      ON evidence.id = snap.evidence_id
                                    WHERE snap.safe_status <> 'VERIFIED'
                                       OR evidence.status <> 'VERIFIED'
                                       OR evidence.expires_at IS NOT NULL
                                          AND evidence.expires_at
                                                <= captured_at_local
                                 ) THEN 'VERIFIED'
                            WHEN skill.item->>'source_kind' = 'VERIFIED_EVIDENCE'
                                 AND jsonb_array_length(
                                    skill.item->'evidence_ids'
                                 ) > 0
                                 AND NOT EXISTS (
                                    SELECT 1
                                    FROM jsonb_array_elements_text(
                                        skill.item->'evidence_ids'
                                    ) AS reference(evidence_id)
                                    JOIN profile.profile_version_evidence AS snap
                                      ON snap.profile_version_id =
                                            source.profile_version_id
                                     AND snap.evidence_id =
                                            reference.evidence_id::uuid
                                    JOIN profile.capability_evidence AS evidence
                                      ON evidence.id = snap.evidence_id
                                    WHERE snap.safe_status IN ('REJECTED','REVOKED')
                                       OR evidence.status IN ('REJECTED','REVOKED')
                                 ) THEN 'DOCUMENTED'
                            ELSE 'NONE' END
                    ) ORDER BY skill.item->>'skill_code' COLLATE "C")
                    FROM jsonb_array_elements(
                        content_document->'skills'
                    ) AS skill(item)
                ), '[]'::jsonb),
                'available_from', COALESCE(
                    content_document->'availability'->>'available_from',
                    '9999-12-31'
                ),
                'available_weekly_hours', COALESCE((
                    content_document->'availability'->>'weekly_hours'
                )::integer, 0),
                'available_duration_weeks', COALESCE((
                    content_document->'availability'->>'duration_weeks'
                )::integer, 0),
                'currency', COALESCE(
                    content_document->'compensation'->>'currency', 'XXX'
                ),
                'within_offered_budget', COALESCE(
                    content_document->'compensation'->>'currency'
                        = context_currency
                    AND (content_document->'compensation'
                            ->>'minimum_project_amount_minor')::bigint
                        <= context_maximum_amount,
                    false
                ),
                'private_floor_evidence_digest',
                    encode(private_floor_evidence_digest_local, 'hex'),
                'allowed_data_sensitivity_codes', CASE
                    WHEN content_document->'boundaries' IS NULL
                      OR content_document->'boundaries' = 'null'::jsonb
                        THEN '[]'::jsonb
                    WHEN content_document->'boundaries'
                            ->'allowed_data_sensitivity'
                            ->>'data_sensitivity' = 'CONFIDENTIAL'
                        THEN '["HIGH"]'::jsonb
                    ELSE jsonb_build_array(content_document->'boundaries'
                        ->'allowed_data_sensitivity'->>'data_sensitivity')
                    END,
                'ai_use_code', CASE
                    WHEN content_document->'ai' IS NULL
                      OR content_document->'ai' = 'null'::jsonb THEN 'OPTIONAL'
                    WHEN NOT (content_document->'ai'->>'allowed')::boolean
                        THEN 'PROHIBITED'
                    WHEN (content_document->'ai'->>'requires_ai')::boolean
                        THEN 'REQUIRED'
                    ELSE 'OPTIONAL' END,
                'language_codes', COALESCE((
                    SELECT jsonb_agg(code ORDER BY code COLLATE "C") FROM (
                        SELECT DISTINCT 'LANGUAGE.' || upper(split_part(
                            item->>'language_code', '-', 1
                        )) AS code
                        FROM jsonb_array_elements(
                            content_document->'collaboration'->'languages'
                        ) AS language(item)
                    ) AS codes
                ), '[]'::jsonb),
                'work_mode_code', COALESCE((
                    SELECT CASE WHEN EXISTS (
                        SELECT 1 FROM jsonb_array_elements(
                            content_document->'collaboration'->'work_modes'
                        ) AS mode(item)
                        WHERE 'WORK_MODE.' || (item->>'work_mode')
                            = context_required_work_mode
                    ) THEN context_required_work_mode ELSE min(
                        'WORK_MODE.' || (item->>'work_mode') COLLATE "C"
                    ) END
                    FROM jsonb_array_elements(
                        content_document->'collaboration'->'work_modes'
                    ) AS mode(item)
                ), 'WORK_MODE.UNSPECIFIED'),
                'region_code', COALESCE(
                    'REGION.' || upper(split_part(
                        content_document->'location'->>'region_code', '-', 1
                    )), 'REGION.UNSPECIFIED'
                ),
                'location_eligible', CASE
                    WHEN content_document->'location' IS NULL
                      OR content_document->'location' = 'null'::jsonb THEN false
                    WHEN jsonb_array_length(context_allowed_regions) = 0 THEN true
                    ELSE context_allowed_regions ? (
                        'REGION.' || upper(split_part(
                            content_document->'location'->>'region_code', '-', 1
                        ))
                    ) END,
                'conflict_of_interest', EXISTS (
                    SELECT 1 FROM jsonb_array_elements(
                        content_document->'conflicts'
                    ) AS conflict(item)
                    WHERE conflict.item->>'organization_id'
                        = context_organization_id::text
                )
            ) INTO derived_document;

            canonical_derived_bytes_local := pg_catalog.convert_to(
                profile.canonical_json_v1(derived_document), 'UTF8'
            );
            derived_input_sha256_local :=
                pg_catalog.sha256(canonical_derived_bytes_local);
            INSERT INTO profile.derived_match_raw_snapshots (
                match_run_id, workload_id, snapshot_ordinal, creator_user_id,
                profile_id, profile_version_id, version_no, taxonomy_bundle_id,
                canonical_profile_version_bytes, profile_content,
                profile_content_sha256, taxonomy_bundle_sha256,
                taxonomy_bundle_version, iam_creator_user_version,
                iam_creator_grant_id, iam_creator_grant_version,
                iam_source_invitation_id, iam_source_invitation_version,
                iam_policy_selector_digest, iam_policy_selector_version,
                iam_policy_bundle_id, iam_policy_bundle_version,
                iam_required_acceptance_set_sha256,
                iam_eligibility_evidence_sha256, source_evidence_facts,
                source_evidence_set_sha256, private_floor_evidence_digest
            ) VALUES (
                exact_match_run_id, exact_workload_id, ordinal_local,
                source.creator_user_id, source.profile_id,
                source.profile_version_id, source.version_no,
                source.taxonomy_bundle_id, source.canonical_content,
                content_document, source.content_sha256,
                taxonomy_bundle_sha256_local, taxonomy_bundle_version_local,
                (iam_json->>'creator_user_version')::bigint,
                (iam_json->>'creator_grant_id')::uuid,
                (iam_json->>'creator_grant_version')::bigint,
                (iam_json->>'source_invitation_id')::uuid,
                (iam_json->>'source_invitation_version')::bigint,
                decode(iam_json->>'policy_selector_digest', 'hex'),
                (iam_json->>'policy_selector_version')::bigint,
                (iam_json->>'policy_bundle_id')::uuid,
                (iam_json->>'policy_bundle_version')::bigint,
                decode(iam_json->>'required_acceptance_set_sha256', 'hex'),
                decode(iam_json->>'eligibility_evidence_sha256', 'hex'),
                source_evidence_facts_local, source_evidence_set_sha256_local,
                private_floor_evidence_digest_local
            );
            INSERT INTO profile.derived_match_input_snapshots (
                match_run_id, workload_id, snapshot_ordinal, profile_id,
                derived_schema_version, derived_canonicalization_version,
                canonical_derived_input_bytes, derived_input,
                derived_input_sha256, evidence_version_digest
            ) VALUES (
                exact_match_run_id, exact_workload_id, ordinal_local,
                source.profile_id, 1, 'profile-match-input-json-v1',
                canonical_derived_bytes_local, derived_document,
                derived_input_sha256_local, evidence_version_digest_local
            );
        END LOOP;
    END IF;

    SELECT count(*) INTO snapshot_count
    FROM profile.derived_match_input_snapshots AS snapshot
    WHERE snapshot.match_run_id = exact_match_run_id
      AND snapshot.workload_id = exact_workload_id;
    IF snapshot_count IS DISTINCT FROM candidate_count_local
       OR allowlist_sha256_local IS DISTINCT FROM pg_catalog.sha256(
            pg_catalog.convert_to(
                'profile-derived-match-allowlist-v1|' ||
                candidate_count_local::text || '|' || COALESCE((
                    SELECT string_agg(raw.profile_id::text, ','
                        ORDER BY raw.snapshot_ordinal)
                    FROM profile.derived_match_raw_snapshots AS raw
                    WHERE raw.match_run_id = exact_match_run_id
                      AND raw.workload_id = exact_workload_id
                ), ''), 'UTF8'
            )
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'ck_profile_derived_match_snapshot_set',
            MESSAGE = 'Profile derived snapshot set drift';
    END IF;

    IF candidate_count_local = 0 THEN
        RETURN QUERY SELECT exact_match_run_id, exact_workload_id, 2,
            'COMPLETED'::text, captured_at_local, 0, allowlist_sha256_local,
            authorization_valid_until_local, replayed_local,
            NULL::integer, NULL::uuid, NULL::uuid, NULL::uuid, NULL::bigint,
            NULL::uuid, NULL::bytea, NULL::jsonb, NULL::bytea, NULL::integer,
            NULL::text, NULL::bytea, NULL::jsonb, NULL::bytea, NULL::bytea;
    ELSE
        RETURN QUERY
        SELECT exact_match_run_id, exact_workload_id, 2, 'COMPLETED'::text,
            captured_at_local, candidate_count_local, allowlist_sha256_local,
            authorization_valid_until_local, replayed_local,
            raw.snapshot_ordinal, raw.creator_user_id, raw.profile_id,
            raw.profile_version_id, raw.version_no, raw.taxonomy_bundle_id,
            raw.canonical_profile_version_bytes, raw.profile_content,
            raw.profile_content_sha256, derived.derived_schema_version,
            derived.derived_canonicalization_version::text,
            derived.canonical_derived_input_bytes, derived.derived_input,
            derived.derived_input_sha256, derived.evidence_version_digest
        FROM profile.derived_match_raw_snapshots AS raw
        JOIN profile.derived_match_input_snapshots AS derived
          ON derived.match_run_id = raw.match_run_id
         AND derived.workload_id = raw.workload_id
         AND derived.profile_id = raw.profile_id
        WHERE raw.match_run_id = exact_match_run_id
          AND raw.workload_id = exact_workload_id
        ORDER BY raw.snapshot_ordinal;
    END IF;
END
$function$;

ALTER FUNCTION profile.canonical_json_v1(jsonb) OWNER TO profile_schema_owner;
ALTER FUNCTION profile_api.discover_and_capture_derived_creator_match_inputs_v1(
    uuid, uuid, bytea, bytea, bytea
) OWNER TO profile_schema_owner;
REVOKE ALL ON FUNCTION profile.canonical_json_v1(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION
profile_api.discover_and_capture_derived_creator_match_inputs_v1(
    uuid, uuid, bytea, bytea, bytea
) FROM PUBLIC;
REVOKE ALL ON profile.derived_match_capture_receipts,
    profile.derived_match_raw_snapshots,
    profile.derived_match_input_snapshots FROM PUBLIC, profile_matcher;
GRANT USAGE ON SCHEMA profile_api TO profile_matcher;
GRANT EXECUTE ON FUNCTION
profile_api.discover_and_capture_derived_creator_match_inputs_v1(
    uuid, uuid, bytea, bytea, bytea
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
            'discover_and_capture_derived_creator_match_inputs_v1'
      AND (
        owner_role.rolname <> 'profile_schema_owner'
        OR NOT procedure.prosecdef
        OR procedure.provolatile <> 'v'
        OR procedure.proparallel <> 'u'
        OR procedure.proconfig IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, profile, iam_api']::text[]
        OR pg_catalog.upper(procedure.prosrc) LIKE '%EXECUTE%'
      );
    IF invalid_count <> 0
       OR NOT pg_catalog.has_function_privilege(
            'profile_matcher',
            'profile_api.discover_and_capture_derived_creator_match_inputs_v1(uuid,uuid,bytea,bytea,bytea)',
            'EXECUTE'
       )
       OR pg_catalog.has_table_privilege(
            'profile_matcher',
            'profile.derived_match_raw_snapshots', 'SELECT'
       )
       OR pg_catalog.has_table_privilege(
            'profile_matcher',
            'profile.derived_match_input_snapshots', 'SELECT'
       )
       OR pg_catalog.has_function_privilege(
            'profile_matcher',
            'iam_api.resolve_profile_match_creator_eligibility_v1(uuid,uuid,uuid,bytea,bytea)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Profile derived match capture security assertion failed';
    END IF;
END
$assert$;
