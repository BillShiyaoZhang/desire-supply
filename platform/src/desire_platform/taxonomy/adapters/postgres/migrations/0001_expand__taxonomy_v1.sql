-- Independent Taxonomy PostgreSQL schema v1.

CREATE SCHEMA taxonomy AUTHORIZATION taxonomy_schema_owner;
CREATE SCHEMA taxonomy_api AUTHORIZATION taxonomy_schema_owner;
REVOKE ALL ON SCHEMA taxonomy, taxonomy_api FROM PUBLIC;

CREATE TABLE taxonomy.schema_migrations (
    component text NOT NULL,
    version integer NOT NULL,
    phase text NOT NULL,
    name text NOT NULL,
    checksum_sha256 bytea NOT NULL,
    manifest_sha256 bytea NOT NULL,
    runner_version varchar(96) NOT NULL,
    applied_at timestamptz NOT NULL,
    PRIMARY KEY (component, version),
    CHECK (component = 'taxonomy'),
    CHECK (version >= 1),
    CHECK (phase IN ('expand', 'migrate', 'contract')),
    CHECK (octet_length(checksum_sha256)=32 AND octet_length(manifest_sha256)=32)
);

CREATE TABLE taxonomy.schema_contracts (
    singleton_key boolean PRIMARY KEY CHECK (singleton_key),
    schema_head_version integer NOT NULL CHECK (schema_head_version=1),
    min_app_compatible_version integer NOT NULL CHECK (min_app_compatible_version=1),
    max_app_compatible_version integer NOT NULL CHECK (max_app_compatible_version=1),
    api_contract_sha256 bytea NOT NULL CHECK (octet_length(api_contract_sha256)=32),
    event_contract_sha256 bytea NOT NULL CHECK (octet_length(event_contract_sha256)=32),
    release_contract_sha256 bytea NOT NULL CHECK (octet_length(release_contract_sha256)=32),
    migration_manifest_sha256 bytea NOT NULL CHECK (octet_length(migration_manifest_sha256)=32),
    generated_at timestamptz NOT NULL
);

CREATE VIEW taxonomy.schema_compatibility
WITH (security_barrier=true, security_invoker=true)
AS SELECT
    'taxonomy'::text AS component,
    COALESCE((SELECT max(version) FROM taxonomy.schema_migrations WHERE component='taxonomy'),0)::integer AS current_schema_version,
    c.schema_head_version,
    c.min_app_compatible_version,
    c.max_app_compatible_version,
    c.migration_manifest_sha256
FROM taxonomy.schema_contracts c WHERE c.singleton_key;

CREATE TABLE taxonomy.families (
    family_code varchar(64) PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('ACTIVE','RETIRED')),
    created_at timestamptz NOT NULL
);

CREATE TABLE taxonomy.selectors (
    selector_digest bytea PRIMARY KEY CHECK (octet_length(selector_digest)=32),
    jurisdiction_code varchar(64) NOT NULL,
    locale_set_digest bytea NOT NULL CHECK (octet_length(locale_set_digest)=32),
    semantic_major integer NOT NULL CHECK (semantic_major>=1),
    intended_consumer_set_digest bytea NOT NULL CHECK (octet_length(intended_consumer_set_digest)=32),
    UNIQUE (jurisdiction_code,locale_set_digest,semantic_major,intended_consumer_set_digest)
);

CREATE TABLE taxonomy.bundles (
    bundle_id varchar(128) PRIMARY KEY,
    family_code varchar(64) NOT NULL REFERENCES taxonomy.families(family_code),
    semantic_version varchar(32) NOT NULL,
    selector_digest bytea NOT NULL REFERENCES taxonomy.selectors(selector_digest),
    release_manifest_sha256 bytea NOT NULL CHECK (octet_length(release_manifest_sha256)=32),
    compatibility_level text NOT NULL CHECK (compatibility_level IN ('INITIAL','PATCH_COMPATIBLE','MINOR_COMPATIBLE','MAJOR_BREAKING')),
    status text NOT NULL CHECK (status IN ('ACTIVE','SUPERSEDED','RETIRED')),
    aggregate_version bigint NOT NULL CHECK (aggregate_version>=1),
    predecessor_bundle_id varchar(128) NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    successor_bundle_id varchar(128) NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    effective_at timestamptz NOT NULL,
    effective_until timestamptz NULL,
    retired_reason_code varchar(64) NULL,
    release_json jsonb NOT NULL CHECK (jsonb_typeof(release_json)='object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (effective_until IS NULL OR effective_until>effective_at),
    CHECK (updated_at>=created_at),
    CHECK ((status='ACTIVE' AND successor_bundle_id IS NULL AND retired_reason_code IS NULL) OR
           (status='SUPERSEDED' AND successor_bundle_id IS NOT NULL AND retired_reason_code IS NULL) OR
           (status='RETIRED' AND retired_reason_code IS NOT NULL))
);
CREATE UNIQUE INDEX ux_taxonomy_bundle_manifest ON taxonomy.bundles(release_manifest_sha256);

CREATE TABLE taxonomy.current_bundles (
    selector_digest bytea PRIMARY KEY REFERENCES taxonomy.selectors(selector_digest),
    bundle_id varchar(128) NOT NULL UNIQUE REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    pointer_version bigint NOT NULL CHECK (pointer_version>=1),
    updated_at timestamptz NOT NULL
);

CREATE TABLE taxonomy.release_artifacts (
    bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    artifact_kind text NOT NULL CHECK (artifact_kind IN ('RELEASE','NODES','EDGES','LABELS','CROSSWALK')),
    locale varchar(35) NOT NULL DEFAULT '',
    schema_name varchar(64) NOT NULL,
    item_count integer NOT NULL CHECK (item_count>=0),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256)=32),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes)>0),
    PRIMARY KEY (bundle_id,artifact_kind,locale),
    CHECK ((artifact_kind='LABELS')=(locale<>''))
);

CREATE TABLE taxonomy.nodes (
    bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    code varchar(64) NOT NULL,
    kind varchar(64) NOT NULL,
    definition_code varchar(64) NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE','DEPRECATED')),
    introduced_in_bundle_id varchar(128) NOT NULL,
    deprecated_reason_code varchar(64) NULL,
    replacement_codes jsonb NOT NULL CHECK (jsonb_typeof(replacement_codes)='array'),
    attributes jsonb NOT NULL CHECK (jsonb_typeof(attributes)='array'),
    PRIMARY KEY (bundle_id,code)
);

CREATE TABLE taxonomy.code_registry (
    family_code varchar(64) NOT NULL REFERENCES taxonomy.families(family_code),
    code varchar(64) NOT NULL,
    kind varchar(64) NOT NULL,
    definition_code varchar(64) NOT NULL,
    attributes_sha256 bytea NOT NULL CHECK (octet_length(attributes_sha256)=32),
    PRIMARY KEY (family_code,code)
);

CREATE TABLE taxonomy.edges (
    bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    edge_kind varchar(64) NOT NULL,
    from_code varchar(64) NOT NULL,
    to_code varchar(64) NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal>=0),
    PRIMARY KEY (bundle_id,edge_kind,from_code,to_code,ordinal),
    FOREIGN KEY (bundle_id,from_code) REFERENCES taxonomy.nodes(bundle_id,code) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (bundle_id,to_code) REFERENCES taxonomy.nodes(bundle_id,code) DEFERRABLE INITIALLY DEFERRED,
    CHECK (from_code<>to_code)
);
CREATE UNIQUE INDEX ux_taxonomy_edge_identity ON taxonomy.edges(bundle_id,edge_kind,from_code,to_code);

CREATE TABLE taxonomy.labels (
    bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    code varchar(64) NOT NULL,
    locale varchar(35) NOT NULL,
    short_label varchar(768) NOT NULL,
    description varchar(6144) NULL,
    accessibility_label varchar(768) NULL,
    PRIMARY KEY (bundle_id,code,locale),
    FOREIGN KEY (bundle_id,code) REFERENCES taxonomy.nodes(bundle_id,code) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE taxonomy.crosswalks (
    crosswalk_id varchar(128) PRIMARY KEY,
    source_bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    target_bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id) DEFERRABLE INITIALLY DEFERRED,
    compatibility_level text NOT NULL CHECK (compatibility_level IN ('PATCH_COMPATIBLE','MINOR_COMPATIBLE','MAJOR_BREAKING')),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256)=32),
    mappings jsonb NOT NULL CHECK (jsonb_typeof(mappings)='array'),
    UNIQUE(source_bundle_id,target_bundle_id)
);

CREATE TABLE taxonomy.signature_evidence (
    signature_receipt_id varchar(128) PRIMARY KEY,
    trust_record_id varchar(128) NOT NULL,
    signing_key_id varchar(128) NOT NULL,
    algorithm text NOT NULL CHECK (algorithm='ED25519'),
    release_manifest_sha256 bytea NOT NULL CHECK (octet_length(release_manifest_sha256)=32),
    verified_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until>verified_at)
);

CREATE TABLE taxonomy.trust_evidence (
    trust_record_id varchar(128) PRIMARY KEY,
    signing_key_id varchar(128) NOT NULL,
    trust_status text NOT NULL CHECK (trust_status IN ('ACTIVE','REVOKED')),
    algorithm text NOT NULL CHECK (algorithm='ED25519'),
    release_manifest_sha256 bytea NOT NULL CHECK (octet_length(release_manifest_sha256)=32),
    valid_until timestamptz NOT NULL
);

CREATE TABLE taxonomy.review_approvals (
    approval_id varchar(128) PRIMARY KEY,
    duty_code text NOT NULL CHECK (duty_code IN ('DOMAIN_STEWARD','SAFETY_DATA_STEWARD')),
    reviewer_id varchar(128) NOT NULL,
    approval_status text NOT NULL CHECK (approval_status IN ('APPROVED','REVOKED')),
    release_manifest_sha256 bytea NOT NULL CHECK (octet_length(release_manifest_sha256)=32),
    golden_result_sha256 bytea NOT NULL CHECK (octet_length(golden_result_sha256)=32),
    approved_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until>approved_at)
);

CREATE TABLE taxonomy.command_receipts (
    identity_digest bytea PRIMARY KEY CHECK (octet_length(identity_digest)=32),
    identity_key_id varchar(128) NOT NULL,
    payload_hash_key_id varchar(128) NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest)=32),
    principal_id varchar(128) NOT NULL,
    operation varchar(64) NOT NULL,
    canonicalization_version varchar(64) NOT NULL CHECK (canonicalization_version='taxonomy-command-json-v1'),
    command_version integer NOT NULL CHECK (command_version=1),
    status text NOT NULL CHECK (status IN ('PENDING','COMPLETED')),
    target_id varchar(128) NULL,
    target_status varchar(32) NULL,
    target_version bigint NULL,
    safe_response jsonb NULL,
    retained_until timestamptz NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CHECK ((status='PENDING' AND safe_response IS NULL AND completed_at IS NULL) OR
           (status='COMPLETED' AND safe_response IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE TABLE taxonomy.audit_log (
    audit_id varchar(128) PRIMARY KEY,
    operation varchar(64) NOT NULL,
    actor_id varchar(128) NOT NULL,
    target_id varchar(128) NOT NULL,
    result varchar(64) NOT NULL,
    evidence_sha256 bytea NOT NULL CHECK (octet_length(evidence_sha256)=32),
    correlation_id varchar(128) NOT NULL,
    causation_id varchar(128) NOT NULL,
    trace_id varchar(128) NOT NULL,
    occurred_at timestamptz NOT NULL
);

CREATE TABLE taxonomy.outbox_events (
    event_id varchar(128) PRIMARY KEY,
    aggregate_id varchar(128) NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version>=1),
    event_type varchar(64) NOT NULL,
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope)='object'),
    occurred_at timestamptz NOT NULL
);

CREATE TABLE taxonomy.consumer_inbox (
    event_id varchar(128) PRIMARY KEY,
    event_sha256 bytea NOT NULL CHECK (octet_length(event_sha256)=32),
    consumer_code varchar(64) NOT NULL,
    status text NOT NULL CHECK (status IN ('PENDING','COMPLETED')),
    safe_response jsonb NULL,
    received_at timestamptz NOT NULL,
    completed_at timestamptz NULL
);

CREATE TABLE taxonomy.consumer_authorizations (
    authorization_digest bytea PRIMARY KEY CHECK (octet_length(authorization_digest)=32),
    consumer_code varchar(64) NOT NULL CHECK (consumer_code IN ('PROFILE','DEMAND','MATCHING')),
    consumer_job_id varchar(128) NOT NULL,
    workload_principal_id varchar(128) NOT NULL,
    bundle_id varchar(128) NOT NULL REFERENCES taxonomy.bundles(bundle_id),
    release_manifest_sha256 bytea NOT NULL CHECK (octet_length(release_manifest_sha256)=32),
    credential_sha256 bytea NOT NULL CHECK (octet_length(credential_sha256)=32),
    attestation_sha256 bytea NOT NULL CHECK (octet_length(attestation_sha256)=32),
    valid_until timestamptz NOT NULL,
    UNIQUE (consumer_code,consumer_job_id,bundle_id)
);

CREATE TABLE taxonomy.workload_authorizations (
    workload_principal_id varchar(128) NOT NULL,
    operation varchar(64) NOT NULL CHECK (operation IN ('PublishTaxonomyBundle','RetireTaxonomyBundle')),
    credential_sha256 bytea NOT NULL CHECK (octet_length(credential_sha256)=32),
    attestation_sha256 bytea NOT NULL CHECK (octet_length(attestation_sha256)=32),
    status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
    valid_until timestamptz NOT NULL,
    PRIMARY KEY (workload_principal_id,operation)
);

CREATE FUNCTION taxonomy.prevent_immutable_change_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,taxonomy AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable taxonomy release fact';
END;
$$;

CREATE TRIGGER trg_taxonomy_artifact_immutable BEFORE UPDATE OR DELETE ON taxonomy.release_artifacts FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_node_immutable BEFORE UPDATE OR DELETE ON taxonomy.nodes FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_edge_immutable BEFORE UPDATE OR DELETE ON taxonomy.edges FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_label_immutable BEFORE UPDATE OR DELETE ON taxonomy.labels FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_crosswalk_immutable BEFORE UPDATE OR DELETE ON taxonomy.crosswalks FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_signature_immutable BEFORE UPDATE OR DELETE ON taxonomy.signature_evidence FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_trust_immutable BEFORE UPDATE OR DELETE ON taxonomy.trust_evidence FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_approval_immutable BEFORE UPDATE OR DELETE ON taxonomy.review_approvals FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_code_registry_immutable BEFORE UPDATE OR DELETE ON taxonomy.code_registry FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_audit_immutable BEFORE UPDATE OR DELETE ON taxonomy.audit_log FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();
CREATE TRIGGER trg_taxonomy_outbox_immutable BEFORE UPDATE OR DELETE ON taxonomy.outbox_events FOR EACH ROW EXECUTE FUNCTION taxonomy.prevent_immutable_change_v1();

CREATE FUNCTION taxonomy.validate_current_bundle_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,taxonomy AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM taxonomy.bundles b
        WHERE b.bundle_id=NEW.bundle_id
          AND b.selector_digest=NEW.selector_digest
          AND b.status='ACTIVE'
          AND b.effective_at<=transaction_timestamp()
          AND (b.effective_until IS NULL OR transaction_timestamp()<b.effective_until)
    ) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='invalid taxonomy current bundle';
    END IF;
    IF (SELECT count(*) FROM taxonomy.release_artifacts a
        WHERE a.bundle_id=NEW.bundle_id AND a.artifact_kind IN ('RELEASE','NODES','EDGES'))<>3
       OR EXISTS (
           SELECT 1 FROM taxonomy.release_artifacts a
           WHERE a.bundle_id=NEW.bundle_id AND (
               (a.artifact_kind='RELEASE' AND a.item_count<>1) OR
               (a.artifact_kind='NODES' AND a.item_count<>(SELECT count(*) FROM taxonomy.nodes n WHERE n.bundle_id=NEW.bundle_id)) OR
               (a.artifact_kind='EDGES' AND a.item_count<>(SELECT count(*) FROM taxonomy.edges e WHERE e.bundle_id=NEW.bundle_id)) OR
               (a.artifact_kind='LABELS' AND (
                   a.item_count<>(SELECT count(*) FROM taxonomy.labels l WHERE l.bundle_id=NEW.bundle_id AND l.locale=a.locale)
                   OR a.item_count<>(SELECT count(*) FROM taxonomy.nodes n WHERE n.bundle_id=NEW.bundle_id)
               )) OR
               (a.artifact_kind='CROSSWALK' AND a.item_count<>(
                   SELECT COALESCE(sum(jsonb_array_length(c.mappings)),0)
                   FROM taxonomy.crosswalks c WHERE c.target_bundle_id=NEW.bundle_id
               ))
           )
       )
       OR EXISTS (
           SELECT 1 FROM taxonomy.nodes n
           CROSS JOIN LATERAL jsonb_array_elements_text(n.replacement_codes) replacement(code)
           WHERE n.bundle_id=NEW.bundle_id
             AND NOT EXISTS (
                 SELECT 1 FROM taxonomy.nodes target
                 WHERE target.bundle_id=NEW.bundle_id AND target.code=replacement.code
             )
       ) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='invalid taxonomy release graph';
    END IF;
    IF EXISTS (
        WITH RECURSIVE walk(origin,node,path,cycle) AS (
            SELECT e.from_code::text,e.to_code::text,
                   ARRAY[e.from_code::text,e.to_code::text]::text[],false
            FROM taxonomy.edges e
            WHERE e.bundle_id=NEW.bundle_id
              AND e.edge_kind IN ('BROADER_THAN','NARROWER_THAN','LOCATED_IN')
            UNION ALL
            SELECT w.origin,e.to_code,w.path||e.to_code,e.to_code=ANY(w.path)
            FROM walk w
            JOIN taxonomy.edges e ON e.bundle_id=NEW.bundle_id
             AND e.from_code=w.node
             AND e.edge_kind IN ('BROADER_THAN','NARROWER_THAN','LOCATED_IN')
            WHERE NOT w.cycle
        ) SELECT 1 FROM walk WHERE cycle
    ) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='cyclic taxonomy release graph';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_taxonomy_current_validate BEFORE INSERT OR UPDATE ON taxonomy.current_bundles FOR EACH ROW EXECUTE FUNCTION taxonomy.validate_current_bundle_v1();

CREATE FUNCTION taxonomy.consumer_bundle_allowed_v1(p_bundle_id text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER
SET search_path=pg_catalog,taxonomy AS $$
    SELECT EXISTS (
        SELECT 1 FROM taxonomy.consumer_authorizations a
        WHERE a.authorization_digest=decode(current_setting('app.consumer_authorization_digest',true),'hex')
          AND a.consumer_code=current_setting('app.consumer_code',true)
          AND a.consumer_job_id=current_setting('app.consumer_job_id',true)
          AND a.workload_principal_id=current_setting('app.workload_principal_id',true)
          AND a.bundle_id=p_bundle_id
          AND transaction_timestamp()<a.valid_until
    )
$$;

-- Every Taxonomy table, including the independent ledger, is FORCE RLS.
ALTER TABLE taxonomy.schema_migrations ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.schema_migrations FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.schema_contracts ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.schema_contracts FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.families ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.families FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.selectors ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.selectors FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.bundles ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.current_bundles ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.current_bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.release_artifacts ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.release_artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.nodes ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.nodes FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.code_registry ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.code_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.edges ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.edges FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.labels ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.labels FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.crosswalks ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.crosswalks FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.signature_evidence ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.signature_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.trust_evidence ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.trust_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.review_approvals ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.review_approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.command_receipts ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.command_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.audit_log ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.audit_log FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.outbox_events ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.outbox_events FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.consumer_inbox ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.consumer_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.consumer_authorizations ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.consumer_authorizations FORCE ROW LEVEL SECURITY;
ALTER TABLE taxonomy.workload_authorizations ENABLE ROW LEVEL SECURITY; ALTER TABLE taxonomy.workload_authorizations FORCE ROW LEVEL SECURITY;

-- Owner maintenance policy is still constrained by FORCE RLS and session_user.
CREATE POLICY taxonomy_owner_schema_migrations ON taxonomy.schema_migrations FOR ALL TO taxonomy_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY taxonomy_owner_schema_contracts ON taxonomy.schema_contracts FOR ALL TO taxonomy_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY taxonomy_online_schema_migrations ON taxonomy.schema_migrations FOR SELECT TO taxonomy_publisher,taxonomy_admin,taxonomy_reader,taxonomy_consumer USING (session_user=current_user AND current_user IN ('taxonomy_publisher','taxonomy_admin','taxonomy_reader','taxonomy_consumer'));
CREATE POLICY taxonomy_online_schema_contracts ON taxonomy.schema_contracts FOR SELECT TO taxonomy_publisher,taxonomy_admin,taxonomy_reader,taxonomy_consumer USING (session_user=current_user AND current_user IN ('taxonomy_publisher','taxonomy_admin','taxonomy_reader','taxonomy_consumer'));

CREATE POLICY taxonomy_owner_workload ON taxonomy.workload_authorizations FOR SELECT TO PUBLIC USING (current_user='taxonomy_schema_owner' AND session_user IN ('taxonomy_publisher','taxonomy_admin'));
CREATE POLICY taxonomy_owner_workload_lock ON taxonomy.workload_authorizations FOR UPDATE TO PUBLIC USING (current_user='taxonomy_schema_owner' AND session_user IN ('taxonomy_publisher','taxonomy_admin'));

CREATE POLICY taxonomy_publisher_families ON taxonomy.families FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_selectors ON taxonomy.selectors FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_bundles ON taxonomy.bundles FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_admin_bundles ON taxonomy.bundles FOR ALL TO taxonomy_admin USING (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle');
CREATE POLICY taxonomy_publisher_current ON taxonomy.current_bundles FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_admin_current ON taxonomy.current_bundles FOR ALL TO taxonomy_admin USING (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle');

CREATE POLICY taxonomy_publisher_artifacts ON taxonomy.release_artifacts FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_nodes ON taxonomy.nodes FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_codes ON taxonomy.code_registry FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_edges ON taxonomy.edges FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_labels ON taxonomy.labels FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_crosswalks ON taxonomy.crosswalks FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_signature ON taxonomy.signature_evidence FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_trust ON taxonomy.trust_evidence FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');
CREATE POLICY taxonomy_publisher_approval ON taxonomy.review_approvals FOR ALL TO taxonomy_publisher USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle') WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle');

CREATE POLICY taxonomy_publisher_receipt ON taxonomy.command_receipts FOR ALL TO taxonomy_publisher USING (session_user='taxonomy_publisher' AND current_user='taxonomy_publisher' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex')) WITH CHECK (session_user='taxonomy_publisher' AND current_user='taxonomy_publisher' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex'));
CREATE POLICY taxonomy_admin_receipt ON taxonomy.command_receipts FOR ALL TO taxonomy_admin USING (session_user='taxonomy_admin' AND current_user='taxonomy_admin' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex')) WITH CHECK (session_user='taxonomy_admin' AND current_user='taxonomy_admin' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex'));
CREATE POLICY taxonomy_publisher_audit ON taxonomy.audit_log FOR ALL TO taxonomy_publisher USING (operation=current_setting('app.taxonomy_operation',true)) WITH CHECK (operation=current_setting('app.taxonomy_operation',true));
CREATE POLICY taxonomy_admin_audit ON taxonomy.audit_log FOR ALL TO taxonomy_admin USING (operation=current_setting('app.taxonomy_operation',true)) WITH CHECK (operation=current_setting('app.taxonomy_operation',true));
CREATE POLICY taxonomy_publisher_outbox ON taxonomy.outbox_events FOR ALL TO taxonomy_publisher USING (true) WITH CHECK (true);
CREATE POLICY taxonomy_admin_outbox ON taxonomy.outbox_events FOR ALL TO taxonomy_admin USING (true) WITH CHECK (true);

CREATE POLICY taxonomy_reader_bundles ON taxonomy.bundles FOR SELECT TO taxonomy_reader USING (session_user='taxonomy_reader' AND current_user='taxonomy_reader' AND current_setting('app.taxonomy_operation',true) IN ('ReadExactTaxonomyBundle','ReadExactTaxonomyNode','ReadExactTaxonomyEdgePair') AND bundle_id=current_setting('app.taxonomy_bundle_id',true) AND status IN ('ACTIVE','SUPERSEDED'));
CREATE POLICY taxonomy_reader_artifacts ON taxonomy.release_artifacts FOR SELECT TO taxonomy_reader USING (session_user='taxonomy_reader' AND current_user='taxonomy_reader' AND current_setting('app.taxonomy_operation',true)='ReadExactTaxonomyBundle' AND bundle_id=current_setting('app.taxonomy_bundle_id',true));
CREATE POLICY taxonomy_reader_nodes ON taxonomy.nodes FOR SELECT TO taxonomy_reader USING (session_user='taxonomy_reader' AND current_user='taxonomy_reader' AND current_setting('app.taxonomy_operation',true)='ReadExactTaxonomyNode' AND bundle_id=current_setting('app.taxonomy_bundle_id',true));
CREATE POLICY taxonomy_reader_edges ON taxonomy.edges FOR SELECT TO taxonomy_reader USING (session_user='taxonomy_reader' AND current_user='taxonomy_reader' AND current_setting('app.taxonomy_operation',true)='ReadExactTaxonomyEdgePair' AND bundle_id=current_setting('app.taxonomy_bundle_id',true));
CREATE POLICY taxonomy_reader_labels ON taxonomy.labels FOR SELECT TO taxonomy_reader USING (session_user='taxonomy_reader' AND current_user='taxonomy_reader' AND current_setting('app.taxonomy_operation',true)='ReadExactTaxonomyNode' AND bundle_id=current_setting('app.taxonomy_bundle_id',true));
CREATE POLICY taxonomy_reader_crosswalks ON taxonomy.crosswalks FOR SELECT TO taxonomy_reader USING (false);

CREATE POLICY taxonomy_consumer_bundles ON taxonomy.bundles FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND bundle_id=current_setting('app.taxonomy_bundle_id',true) AND status IN ('ACTIVE','SUPERSEDED') AND taxonomy.consumer_bundle_allowed_v1(bundle_id));
CREATE POLICY taxonomy_consumer_artifacts ON taxonomy.release_artifacts FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND bundle_id=current_setting('app.taxonomy_bundle_id',true) AND taxonomy.consumer_bundle_allowed_v1(bundle_id));
CREATE POLICY taxonomy_consumer_nodes ON taxonomy.nodes FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND bundle_id=current_setting('app.taxonomy_bundle_id',true) AND taxonomy.consumer_bundle_allowed_v1(bundle_id));
CREATE POLICY taxonomy_consumer_edges ON taxonomy.edges FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND bundle_id=current_setting('app.taxonomy_bundle_id',true) AND taxonomy.consumer_bundle_allowed_v1(bundle_id));
CREATE POLICY taxonomy_consumer_labels ON taxonomy.labels FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND bundle_id=current_setting('app.taxonomy_bundle_id',true) AND taxonomy.consumer_bundle_allowed_v1(bundle_id));
CREATE POLICY taxonomy_consumer_crosswalks ON taxonomy.crosswalks FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND ((source_bundle_id=current_setting('app.taxonomy_bundle_id',true) AND taxonomy.consumer_bundle_allowed_v1(source_bundle_id)) OR (target_bundle_id=current_setting('app.taxonomy_bundle_id',true) AND taxonomy.consumer_bundle_allowed_v1(target_bundle_id))));
CREATE POLICY taxonomy_consumer_authorization ON taxonomy.consumer_authorizations FOR SELECT TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='CaptureTaxonomyConsumerRelease' AND authorization_digest=decode(current_setting('app.consumer_authorization_digest',true),'hex') AND consumer_code=current_setting('app.consumer_code',true) AND consumer_job_id=current_setting('app.consumer_job_id',true) AND workload_principal_id=current_setting('app.workload_principal_id',true) AND credential_sha256=decode(current_setting('app.workload_credential_sha256',true),'hex') AND attestation_sha256=decode(current_setting('app.workload_attestation_sha256',true),'hex') AND transaction_timestamp()<valid_until);
CREATE POLICY taxonomy_consumer_inbox_policy ON taxonomy.consumer_inbox FOR ALL TO taxonomy_consumer USING (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='ClaimTaxonomyConsumerInbox' AND consumer_code=current_setting('app.consumer_code',true)) WITH CHECK (session_user='taxonomy_consumer' AND current_user='taxonomy_consumer' AND current_setting('app.taxonomy_operation',true)='ClaimTaxonomyConsumerInbox' AND consumer_code=current_setting('app.consumer_code',true));

CREATE FUNCTION taxonomy_api.lock_workload_authority_v1(
    p_workload_principal_id text,
    p_operation text,
    p_credential_sha256 bytea,
    p_attestation_sha256 bytea
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,taxonomy AS $$
DECLARE
    allowed boolean := false;
    expected_role text;
BEGIN
    expected_role := CASE p_operation
        WHEN 'PublishTaxonomyBundle' THEN 'taxonomy_publisher'
        WHEN 'RetireTaxonomyBundle' THEN 'taxonomy_admin'
        ELSE NULL
    END;
    IF expected_role IS NULL OR session_user<>expected_role
       OR current_setting('app.taxonomy_operation',true)<>p_operation
       OR current_setting('app.workload_principal_id',true)<>p_workload_principal_id
       OR current_setting('app.workload_credential_sha256',true)<>encode(p_credential_sha256,'hex')
       OR current_setting('app.workload_attestation_sha256',true)<>encode(p_attestation_sha256,'hex') THEN
        RETURN false;
    END IF;
    SELECT true INTO allowed
    FROM taxonomy.workload_authorizations a
    WHERE a.workload_principal_id=p_workload_principal_id
      AND a.operation=p_operation
      AND a.credential_sha256=p_credential_sha256
      AND a.attestation_sha256=p_attestation_sha256
      AND a.status='ACTIVE'
      AND transaction_timestamp()<a.valid_until
    FOR SHARE;
    RETURN COALESCE(allowed,false);
END;
$$;

CREATE FUNCTION taxonomy_api.workload_scope_authorized_v1()
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER
SET search_path=pg_catalog,taxonomy,taxonomy_api AS $$
    SELECT taxonomy_api.lock_workload_authority_v1(
        current_setting('app.workload_principal_id',true),
        current_setting('app.taxonomy_operation',true),
        decode(current_setting('app.workload_credential_sha256',true),'hex'),
        decode(current_setting('app.workload_attestation_sha256',true),'hex')
    )
$$;

ALTER POLICY taxonomy_publisher_families ON taxonomy.families USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_selectors ON taxonomy.selectors USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_bundles ON taxonomy.bundles USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_current ON taxonomy.current_bundles USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_artifacts ON taxonomy.release_artifacts USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_nodes ON taxonomy.nodes USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_codes ON taxonomy.code_registry USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_edges ON taxonomy.edges USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_labels ON taxonomy.labels USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_crosswalks ON taxonomy.crosswalks USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_signature ON taxonomy.signature_evidence USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_trust ON taxonomy.trust_evidence USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_approval ON taxonomy.review_approvals USING (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='PublishTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_receipt ON taxonomy.command_receipts USING (session_user='taxonomy_publisher' AND current_user='taxonomy_publisher' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex') AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (session_user='taxonomy_publisher' AND current_user='taxonomy_publisher' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex') AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_audit ON taxonomy.audit_log USING (operation=current_setting('app.taxonomy_operation',true) AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (operation=current_setting('app.taxonomy_operation',true) AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_publisher_outbox ON taxonomy.outbox_events USING (taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_admin_bundles ON taxonomy.bundles USING (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_admin_current ON taxonomy.current_bundles USING (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (current_setting('app.taxonomy_operation',true)='RetireTaxonomyBundle' AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_admin_receipt ON taxonomy.command_receipts USING (session_user='taxonomy_admin' AND current_user='taxonomy_admin' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex') AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (session_user='taxonomy_admin' AND current_user='taxonomy_admin' AND principal_id=current_setting('app.workload_principal_id',true) AND operation=current_setting('app.taxonomy_operation',true) AND identity_digest=decode(current_setting('app.taxonomy_receipt_identity_digest',true),'hex') AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_admin_audit ON taxonomy.audit_log USING (operation=current_setting('app.taxonomy_operation',true) AND taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (operation=current_setting('app.taxonomy_operation',true) AND taxonomy_api.workload_scope_authorized_v1());
ALTER POLICY taxonomy_admin_outbox ON taxonomy.outbox_events USING (taxonomy_api.workload_scope_authorized_v1()) WITH CHECK (taxonomy_api.workload_scope_authorized_v1());

GRANT USAGE ON SCHEMA taxonomy TO taxonomy_publisher,taxonomy_admin,taxonomy_reader,taxonomy_consumer;
GRANT USAGE ON SCHEMA taxonomy_api TO taxonomy_publisher,taxonomy_admin;
GRANT SELECT ON taxonomy.schema_migrations,taxonomy.schema_contracts TO taxonomy_publisher,taxonomy_admin,taxonomy_reader,taxonomy_consumer;
GRANT SELECT,INSERT ON taxonomy.families,taxonomy.selectors,taxonomy.release_artifacts,taxonomy.nodes,taxonomy.code_registry,taxonomy.edges,taxonomy.labels,taxonomy.crosswalks,taxonomy.signature_evidence,taxonomy.trust_evidence,taxonomy.review_approvals,taxonomy.audit_log,taxonomy.outbox_events TO taxonomy_publisher;
GRANT SELECT,INSERT ON taxonomy.bundles,taxonomy.current_bundles TO taxonomy_publisher;
GRANT UPDATE(status,aggregate_version,successor_bundle_id,updated_at) ON taxonomy.bundles TO taxonomy_publisher;
GRANT UPDATE(bundle_id,pointer_version,updated_at) ON taxonomy.current_bundles TO taxonomy_publisher;
GRANT SELECT,INSERT,UPDATE ON taxonomy.command_receipts TO taxonomy_publisher;
GRANT SELECT ON taxonomy.bundles,taxonomy.current_bundles,taxonomy.command_receipts TO taxonomy_admin;
GRANT INSERT ON taxonomy.command_receipts,taxonomy.audit_log,taxonomy.outbox_events TO taxonomy_admin;
GRANT UPDATE ON taxonomy.command_receipts TO taxonomy_admin;
GRANT UPDATE(status,aggregate_version,retired_reason_code,updated_at) ON taxonomy.bundles TO taxonomy_admin;
GRANT DELETE ON taxonomy.current_bundles TO taxonomy_admin;
GRANT SELECT ON taxonomy.bundles,taxonomy.release_artifacts,taxonomy.nodes,taxonomy.edges,taxonomy.labels,taxonomy.crosswalks TO taxonomy_reader;
GRANT SELECT ON taxonomy.bundles,taxonomy.release_artifacts,taxonomy.nodes,taxonomy.edges,taxonomy.labels,taxonomy.crosswalks,taxonomy.consumer_authorizations TO taxonomy_consumer;
GRANT SELECT,INSERT,UPDATE ON taxonomy.consumer_inbox TO taxonomy_consumer;
GRANT EXECUTE ON FUNCTION taxonomy.consumer_bundle_allowed_v1(text) TO taxonomy_consumer;
GRANT EXECUTE ON FUNCTION taxonomy_api.lock_workload_authority_v1(text,text,bytea,bytea) TO taxonomy_publisher,taxonomy_admin;
GRANT EXECUTE ON FUNCTION taxonomy_api.workload_scope_authorized_v1() TO taxonomy_publisher,taxonomy_admin;

REVOKE ALL ON ALL TABLES IN SCHEMA taxonomy FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA taxonomy FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA taxonomy_api FROM PUBLIC;
