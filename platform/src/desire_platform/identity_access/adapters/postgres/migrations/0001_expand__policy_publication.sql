CREATE TABLE iam.policy_selectors (
    selector_digest bytea NOT NULL,
    canonicalization_version varchar(64) NOT NULL,
    access_purpose text NOT NULL,
    scope_type text NOT NULL,
    target_role text NOT NULL,
    jurisdiction varchar(32) NOT NULL,
    locale varchar(35) NOT NULL,
    current_bundle_id uuid NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_policy_selectors PRIMARY KEY (selector_digest),
    CONSTRAINT uq_policy_selector_facts UNIQUE (
        access_purpose,
        scope_type,
        target_role,
        jurisdiction,
        locale
    ),
    CONSTRAINT ck_policy_selector_digest CHECK (
        octet_length(selector_digest) = 32
    ),
    CONSTRAINT ck_policy_selector_canonicalization CHECK (
        canonicalization_version = 'policy-selector-json-v1'
    ),
    CONSTRAINT ck_policy_selector_shape CHECK (
        (
            access_purpose = 'CREATOR_ENROLLMENT'
            AND scope_type = 'USER_ROLE'
            AND target_role = 'CREATOR'
        )
        OR
        (
            access_purpose = 'ORGANIZATION_MEMBERSHIP'
            AND scope_type = 'ORGANIZATION_ROLE'
            AND target_role IN ('ORG_ADMIN', 'DEMAND_OWNER')
        )
    ),
    CONSTRAINT ck_policy_selector_jurisdiction CHECK (
        jurisdiction ~ '^[A-Z0-9_-]{2,32}$'
    ),
    CONSTRAINT ck_policy_selector_locale CHECK (
        locale ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
    ),
    CONSTRAINT ck_policy_selector_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_policy_selector_time CHECK (updated_at >= created_at)
);

CREATE TABLE iam.policy_documents (
    id uuid NOT NULL,
    kind text NOT NULL,
    locale varchar(35) NOT NULL,
    semantic_version varchar(64) NOT NULL,
    canonical_body text NOT NULL,
    content_sha256 bytea NOT NULL,
    legal_effect text NOT NULL,
    jurisdiction varchar(32) NOT NULL,
    status text NOT NULL,
    effective_at timestamptz NULL,
    superseded_by_document_id uuid NULL,
    publication_command_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_policy_documents PRIMARY KEY (id),
    CONSTRAINT uq_policy_document_version UNIQUE (
        kind,
        locale,
        semantic_version,
        jurisdiction
    ),
    CONSTRAINT uq_policy_document_id_hash UNIQUE (id, content_sha256),
    CONSTRAINT fk_policy_document_successor FOREIGN KEY (
        superseded_by_document_id
    ) REFERENCES iam.policy_documents (id)
      ON DELETE RESTRICT
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_policy_document_kind CHECK (
        kind IN (
            'TERMS',
            'PRIVACY_NOTICE',
            'COMMUNITY_TRANSACTION_COVENANT',
            'CONSENT_TEXT'
        )
    ),
    CONSTRAINT ck_policy_document_legal_effect CHECK (
        legal_effect IN (
            'NOTICE_ACKNOWLEDGEMENT',
            'CONTRACT_ACCEPTANCE',
            'CONSENT_TEXT'
        )
    ),
    CONSTRAINT ck_policy_document_status CHECK (
        status IN ('DRAFT', 'ACTIVE', 'SUPERSEDED', 'RETIRED')
    ),
    CONSTRAINT ck_policy_document_hash CHECK (
        octet_length(content_sha256) = 32
    ),
    CONSTRAINT ck_policy_document_locale CHECK (
        locale ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
    ),
    CONSTRAINT ck_policy_document_version_text CHECK (
        semantic_version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$'
    ),
    CONSTRAINT ck_policy_document_jurisdiction CHECK (
        jurisdiction ~ '^[A-Z0-9_-]{2,32}$'
    ),
    CONSTRAINT ck_policy_document_body CHECK (length(canonical_body) BETWEEN 1 AND 200000),
    CONSTRAINT ck_policy_document_lifecycle CHECK (
        (
            status = 'DRAFT'
            AND effective_at IS NULL
            AND superseded_by_document_id IS NULL
        )
        OR
        (
            status = 'ACTIVE'
            AND effective_at IS NOT NULL
            AND superseded_by_document_id IS NULL
        )
        OR
        (
            status = 'SUPERSEDED'
            AND effective_at IS NOT NULL
            AND superseded_by_document_id IS NOT NULL
        )
        OR
        (
            status = 'RETIRED'
            AND effective_at IS NOT NULL
        )
    ),
    CONSTRAINT ck_policy_document_not_self_successor CHECK (
        superseded_by_document_id IS NULL OR superseded_by_document_id <> id
    ),
    CONSTRAINT ck_policy_document_time CHECK (updated_at >= created_at)
);

CREATE TABLE iam.policy_bundles (
    id uuid NOT NULL,
    selector_digest bytea NOT NULL,
    status text NOT NULL,
    effective_at timestamptz NULL,
    effective_until timestamptz NULL,
    superseded_by_bundle_id uuid NULL,
    release_manifest_sha256 bytea NOT NULL,
    release_signature bytea NOT NULL,
    release_signing_key_id varchar(64) NOT NULL,
    publication_command_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_policy_bundles PRIMARY KEY (id),
    CONSTRAINT uq_policy_bundle_id_selector UNIQUE (id, selector_digest),
    CONSTRAINT fk_policy_bundle_selector FOREIGN KEY (selector_digest)
        REFERENCES iam.policy_selectors (selector_digest) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_bundle_successor FOREIGN KEY (superseded_by_bundle_id)
        REFERENCES iam.policy_bundles (id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_policy_bundle_selector_digest CHECK (
        octet_length(selector_digest) = 32
    ),
    CONSTRAINT ck_policy_bundle_status CHECK (
        status IN ('DRAFT', 'ACTIVE', 'SUPERSEDED', 'RETIRED')
    ),
    CONSTRAINT ck_policy_bundle_manifest_hash CHECK (
        octet_length(release_manifest_sha256) = 32
    ),
    CONSTRAINT ck_policy_bundle_signature CHECK (
        octet_length(release_signature) > 0
        AND length(release_signing_key_id) > 0
    ),
    CONSTRAINT ck_policy_bundle_lifecycle CHECK (
        (
            status = 'DRAFT'
            AND effective_at IS NULL
            AND effective_until IS NULL
            AND superseded_by_bundle_id IS NULL
        )
        OR
        (
            status = 'ACTIVE'
            AND effective_at IS NOT NULL
            AND effective_until IS NULL
            AND superseded_by_bundle_id IS NULL
        )
        OR
        (
            status = 'SUPERSEDED'
            AND effective_at IS NOT NULL
            AND effective_until IS NOT NULL
            AND effective_until > effective_at
            AND superseded_by_bundle_id IS NOT NULL
        )
        OR
        (
            status = 'RETIRED'
            AND effective_at IS NOT NULL
            AND effective_until IS NOT NULL
            AND effective_until > effective_at
            AND superseded_by_bundle_id IS NULL
        )
    ),
    CONSTRAINT ck_policy_bundle_not_self_successor CHECK (
        superseded_by_bundle_id IS NULL OR superseded_by_bundle_id <> id
    ),
    CONSTRAINT ck_policy_bundle_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_policy_bundle_time CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX ux_policy_bundle_active_selector
    ON iam.policy_bundles (selector_digest)
    WHERE status = 'ACTIVE';

ALTER TABLE iam.policy_selectors
    ADD CONSTRAINT fk_policy_selector_current_bundle
    FOREIGN KEY (current_bundle_id, selector_digest)
    REFERENCES iam.policy_bundles (id, selector_digest)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE iam.policy_bundle_documents (
    bundle_id uuid NOT NULL,
    document_id uuid NOT NULL,
    position smallint NOT NULL,
    required boolean NOT NULL,
    CONSTRAINT pk_policy_bundle_documents PRIMARY KEY (bundle_id, document_id),
    CONSTRAINT uq_policy_bundle_document_position UNIQUE (bundle_id, position),
    CONSTRAINT fk_policy_bundle_document_bundle FOREIGN KEY (bundle_id)
        REFERENCES iam.policy_bundles (id) ON DELETE RESTRICT,
    CONSTRAINT fk_policy_bundle_document_document FOREIGN KEY (document_id)
        REFERENCES iam.policy_documents (id) ON DELETE RESTRICT,
    CONSTRAINT ck_policy_bundle_document_position CHECK (position BETWEEN 1 AND 50)
);

CREATE TABLE iam.consent_offers (
    id uuid NOT NULL,
    bundle_id uuid NOT NULL,
    offer_version bigint NOT NULL,
    purpose text NOT NULL,
    scope_type text NOT NULL,
    scope_derivation text NOT NULL,
    recipient_ref varchar(128) NOT NULL,
    recipient_label varchar(160) NOT NULL,
    document_id uuid NOT NULL,
    document_content_sha256 bytea NOT NULL,
    expiry_rule text NOT NULL,
    expiry_days smallint NULL,
    not_after timestamptz NOT NULL,
    optional boolean NOT NULL,
    canonical_offer_sha256 bytea NOT NULL,
    publication_command_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_consent_offers PRIMARY KEY (id),
    CONSTRAINT uq_consent_offer_id_version UNIQUE (id, offer_version),
    CONSTRAINT uq_consent_offer_bundle_id UNIQUE (bundle_id, id),
    CONSTRAINT fk_consent_offer_bundle FOREIGN KEY (bundle_id)
        REFERENCES iam.policy_bundles (id) ON DELETE RESTRICT,
    CONSTRAINT fk_consent_offer_bundle_document FOREIGN KEY (bundle_id, document_id)
        REFERENCES iam.policy_bundle_documents (bundle_id, document_id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_consent_offer_document_hash FOREIGN KEY (
        document_id,
        document_content_sha256
    ) REFERENCES iam.policy_documents (id, content_sha256) ON DELETE RESTRICT,
    CONSTRAINT ck_consent_offer_version CHECK (offer_version >= 1),
    CONSTRAINT ck_consent_offer_purpose CHECK (
        purpose IN (
            'PILOT_RESEARCH',
            'AI_ASSISTED_PROCESSING',
            'DISCLOSE_PROFILE_FIELDS_TO_PARTY'
        )
    ),
    CONSTRAINT ck_consent_offer_scope CHECK (
        scope_type = 'PLATFORM_PARTICIPATION'
        AND scope_derivation = 'PLATFORM_PARTICIPATION_NULL_SCOPE'
    ),
    CONSTRAINT ck_consent_offer_recipient CHECK (
        length(recipient_ref) > 0 AND length(recipient_label) > 0
    ),
    CONSTRAINT ck_consent_offer_document_hash CHECK (
        octet_length(document_content_sha256) = 32
    ),
    CONSTRAINT ck_consent_offer_expiry CHECK (
        (
            expiry_rule = 'FIXED_NOT_AFTER'
            AND expiry_days IS NULL
        )
        OR
        (
            expiry_rule = 'EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER'
            AND expiry_days = 365
        )
    ),
    CONSTRAINT ck_consent_offer_optional CHECK (optional),
    CONSTRAINT ck_consent_offer_canonical_hash CHECK (
        octet_length(canonical_offer_sha256) = 32
    ),
    CONSTRAINT ck_consent_offer_time CHECK (not_after > created_at)
);

CREATE TABLE iam.consent_offer_data_categories (
    offer_id uuid NOT NULL,
    category text NOT NULL,
    position smallint NOT NULL,
    CONSTRAINT pk_consent_offer_data_categories PRIMARY KEY (offer_id, category),
    CONSTRAINT uq_consent_offer_category_position UNIQUE (offer_id, position),
    CONSTRAINT fk_consent_offer_category_offer FOREIGN KEY (offer_id)
        REFERENCES iam.consent_offers (id) ON DELETE RESTRICT,
    CONSTRAINT ck_consent_offer_category CHECK (
        category IN ('PROFILE', 'MATCHING', 'RESEARCH', 'AI_INPUT', 'CONTACT', 'PROJECT')
    ),
    CONSTRAINT ck_consent_offer_category_position CHECK (position BETWEEN 1 AND 20)
);

CREATE FUNCTION iam.enforce_policy_selector_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.selector_digest IS DISTINCT FROM OLD.selector_digest
       OR NEW.canonicalization_version IS DISTINCT FROM OLD.canonicalization_version
       OR NEW.access_purpose IS DISTINCT FROM OLD.access_purpose
       OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
       OR NEW.target_role IS DISTINCT FROM OLD.target_role
       OR NEW.jurisdiction IS DISTINCT FROM OLD.jurisdiction
       OR NEW.locale IS DISTINCT FROM OLD.locale
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_selector_immutable',
            MESSAGE = 'policy selector is immutable';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_policy_selector_immutable
BEFORE UPDATE ON iam.policy_selectors
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_selector_immutable();

CREATE FUNCTION iam.enforce_policy_document_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_document_immutable',
            MESSAGE = 'policy document history is append only';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_document_immutable',
            MESSAGE = 'policy document identity is immutable';
    END IF;

    IF OLD.status <> 'DRAFT' AND (
        NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.locale IS DISTINCT FROM OLD.locale
        OR NEW.semantic_version IS DISTINCT FROM OLD.semantic_version
        OR NEW.canonical_body IS DISTINCT FROM OLD.canonical_body
        OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
        OR NEW.legal_effect IS DISTINCT FROM OLD.legal_effect
        OR NEW.jurisdiction IS DISTINCT FROM OLD.jurisdiction
        OR NEW.publication_command_id IS DISTINCT FROM OLD.publication_command_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_document_immutable',
            MESSAGE = 'published policy document is immutable';
    END IF;

    IF (OLD.status = 'DRAFT' AND NEW.status NOT IN ('DRAFT', 'ACTIVE', 'RETIRED'))
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'SUPERSEDED', 'RETIRED'))
       OR (OLD.status IN ('SUPERSEDED', 'RETIRED') AND NEW.status <> OLD.status) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_document_state',
            MESSAGE = 'invalid policy document state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_policy_document_immutable
BEFORE UPDATE OR DELETE ON iam.policy_documents
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_document_immutable();

CREATE FUNCTION iam.enforce_policy_bundle_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_bundle_immutable',
            MESSAGE = 'policy bundle history is append only';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_bundle_immutable',
            MESSAGE = 'policy bundle identity is immutable';
    END IF;

    IF OLD.status <> 'DRAFT' AND (
        NEW.selector_digest IS DISTINCT FROM OLD.selector_digest
        OR NEW.release_manifest_sha256 IS DISTINCT FROM OLD.release_manifest_sha256
        OR NEW.release_signature IS DISTINCT FROM OLD.release_signature
        OR NEW.release_signing_key_id IS DISTINCT FROM OLD.release_signing_key_id
        OR NEW.publication_command_id IS DISTINCT FROM OLD.publication_command_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_bundle_immutable',
            MESSAGE = 'published policy bundle is immutable';
    END IF;

    IF NEW.aggregate_version <> OLD.aggregate_version + 1
       OR (OLD.status = 'DRAFT' AND NEW.status NOT IN ('DRAFT', 'ACTIVE', 'RETIRED'))
       OR (OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE', 'SUPERSEDED', 'RETIRED'))
       OR (OLD.status IN ('SUPERSEDED', 'RETIRED') AND NEW.status <> OLD.status) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_bundle_state',
            MESSAGE = 'invalid policy bundle state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER trg_policy_bundle_immutable
BEFORE UPDATE OR DELETE ON iam.policy_bundles
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_bundle_immutable();

CREATE FUNCTION iam.enforce_bundle_artifact_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    affected_bundle_id uuid;
    affected_status text;
BEGIN
    affected_bundle_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.bundle_id ELSE NEW.bundle_id END;
    SELECT status INTO affected_status
    FROM iam.policy_bundles
    WHERE id = affected_bundle_id;

    IF affected_status IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_bundle_artifact_immutable',
            MESSAGE = 'published policy bundle artifacts are immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;

CREATE TRIGGER trg_policy_bundle_document_immutable
BEFORE INSERT OR UPDATE OR DELETE ON iam.policy_bundle_documents
FOR EACH ROW EXECUTE FUNCTION iam.enforce_bundle_artifact_immutable();

CREATE FUNCTION iam.enforce_consent_offer_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    affected_bundle_id uuid;
    affected_status text;
BEGIN
    affected_bundle_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.bundle_id ELSE NEW.bundle_id END;
    SELECT status INTO affected_status
    FROM iam.policy_bundles
    WHERE id = affected_bundle_id;

    IF affected_status IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_offer_immutable',
            MESSAGE = 'published consent offer is immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.id IS DISTINCT FROM OLD.id
        OR NEW.bundle_id IS DISTINCT FROM OLD.bundle_id
        OR NEW.publication_command_id IS DISTINCT FROM OLD.publication_command_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_offer_immutable',
            MESSAGE = 'consent offer identity is immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;

CREATE TRIGGER trg_consent_offer_immutable
BEFORE INSERT OR UPDATE OR DELETE ON iam.consent_offers
FOR EACH ROW EXECUTE FUNCTION iam.enforce_consent_offer_immutable();

CREATE FUNCTION iam.enforce_consent_category_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    affected_offer_id uuid;
    affected_status text;
BEGIN
    affected_offer_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.offer_id ELSE NEW.offer_id END;
    SELECT bundle.status INTO affected_status
    FROM iam.consent_offers AS offer
    JOIN iam.policy_bundles AS bundle ON bundle.id = offer.bundle_id
    WHERE offer.id = affected_offer_id;

    IF affected_status IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_consent_offer_category_immutable',
            MESSAGE = 'published consent categories are immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$function$;

CREATE TRIGGER trg_consent_offer_category_immutable
BEFORE INSERT OR UPDATE OR DELETE ON iam.consent_offer_data_categories
FOR EACH ROW EXECUTE FUNCTION iam.enforce_consent_category_immutable();

CREATE FUNCTION iam.assert_policy_selector_consistent(checked_selector bytea)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    selector_row iam.policy_selectors%ROWTYPE;
    bundle_row iam.policy_bundles%ROWTYPE;
BEGIN
    SELECT * INTO selector_row
    FROM iam.policy_selectors
    WHERE selector_digest = checked_selector;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF selector_row.current_bundle_id IS NULL THEN
        IF EXISTS (
            SELECT 1 FROM iam.policy_bundles
            WHERE selector_digest = checked_selector AND status = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'trg_policy_publication_consistent',
                MESSAGE = 'active bundle has no selector pointer';
        END IF;
        RETURN;
    END IF;

    SELECT * INTO bundle_row
    FROM iam.policy_bundles
    WHERE id = selector_row.current_bundle_id
      AND selector_digest = checked_selector;

    IF NOT FOUND
       OR bundle_row.status <> 'ACTIVE'
       OR bundle_row.effective_at > transaction_timestamp()
       OR bundle_row.effective_until IS NOT NULL
       OR (
            SELECT count(*)
            FROM iam.policy_bundles
            WHERE selector_digest = checked_selector AND status = 'ACTIVE'
       ) <> 1
       OR NOT EXISTS (
            SELECT 1
            FROM iam.policy_bundle_documents
            WHERE bundle_id = selector_row.current_bundle_id AND required
       )
       OR EXISTS (
            SELECT 1
            FROM iam.policy_bundle_documents AS membership
            JOIN iam.policy_documents AS document
              ON document.id = membership.document_id
            WHERE membership.bundle_id = selector_row.current_bundle_id
              AND (
                  document.status <> 'ACTIVE'
                  OR document.locale <> selector_row.locale
                  OR document.jurisdiction <> selector_row.jurisdiction
              )
       )
       OR EXISTS (
            SELECT 1
            FROM iam.consent_offers AS offer
            JOIN iam.policy_documents AS document
              ON document.id = offer.document_id
            WHERE offer.bundle_id = selector_row.current_bundle_id
              AND (
                  offer.publication_command_id <> bundle_row.publication_command_id
                  OR document.legal_effect <> 'CONSENT_TEXT'
              )
       )
       OR EXISTS (
            SELECT 1
            FROM iam.consent_offers AS offer
            WHERE offer.bundle_id = selector_row.current_bundle_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM iam.consent_offer_data_categories AS category
                  WHERE category.offer_id = offer.id
              )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_policy_publication_consistent',
            MESSAGE = 'policy publication is inconsistent';
    END IF;
END
$function$;

CREATE FUNCTION iam.enforce_policy_publication_consistent()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
DECLARE
    checked_selector bytea;
    affected_id uuid;
    selector_item record;
BEGIN
    IF TG_TABLE_NAME = 'policy_selectors' THEN
        checked_selector := CASE WHEN TG_OP = 'DELETE' THEN OLD.selector_digest ELSE NEW.selector_digest END;
        PERFORM iam.assert_policy_selector_consistent(checked_selector);
    ELSIF TG_TABLE_NAME = 'policy_bundles' THEN
        checked_selector := CASE WHEN TG_OP = 'DELETE' THEN OLD.selector_digest ELSE NEW.selector_digest END;
        PERFORM iam.assert_policy_selector_consistent(checked_selector);
        IF TG_OP = 'UPDATE' AND OLD.selector_digest IS DISTINCT FROM NEW.selector_digest THEN
            PERFORM iam.assert_policy_selector_consistent(OLD.selector_digest);
        END IF;
    ELSIF TG_TABLE_NAME = 'policy_bundle_documents' THEN
        affected_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.bundle_id ELSE NEW.bundle_id END;
        SELECT selector_digest INTO checked_selector FROM iam.policy_bundles WHERE id = affected_id;
        PERFORM iam.assert_policy_selector_consistent(checked_selector);
    ELSIF TG_TABLE_NAME = 'consent_offers' THEN
        affected_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.bundle_id ELSE NEW.bundle_id END;
        SELECT selector_digest INTO checked_selector FROM iam.policy_bundles WHERE id = affected_id;
        PERFORM iam.assert_policy_selector_consistent(checked_selector);
    ELSIF TG_TABLE_NAME = 'consent_offer_data_categories' THEN
        affected_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.offer_id ELSE NEW.offer_id END;
        SELECT bundle.selector_digest INTO checked_selector
        FROM iam.consent_offers AS offer
        JOIN iam.policy_bundles AS bundle ON bundle.id = offer.bundle_id
        WHERE offer.id = affected_id;
        PERFORM iam.assert_policy_selector_consistent(checked_selector);
    ELSIF TG_TABLE_NAME = 'policy_documents' THEN
        affected_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        FOR selector_item IN
            SELECT DISTINCT bundle.selector_digest
            FROM iam.policy_bundle_documents AS membership
            JOIN iam.policy_bundles AS bundle ON bundle.id = membership.bundle_id
            WHERE membership.document_id = affected_id
        LOOP
            PERFORM iam.assert_policy_selector_consistent(selector_item.selector_digest);
        END LOOP;
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER trg_policy_publication_consistent
AFTER INSERT OR UPDATE ON iam.policy_selectors
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_publication_consistent();

CREATE CONSTRAINT TRIGGER trg_policy_publication_consistent
AFTER INSERT OR UPDATE OR DELETE ON iam.policy_bundles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_publication_consistent();

CREATE CONSTRAINT TRIGGER trg_policy_publication_consistent
AFTER INSERT OR UPDATE OR DELETE ON iam.policy_documents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_publication_consistent();

CREATE CONSTRAINT TRIGGER trg_policy_publication_consistent
AFTER INSERT OR UPDATE OR DELETE ON iam.policy_bundle_documents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_publication_consistent();

CREATE CONSTRAINT TRIGGER trg_policy_publication_consistent
AFTER INSERT OR UPDATE OR DELETE ON iam.consent_offers
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_publication_consistent();

CREATE CONSTRAINT TRIGGER trg_policy_publication_consistent
AFTER INSERT OR UPDATE OR DELETE ON iam.consent_offer_data_categories
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION iam.enforce_policy_publication_consistent();

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM PUBLIC;
