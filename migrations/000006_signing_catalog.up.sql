CREATE TABLE catalog_version_counters (
    product_id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    root_version BIGINT NOT NULL CHECK (root_version >= 1),
    targets_version BIGINT NOT NULL CHECK (targets_version >= 1),
    snapshot_version BIGINT NOT NULL CHECK (snapshot_version >= 1),
    timestamp_version BIGINT NOT NULL CHECK (timestamp_version >= 1),
    revocation_version BIGINT NOT NULL CHECK (revocation_version >= 1),
    PRIMARY KEY (product_id, channel_name),
    CONSTRAINT catalog_version_counters_channel_fk FOREIGN KEY (product_id, channel_name)
        REFERENCES product_channels(product_id, name) ON DELETE RESTRICT
);

CREATE TABLE catalog_versions (
    id UUID PRIMARY KEY,
    product_id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    release_id UUID NOT NULL,
    root_version BIGINT NOT NULL CHECK (root_version >= 1),
    targets_version BIGINT NOT NULL CHECK (targets_version >= 1),
    snapshot_version BIGINT NOT NULL CHECK (snapshot_version >= 1),
    timestamp_version BIGINT NOT NULL CHECK (timestamp_version >= 1),
    revocation_version BIGINT NOT NULL CHECK (revocation_version >= 1),
    bundle_sha256 CHAR(64) NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    CONSTRAINT catalog_versions_product_channel_fk FOREIGN KEY (product_id, channel_name)
        REFERENCES product_channels(product_id, name) ON DELETE RESTRICT,
    CONSTRAINT catalog_versions_release_fk FOREIGN KEY (release_id, product_id)
        REFERENCES releases(id, product_id) ON DELETE RESTRICT,
    CONSTRAINT catalog_versions_id_scope_unique UNIQUE (id, product_id, channel_name),
    CONSTRAINT catalog_versions_targets_monotonic_unique UNIQUE (product_id, channel_name, targets_version),
    CONSTRAINT catalog_versions_snapshot_monotonic_unique UNIQUE (product_id, channel_name, snapshot_version),
    CONSTRAINT catalog_versions_timestamp_monotonic_unique UNIQUE (product_id, channel_name, timestamp_version),
    CONSTRAINT catalog_versions_revocation_monotonic_unique UNIQUE (product_id, channel_name, revocation_version),
    CONSTRAINT catalog_versions_publish_time_valid CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE TABLE catalog_role_documents (
    catalog_version_id UUID NOT NULL REFERENCES catalog_versions(id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('root', 'targets', 'snapshot', 'timestamp', 'revocation')),
    role_version BIGINT NOT NULL CHECK (role_version >= 1),
    envelope_sha256 CHAR(64) NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    object_key TEXT NOT NULL CHECK (
        length(object_key) BETWEEN 1 AND 2048
        AND object_key LIKE 'catalogs/%'
        AND position('..' IN object_key) = 0
        AND position(E'\\' IN object_key) = 0
    ),
    signatures JSONB NOT NULL CHECK (jsonb_typeof(signatures) = 'array' AND jsonb_array_length(signatures) >= 1),
    PRIMARY KEY (catalog_version_id, role)
);

CREATE TABLE catalog_current_pointers (
    product_id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    catalog_version_id UUID NOT NULL,
    switched_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (product_id, channel_name),
    CONSTRAINT catalog_current_pointer_channel_fk FOREIGN KEY (product_id, channel_name)
        REFERENCES product_channels(product_id, name) ON DELETE RESTRICT,
    CONSTRAINT catalog_current_pointer_version_fk FOREIGN KEY (catalog_version_id, product_id, channel_name)
        REFERENCES catalog_versions(id, product_id, channel_name) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION validate_catalog_role_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_version BIGINT;
BEGIN
    SELECT CASE NEW.role
        WHEN 'root' THEN root_version
        WHEN 'targets' THEN targets_version
        WHEN 'snapshot' THEN snapshot_version
        WHEN 'timestamp' THEN timestamp_version
        WHEN 'revocation' THEN revocation_version
    END
    INTO expected_version
    FROM catalog_versions
    WHERE id = NEW.catalog_version_id;
    IF expected_version IS NULL OR expected_version <> NEW.role_version THEN
        RAISE EXCEPTION 'catalog role version does not match catalog version' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER catalog_role_documents_validate_version
BEFORE INSERT ON catalog_role_documents
FOR EACH ROW
EXECUTE FUNCTION validate_catalog_role_version();

CREATE OR REPLACE FUNCTION validate_catalog_current_switch()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate catalog_versions%ROWTYPE;
    previous catalog_versions%ROWTYPE;
    role_count INTEGER;
BEGIN
    SELECT * INTO candidate FROM catalog_versions WHERE id = NEW.catalog_version_id FOR SHARE;
    SELECT count(*) INTO role_count FROM catalog_role_documents WHERE catalog_version_id = NEW.catalog_version_id;
    IF candidate.id IS NULL OR candidate.product_id <> NEW.product_id OR candidate.channel_name <> NEW.channel_name OR role_count <> 5 THEN
        RAISE EXCEPTION 'catalog current pointer requires a complete five-role version' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        SELECT * INTO previous FROM catalog_versions WHERE id = OLD.catalog_version_id FOR SHARE;
        IF candidate.root_version < previous.root_version
            OR candidate.targets_version < previous.targets_version
            OR candidate.snapshot_version < previous.snapshot_version
            OR candidate.timestamp_version < previous.timestamp_version
            OR candidate.revocation_version < previous.revocation_version THEN
            RAISE EXCEPTION 'catalog metadata rollback is forbidden' USING ERRCODE = '55000';
        END IF;
    END IF;
    UPDATE catalog_versions
    SET published_at = NEW.switched_at
    WHERE id = NEW.catalog_version_id AND published_at IS NULL;
    RETURN NEW;
END;
$$;

CREATE TRIGGER catalog_current_pointers_validate_switch
BEFORE INSERT OR UPDATE ON catalog_current_pointers
FOR EACH ROW
EXECUTE FUNCTION validate_catalog_current_switch();

CREATE OR REPLACE FUNCTION reject_catalog_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'catalog signed evidence is immutable' USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION protect_catalog_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.product_id IS DISTINCT FROM NEW.product_id
        OR OLD.channel_name IS DISTINCT FROM NEW.channel_name
        OR OLD.release_id IS DISTINCT FROM NEW.release_id
        OR OLD.root_version IS DISTINCT FROM NEW.root_version
        OR OLD.targets_version IS DISTINCT FROM NEW.targets_version
        OR OLD.snapshot_version IS DISTINCT FROM NEW.snapshot_version
        OR OLD.timestamp_version IS DISTINCT FROM NEW.timestamp_version
        OR OLD.revocation_version IS DISTINCT FROM NEW.revocation_version
        OR OLD.bundle_sha256 IS DISTINCT FROM NEW.bundle_sha256
        OR OLD.created_at IS DISTINCT FROM NEW.created_at
        OR OLD.published_at IS NOT NULL
        OR NEW.published_at IS NULL THEN
        RAISE EXCEPTION 'catalog signed evidence is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER catalog_versions_protect_update
BEFORE UPDATE ON catalog_versions
FOR EACH ROW
EXECUTE FUNCTION protect_catalog_version();

CREATE TRIGGER catalog_versions_reject_delete
BEFORE DELETE OR TRUNCATE ON catalog_versions
FOR EACH STATEMENT
EXECUTE FUNCTION reject_catalog_evidence_mutation();

CREATE TRIGGER catalog_role_documents_reject_update_delete
BEFORE UPDATE OR DELETE OR TRUNCATE ON catalog_role_documents
FOR EACH STATEMENT
EXECUTE FUNCTION reject_catalog_evidence_mutation();

CREATE TRIGGER catalog_current_pointers_reject_delete
BEFORE DELETE OR TRUNCATE ON catalog_current_pointers
FOR EACH STATEMENT
EXECUTE FUNCTION reject_catalog_evidence_mutation();

CREATE TRIGGER catalog_version_counters_reject_delete
BEFORE DELETE OR TRUNCATE ON catalog_version_counters
FOR EACH STATEMENT
EXECUTE FUNCTION reject_catalog_evidence_mutation();

REVOKE DELETE, TRUNCATE ON catalog_version_counters FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON catalog_versions FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON catalog_role_documents FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON catalog_current_pointers FROM PUBLIC;
