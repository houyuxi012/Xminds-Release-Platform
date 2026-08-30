ALTER TABLE catalog_versions
    ADD COLUMN publication_attempt_id UUID,
    ADD CONSTRAINT catalog_versions_publication_attempt_fk
        FOREIGN KEY (publication_attempt_id) REFERENCES release_attempts(id) ON DELETE RESTRICT,
    ADD CONSTRAINT catalog_versions_publication_attempt_unique UNIQUE (publication_attempt_id);

ALTER TABLE catalog_role_documents
    ADD COLUMN envelope_bytes BYTEA;

CREATE OR REPLACE FUNCTION protect_catalog_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.publication_attempt_id IS DISTINCT FROM NEW.publication_attempt_id
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

ALTER TABLE audit_exports
    ADD COLUMN sha256 CHAR(64),
    ADD COLUMN size_bytes BIGINT,
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD CONSTRAINT audit_exports_sha256_format CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT audit_exports_size_positive CHECK (size_bytes IS NULL OR size_bytes > 0),
    ADD CONSTRAINT audit_exports_completion_consistent CHECK (
        (status = 'completed' AND length(object_key) > 0 AND sha256 IS NOT NULL AND size_bytes IS NOT NULL AND expires_at IS NOT NULL)
        OR (status <> 'completed' AND object_key = '' AND sha256 IS NULL AND size_bytes IS NULL AND expires_at IS NULL)
    );

CREATE OR REPLACE FUNCTION protect_audit_export_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.product_id IS DISTINCT FROM NEW.product_id
        OR OLD.requested_by IS DISTINCT FROM NEW.requested_by
        OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.filter IS DISTINCT FROM NEW.filter
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'audit export request fields are immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'completed' AND ROW(
        OLD.status, OLD.object_key, OLD.sha256, OLD.size_bytes, OLD.expires_at, OLD.error_code
    ) IS DISTINCT FROM ROW(
        NEW.status, NEW.object_key, NEW.sha256, NEW.size_bytes, NEW.expires_at, NEW.error_code
    ) THEN
        RAISE EXCEPTION 'completed audit export is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IS DISTINCT FROM NEW.status
        AND NOT (OLD.status = 'pending' AND NEW.status IN ('completed', 'failed')) THEN
        RAISE EXCEPTION 'invalid audit export status transition' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = GREATEST(OLD.updated_at, NEW.updated_at, clock_timestamp());
    RETURN NEW;
END;
$$;
