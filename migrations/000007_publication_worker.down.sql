ALTER TABLE audit_exports
    DROP CONSTRAINT IF EXISTS audit_exports_completion_consistent,
    DROP CONSTRAINT IF EXISTS audit_exports_size_positive,
    DROP CONSTRAINT IF EXISTS audit_exports_sha256_format,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS size_bytes,
    DROP COLUMN IF EXISTS sha256;

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
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

ALTER TABLE catalog_role_documents
    DROP COLUMN IF EXISTS envelope_bytes;

ALTER TABLE catalog_versions
    DROP CONSTRAINT IF EXISTS catalog_versions_publication_attempt_unique,
    DROP CONSTRAINT IF EXISTS catalog_versions_publication_attempt_fk,
    DROP COLUMN IF EXISTS publication_attempt_id;

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
