CREATE TABLE artifacts (
    id UUID PRIMARY KEY,
    sha256 CHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    object_key TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT artifacts_sha256_unique UNIQUE (sha256),
    CONSTRAINT artifacts_object_key_unique UNIQUE (object_key),
    CONSTRAINT artifacts_sha256_format CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT artifacts_size_valid CHECK (size_bytes BETWEEN 1 AND 21474836480),
    CONSTRAINT artifacts_object_key_format CHECK (object_key ~ '^artifacts/sha256/[0-9a-f]{2}/[0-9a-f]{64}$'),
    CONSTRAINT artifacts_object_key_digest_matches CHECK (right(object_key, 64) = sha256),
    CONSTRAINT artifacts_created_by_length CHECK (length(created_by) BETWEEN 1 AND 512)
);

CREATE TABLE artifact_product_bindings (
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    artifact_type TEXT NOT NULL
        CONSTRAINT artifact_bindings_type_format CHECK (artifact_type ~ '^[a-z][a-z0-9._-]{0,63}$'),
    filename TEXT NOT NULL
        CONSTRAINT artifact_bindings_filename_length CHECK (length(filename) BETWEEN 1 AND 255),
    content_type TEXT NOT NULL
        CONSTRAINT artifact_bindings_content_type_length CHECK (length(content_type) BETWEEN 1 AND 255),
    created_by TEXT NOT NULL
        CONSTRAINT artifact_bindings_created_by_length CHECK (length(created_by) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (product_id, artifact_id)
);

CREATE INDEX artifact_bindings_product_time_idx
    ON artifact_product_bindings (product_id, created_at DESC, artifact_id DESC);

CREATE TABLE artifact_uploads (
    id UUID PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    artifact_type TEXT NOT NULL
        CONSTRAINT artifact_uploads_type_format CHECK (artifact_type ~ '^[a-z][a-z0-9._-]{0,63}$'),
    filename TEXT NOT NULL
        CONSTRAINT artifact_uploads_filename_length CHECK (length(filename) BETWEEN 1 AND 255),
    content_type TEXT NOT NULL
        CONSTRAINT artifact_uploads_content_type_length CHECK (length(content_type) BETWEEN 1 AND 255),
    expected_size BIGINT NOT NULL
        CONSTRAINT artifact_uploads_size_valid CHECK (expected_size BETWEEN 1 AND 21474836480),
    expected_sha256 CHAR(64) NOT NULL
        CONSTRAINT artifact_uploads_sha256_format CHECK (expected_sha256 ~ '^[0-9a-f]{64}$'),
    staging_key TEXT NOT NULL UNIQUE
        CONSTRAINT artifact_uploads_staging_key_format CHECK (staging_key ~ '^uploads/[0-9a-f-]{36}$'),
    object_upload_id TEXT NOT NULL
        CONSTRAINT artifact_uploads_object_upload_id_length CHECK (length(object_upload_id) BETWEEN 1 AND 1024),
    status TEXT NOT NULL
        CONSTRAINT artifact_uploads_status_valid CHECK (status IN ('uploading', 'completed', 'quarantined', 'expired')),
    artifact_id UUID REFERENCES artifacts(id) ON DELETE RESTRICT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
        CONSTRAINT artifact_uploads_created_by_length CHECK (length(created_by) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT artifact_uploads_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT artifact_uploads_updated_valid CHECK (updated_at >= created_at),
    CONSTRAINT artifact_uploads_completion_consistent CHECK (
        (status = 'completed' AND artifact_id IS NOT NULL)
        OR (status <> 'completed' AND artifact_id IS NULL)
    )
);

CREATE INDEX artifact_uploads_product_status_expiry_idx
    ON artifact_uploads (product_id, status, expires_at);

CREATE TABLE artifact_upload_parts (
    upload_id UUID NOT NULL REFERENCES artifact_uploads(id) ON DELETE RESTRICT,
    part_number INTEGER NOT NULL
        CONSTRAINT artifact_upload_parts_number_valid CHECK (part_number BETWEEN 1 AND 10000),
    size_bytes BIGINT NOT NULL
        CONSTRAINT artifact_upload_parts_size_valid CHECK (size_bytes BETWEEN 1 AND 268435456),
    sha256 CHAR(64) NOT NULL
        CONSTRAINT artifact_upload_parts_sha256_format CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    etag TEXT NOT NULL
        CONSTRAINT artifact_upload_parts_etag_length CHECK (length(etag) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (upload_id, part_number),
    CONSTRAINT artifact_upload_parts_updated_valid CHECK (updated_at >= created_at)
);

CREATE OR REPLACE FUNCTION reject_immutable_artifact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'verified artifacts and product bindings are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER artifacts_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON artifacts
FOR EACH STATEMENT
EXECUTE FUNCTION reject_immutable_artifact_mutation();

CREATE TRIGGER artifact_product_bindings_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON artifact_product_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION reject_immutable_artifact_mutation();

CREATE OR REPLACE FUNCTION protect_artifact_upload_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.product_id IS DISTINCT FROM NEW.product_id
        OR OLD.artifact_type IS DISTINCT FROM NEW.artifact_type
        OR OLD.filename IS DISTINCT FROM NEW.filename
        OR OLD.content_type IS DISTINCT FROM NEW.content_type
        OR OLD.expected_size IS DISTINCT FROM NEW.expected_size
        OR OLD.expected_sha256 IS DISTINCT FROM NEW.expected_sha256
        OR OLD.staging_key IS DISTINCT FROM NEW.staging_key
        OR OLD.object_upload_id IS DISTINCT FROM NEW.object_upload_id
        OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
        OR OLD.created_by IS DISTINCT FROM NEW.created_by
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'artifact upload request fields are immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'completed' AND ROW(OLD.status, OLD.artifact_id) IS DISTINCT FROM ROW(NEW.status, NEW.artifact_id) THEN
        RAISE EXCEPTION 'completed artifact upload is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IS DISTINCT FROM NEW.status
        AND NOT (OLD.status = 'uploading' AND NEW.status IN ('completed', 'quarantined', 'expired')) THEN
        RAISE EXCEPTION 'invalid artifact upload status transition' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_uploads_protect_transition
BEFORE UPDATE ON artifact_uploads
FOR EACH ROW
EXECUTE FUNCTION protect_artifact_upload_transition();

CREATE OR REPLACE FUNCTION require_uploading_session_for_part()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM artifact_uploads
        WHERE id = NEW.upload_id AND status = 'uploading' AND expires_at > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'artifact upload is not active' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_upload_parts_require_active_upload
BEFORE INSERT OR UPDATE ON artifact_upload_parts
FOR EACH ROW
EXECUTE FUNCTION require_uploading_session_for_part();

REVOKE UPDATE, DELETE, TRUNCATE ON artifacts FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON artifact_product_bindings FROM PUBLIC;
