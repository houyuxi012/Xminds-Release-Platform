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
    NEW.updated_at = GREATEST(OLD.updated_at, NEW.updated_at, clock_timestamp());
    RETURN NEW;
END;
$$;

CREATE TABLE releases (
    id UUID PRIMARY KEY,
    product_id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    version TEXT NOT NULL
        CONSTRAINT releases_version_length CHECK (length(version) BETWEEN 5 AND 255),
    status TEXT NOT NULL
        CONSTRAINT releases_status_valid CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'PUBLISHING', 'PUBLISHED', 'FAILED')),
    lock_version BIGINT NOT NULL DEFAULT 1
        CONSTRAINT releases_lock_version_positive CHECK (lock_version >= 1),
    release_notes TEXT NOT NULL
        CONSTRAINT releases_notes_length CHECK (octet_length(release_notes) BETWEEN 1 AND 1048576),
    release_notes_sha256 CHAR(64) NOT NULL
        CONSTRAINT releases_notes_sha256_format CHECK (release_notes_sha256 ~ '^[0-9a-f]{64}$'),
    compatibility_bytes BYTEA NOT NULL
        CONSTRAINT releases_compatibility_length CHECK (octet_length(compatibility_bytes) BETWEEN 2 AND 65536),
    compatibility_json JSONB NOT NULL
        CONSTRAINT releases_compatibility_object CHECK (jsonb_typeof(compatibility_json) = 'object'),
    compatibility_sha256 CHAR(64) NOT NULL
        CONSTRAINT releases_compatibility_sha256_format CHECK (compatibility_sha256 ~ '^[0-9a-f]{64}$'),
    source_repository TEXT NOT NULL
        CONSTRAINT releases_source_repository_length CHECK (length(source_repository) BETWEEN 1 AND 2048),
    source_commit_sha TEXT NOT NULL
        CONSTRAINT releases_source_commit_sha_format CHECK (source_commit_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    source_tag TEXT NOT NULL
        CONSTRAINT releases_source_tag_length CHECK (length(source_tag) BETWEEN 1 AND 255),
    source_pipeline_ref TEXT NOT NULL
        CONSTRAINT releases_source_pipeline_length CHECK (length(source_pipeline_ref) BETWEEN 1 AND 512),
    created_by TEXT NOT NULL
        CONSTRAINT releases_created_by_length CHECK (length(created_by) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    submitted_by TEXT,
    submitted_at TIMESTAMPTZ,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    rejected_by TEXT,
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revocation_reason TEXT,
    publication_failure_code TEXT,
    CONSTRAINT releases_product_channel_fk FOREIGN KEY (product_id, channel_name)
        REFERENCES product_channels(product_id, name) ON DELETE RESTRICT,
    CONSTRAINT releases_product_channel_version_unique UNIQUE (product_id, channel_name, version),
    CONSTRAINT releases_id_product_unique UNIQUE (id, product_id),
    CONSTRAINT releases_updated_valid CHECK (updated_at >= created_at),
    CONSTRAINT releases_submission_consistent CHECK (
        (status = 'DRAFT' AND submitted_by IS NULL AND submitted_at IS NULL)
        OR (status <> 'DRAFT' AND submitted_by IS NOT NULL AND submitted_at IS NOT NULL)
    ),
    CONSTRAINT releases_decision_consistent CHECK (
        (status IN ('DRAFT', 'SUBMITTED') AND approved_by IS NULL AND approved_at IS NULL AND rejected_by IS NULL AND rejected_at IS NULL AND rejection_reason IS NULL)
        OR (status = 'REJECTED' AND approved_by IS NULL AND approved_at IS NULL AND rejected_by IS NOT NULL AND rejected_at IS NOT NULL AND length(rejection_reason) BETWEEN 1 AND 2048)
        OR (status IN ('APPROVED', 'PUBLISHING', 'PUBLISHED', 'FAILED') AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND rejected_by IS NULL AND rejected_at IS NULL AND rejection_reason IS NULL)
    ),
    CONSTRAINT releases_revocation_consistent CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
        OR (status = 'PUBLISHED' AND revoked_at IS NOT NULL AND length(revoked_by) BETWEEN 1 AND 512 AND length(revocation_reason) BETWEEN 1 AND 2048)
    )
);

CREATE INDEX releases_product_status_time_idx
    ON releases (product_id, status, updated_at DESC, id DESC);

CREATE TABLE release_artifacts (
    release_id UUID NOT NULL,
    product_id TEXT NOT NULL,
    artifact_id UUID NOT NULL,
    position INTEGER NOT NULL
        CONSTRAINT release_artifacts_position_nonnegative CHECK (position >= 0),
    PRIMARY KEY (release_id, artifact_id),
    CONSTRAINT release_artifacts_position_unique UNIQUE (release_id, position),
    CONSTRAINT release_artifacts_release_fk FOREIGN KEY (release_id, product_id)
        REFERENCES releases(id, product_id) ON DELETE RESTRICT,
    CONSTRAINT release_artifacts_product_binding_fk FOREIGN KEY (product_id, artifact_id)
        REFERENCES artifact_product_bindings(product_id, artifact_id) ON DELETE RESTRICT
);

CREATE TABLE release_attempts (
    id UUID PRIMARY KEY,
    release_id UUID NOT NULL REFERENCES releases(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL
        CONSTRAINT release_attempts_kind_valid CHECK (kind IN ('publish', 'retry', 'revoke')),
    attempt_number INTEGER NOT NULL
        CONSTRAINT release_attempts_number_positive CHECK (attempt_number >= 1),
    idempotency_key TEXT NOT NULL
        CONSTRAINT release_attempts_idempotency_length CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    status TEXT NOT NULL
        CONSTRAINT release_attempts_status_valid CHECK (status IN ('pending', 'succeeded', 'failed')),
    error_code TEXT,
    created_by TEXT NOT NULL
        CONSTRAINT release_attempts_created_by_length CHECK (length(created_by) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT release_attempts_number_unique UNIQUE (release_id, attempt_number),
    CONSTRAINT release_attempts_idempotency_unique UNIQUE (release_id, kind, idempotency_key),
    CONSTRAINT release_attempts_error_consistent CHECK (
        (status = 'failed' AND length(error_code) BETWEEN 1 AND 128)
        OR (status <> 'failed' AND error_code IS NULL)
    ),
    CONSTRAINT release_attempts_updated_valid CHECK (updated_at >= created_at)
);

CREATE INDEX release_attempts_release_time_idx
    ON release_attempts (release_id, attempt_number DESC);

CREATE OR REPLACE FUNCTION protect_release_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.product_id IS DISTINCT FROM NEW.product_id
        OR OLD.channel_name IS DISTINCT FROM NEW.channel_name
        OR OLD.version IS DISTINCT FROM NEW.version
        OR OLD.release_notes IS DISTINCT FROM NEW.release_notes
        OR OLD.release_notes_sha256 IS DISTINCT FROM NEW.release_notes_sha256
        OR OLD.compatibility_bytes IS DISTINCT FROM NEW.compatibility_bytes
        OR OLD.compatibility_json IS DISTINCT FROM NEW.compatibility_json
        OR OLD.compatibility_sha256 IS DISTINCT FROM NEW.compatibility_sha256
        OR OLD.source_repository IS DISTINCT FROM NEW.source_repository
        OR OLD.source_commit_sha IS DISTINCT FROM NEW.source_commit_sha
        OR OLD.source_tag IS DISTINCT FROM NEW.source_tag
        OR OLD.source_pipeline_ref IS DISTINCT FROM NEW.source_pipeline_ref
        OR OLD.created_by IS DISTINCT FROM NEW.created_by
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'release immutable fields cannot change' USING ERRCODE = '55000';
    END IF;
    IF NEW.lock_version <> OLD.lock_version + 1 THEN
        RAISE EXCEPTION 'release lock version must increase by one' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IS DISTINCT FROM NEW.status AND NOT (
        (OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED')
        OR (OLD.status = 'SUBMITTED' AND NEW.status IN ('APPROVED', 'REJECTED'))
        OR (OLD.status = 'APPROVED' AND NEW.status = 'PUBLISHING')
        OR (OLD.status = 'PUBLISHING' AND NEW.status IN ('PUBLISHED', 'FAILED'))
        OR (OLD.status = 'FAILED' AND NEW.status = 'PUBLISHING')
    ) THEN
        RAISE EXCEPTION 'invalid release status transition' USING ERRCODE = '55000';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND ROW(OLD.revoked_at, OLD.revoked_by, OLD.revocation_reason)
        IS DISTINCT FROM ROW(NEW.revoked_at, NEW.revoked_by, NEW.revocation_reason) THEN
        RAISE EXCEPTION 'release revocation is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
        AND (OLD.status <> 'PUBLISHED' OR NEW.status <> 'PUBLISHED') THEN
        RAISE EXCEPTION 'only a published release can be revoked' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = GREATEST(OLD.updated_at, NEW.updated_at, clock_timestamp());
    RETURN NEW;
END;
$$;

CREATE TRIGGER releases_protect_transition
BEFORE UPDATE ON releases
FOR EACH ROW
EXECUTE FUNCTION protect_release_transition();

CREATE OR REPLACE FUNCTION reject_release_evidence_deletion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'release workflow evidence is immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER releases_reject_delete
BEFORE DELETE OR TRUNCATE ON releases
FOR EACH STATEMENT
EXECUTE FUNCTION reject_release_evidence_deletion();

CREATE TRIGGER release_artifacts_reject_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON release_artifacts
FOR EACH STATEMENT
EXECUTE FUNCTION reject_release_evidence_deletion();

CREATE TRIGGER release_attempts_reject_delete
BEFORE DELETE OR TRUNCATE ON release_attempts
FOR EACH STATEMENT
EXECUTE FUNCTION reject_release_evidence_deletion();

REVOKE DELETE, TRUNCATE ON releases FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON release_artifacts FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON release_attempts FROM PUBLIC;
