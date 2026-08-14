DROP TRIGGER IF EXISTS release_attempts_reject_delete ON release_attempts;
DROP TRIGGER IF EXISTS release_artifacts_reject_mutation ON release_artifacts;
DROP TRIGGER IF EXISTS releases_reject_delete ON releases;
DROP TRIGGER IF EXISTS releases_protect_transition ON releases;
DROP FUNCTION IF EXISTS reject_release_evidence_deletion();
DROP FUNCTION IF EXISTS protect_release_transition();
DROP TABLE IF EXISTS release_attempts;
DROP TABLE IF EXISTS release_artifacts;
DROP TABLE IF EXISTS releases;

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
