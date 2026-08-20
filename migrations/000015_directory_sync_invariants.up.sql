-- Databases that applied immutable migration 000014 before the companion
-- mechanism may still contain a single legacy active job. Converge it to the
-- same explicit, operator-visible terminal state.
UPDATE directory_sync_jobs
SET status = 'failed',
    error_code = 'directory_migration_restart_required',
    completed_at = COALESCE(completed_at, clock_timestamp()),
    updated_at = GREATEST(updated_at, clock_timestamp())
WHERE status IN ('pending', 'running', 'partial');

DROP INDEX directory_sync_jobs_one_active_source_uidx;

ALTER TABLE directory_sync_jobs
    DROP CONSTRAINT directory_sync_jobs_status_check,
    ADD CONSTRAINT directory_sync_jobs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'failed'));

CREATE UNIQUE INDEX directory_sync_jobs_one_active_source_uidx
    ON directory_sync_jobs (identity_source_id)
    WHERE status IN ('pending', 'running');

ALTER TABLE directory_sync_stage_parents
    DROP CONSTRAINT directory_sync_stage_parents_check;

CREATE TABLE principal_mapping_registry (
    mapping_kind TEXT NOT NULL CHECK (mapping_kind IN ('username', 'email')),
    canonical_value TEXT NOT NULL CHECK (length(canonical_value) BETWEEN 1 AND 320),
    principal_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE CASCADE,
    identity_source_id UUID REFERENCES identity_sources(id) ON DELETE RESTRICT,
    external_subject TEXT NOT NULL DEFAULT '' CHECK (length(external_subject) <= 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (mapping_kind, canonical_value),
    UNIQUE (principal_id, mapping_kind),
    CHECK ((identity_source_id IS NULL) = (external_subject = ''))
);

CREATE INDEX principal_mapping_registry_source_subject_idx
    ON principal_mapping_registry (identity_source_id, external_subject);

INSERT INTO principal_mapping_registry (
    mapping_kind, canonical_value, principal_id, identity_source_id, external_subject
)
SELECT 'username', lower(btrim(username)), id, identity_source_id, external_subject
FROM user_principals;

INSERT INTO principal_mapping_registry (
    mapping_kind, canonical_value, principal_id, identity_source_id, external_subject
)
SELECT 'email', lower(btrim(email)), id, identity_source_id, external_subject
FROM user_principals
WHERE btrim(email) <> '';

CREATE OR REPLACE FUNCTION maintain_principal_mapping_registry()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    canonical_username TEXT := lower(btrim(NEW.username));
    canonical_email TEXT := lower(btrim(NEW.email));
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'xminds-release-platform:iam:directory-mapping:' || mapping_key, 0
    ))
    FROM (
        SELECT 'username:' || canonical_username AS mapping_key
        UNION ALL
        SELECT 'email:' || canonical_email WHERE canonical_email <> ''
    ) AS desired
    ORDER BY mapping_key;

    IF EXISTS (
        SELECT 1 FROM principal_mapping_registry
        WHERE mapping_kind='username' AND canonical_value=canonical_username AND principal_id<>NEW.id
    ) OR (
        canonical_email <> '' AND EXISTS (
            SELECT 1 FROM principal_mapping_registry
            WHERE mapping_kind='email' AND canonical_value=canonical_email AND principal_id<>NEW.id
        )
    ) THEN
        RAISE EXCEPTION 'principal mapping conflict' USING ERRCODE = '23505';
    END IF;

    DELETE FROM principal_mapping_registry WHERE principal_id=NEW.id;
    INSERT INTO principal_mapping_registry (
        mapping_kind, canonical_value, principal_id, identity_source_id, external_subject
    ) VALUES ('username', canonical_username, NEW.id, NEW.identity_source_id, NEW.external_subject);
    IF canonical_email <> '' THEN
        INSERT INTO principal_mapping_registry (
            mapping_kind, canonical_value, principal_id, identity_source_id, external_subject
        ) VALUES ('email', canonical_email, NEW.id, NEW.identity_source_id, NEW.external_subject);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER user_principals_mapping_registry
AFTER INSERT OR UPDATE OF username, email, identity_source_id, external_subject ON user_principals
FOR EACH ROW EXECUTE FUNCTION maintain_principal_mapping_registry();
