DROP TRIGGER IF EXISTS user_principals_mapping_registry ON user_principals;
DROP FUNCTION IF EXISTS maintain_principal_mapping_registry();
DROP TABLE IF EXISTS principal_mapping_registry;

ALTER TABLE directory_sync_stage_parents
    ADD CONSTRAINT directory_sync_stage_parents_check
        CHECK (organization_external_id <> parent_external_id);

DROP INDEX directory_sync_jobs_one_active_source_uidx;

ALTER TABLE directory_sync_jobs
    DROP CONSTRAINT directory_sync_jobs_status_check,
    ADD CONSTRAINT directory_sync_jobs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'partial'));

CREATE UNIQUE INDEX directory_sync_jobs_one_active_source_uidx
    ON directory_sync_jobs (identity_source_id)
    WHERE status IN ('pending', 'running', 'partial');
