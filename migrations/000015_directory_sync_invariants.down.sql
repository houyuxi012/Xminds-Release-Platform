-- Rollback must run with directory workers stopped. Capture the v15-only
-- self-cycle staging rows before restoring the immutable v14 CHECK so every
-- affected non-terminal job and its active outbox delivery converge in the
-- same transaction.
CREATE TEMP TABLE directory_sync_v15_rollback_jobs (
    job_id UUID PRIMARY KEY,
    requires_failure BOOLEAN NOT NULL
) ON COMMIT DROP;

INSERT INTO directory_sync_v15_rollback_jobs (job_id, requires_failure)
SELECT DISTINCT sync_job.id, sync_job.status IN ('pending', 'running')
FROM directory_sync_jobs AS sync_job
JOIN directory_sync_stage_parents AS staged_parent
  ON staged_parent.sync_job_id = sync_job.id
WHERE staged_parent.organization_external_id = staged_parent.parent_external_id;

SELECT sync_job.id
FROM directory_sync_jobs AS sync_job
JOIN directory_sync_v15_rollback_jobs AS affected ON affected.job_id = sync_job.id
FOR UPDATE;

UPDATE directory_sync_jobs AS sync_job
SET status = 'failed',
    error_code = 'directory_migration_rollback_restart_required',
    completed_at = COALESCE(sync_job.completed_at, clock_timestamp()),
    updated_at = GREATEST(sync_job.updated_at, clock_timestamp())
FROM directory_sync_v15_rollback_jobs AS affected
WHERE sync_job.id = affected.job_id
  AND affected.requires_failure;

UPDATE outbox_jobs AS outbox_job
SET status = 'dead_letter',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = 'directory_migration_rollback_restart_required',
    updated_at = GREATEST(outbox_job.updated_at, clock_timestamp())
FROM directory_sync_v15_rollback_jobs AS affected
WHERE outbox_job.kind = 'iam.directory.sync.v1'
  AND outbox_job.aggregate_id = affected.job_id
  AND outbox_job.status IN ('pending', 'leased');

DELETE FROM directory_sync_stage_parents
WHERE organization_external_id = parent_external_id;

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
