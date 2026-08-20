DROP TABLE IF EXISTS directory_sync_stage_parents;
DROP TABLE IF EXISTS directory_sync_stage_memberships;
DROP TABLE IF EXISTS directory_sync_stage_organizations;
DROP TABLE IF EXISTS directory_sync_stage_users;

ALTER TABLE organization_units DROP COLUMN IF EXISTS last_directory_run_id;
ALTER TABLE user_principals DROP COLUMN IF EXISTS last_directory_run_id;

DROP INDEX IF EXISTS directory_sync_conflicts_source_created_idx;
ALTER TABLE directory_sync_conflicts
    DROP CONSTRAINT IF EXISTS directory_sync_conflicts_job_object_code_unique,
    DROP CONSTRAINT IF EXISTS directory_sync_conflicts_details_bounded,
    DROP CONSTRAINT IF EXISTS directory_sync_conflicts_details_object;

DROP INDEX IF EXISTS directory_sync_jobs_source_created_idx;
DROP INDEX IF EXISTS directory_sync_jobs_one_active_source_uidx;
ALTER TABLE directory_sync_jobs
	DROP CONSTRAINT IF EXISTS directory_sync_jobs_status_check,
	ADD CONSTRAINT directory_sync_jobs_status_check
	    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'partial')),
    DROP CONSTRAINT IF EXISTS directory_sync_jobs_processed_counts_nonnegative,
    DROP CONSTRAINT IF EXISTS directory_sync_jobs_phase_valid,
    DROP CONSTRAINT IF EXISTS directory_sync_jobs_source_version_positive,
    DROP COLUMN IF EXISTS processed_memberships,
    DROP COLUMN IF EXISTS processed_organizations,
    DROP COLUMN IF EXISTS processed_users,
    DROP COLUMN IF EXISTS phase,
    DROP COLUMN IF EXISTS run_marker,
    DROP COLUMN IF EXISTS source_version;
