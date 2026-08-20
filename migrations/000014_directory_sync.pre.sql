-- Immutable migration 000014 creates a unique active-job index. Historical
-- pre-v14 rows have no durable stage state and cannot be resumed safely, so the
-- migration framework executes this companion in the same transaction as
-- 000014 only when 000014 has not yet been recorded.
UPDATE directory_sync_jobs
SET status = 'failed',
    error_code = 'directory_migration_restart_required',
    completed_at = COALESCE(completed_at, clock_timestamp()),
    updated_at = GREATEST(updated_at, clock_timestamp())
WHERE status IN ('pending', 'running', 'partial');
