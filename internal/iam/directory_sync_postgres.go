package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const directorySyncJobColumns = `
id, identity_source_id, source_version, run_marker, mode, status, phase,
create_count, update_count, disable_count, conflict_count,
processed_users, processed_organizations, processed_memberships,
error_code, requested_by, request_id, created_at, updated_at, completed_at, cursor`

func (repository *PostgresRepository) InsertDirectorySyncJob(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	if repository == nil || repository.pool == nil || tx == nil || job.ID == uuid.Nil || job.IdentitySourceID == uuid.Nil ||
		job.SourceVersion < 1 || job.RunMarker == uuid.Nil || job.Status != DirectorySyncStatusPending || job.Phase != DirectorySyncPhaseFetch {
		return ErrDirectorySyncConfiguration
	}
	_, err := tx.Exec(ctx, `
INSERT INTO directory_sync_jobs (
    id, identity_source_id, source_version, run_marker, mode, status, phase,
    create_count, update_count, disable_count, conflict_count,
    processed_users, processed_organizations, processed_memberships,
    error_code, requested_by, request_id, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, 'pending', 'fetch', 0, 0, 0, 0, 0, 0, 0, '', $6, $7, $8, $9)`,
		job.ID, job.IdentitySourceID, job.SourceVersion, job.RunMarker, job.Mode, job.RequestedBy, job.RequestID, job.CreatedAt.UTC(), job.UpdatedAt.UTC())
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" && postgresError.ConstraintName == "directory_sync_jobs_one_active_source_uidx" {
			return ErrDirectorySyncActive
		}
		return fmt.Errorf("insert directory synchronization job: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetDirectorySyncJob(ctx context.Context, sourceID, jobID uuid.UUID) (DirectorySyncJob, error) {
	if repository == nil || repository.pool == nil || sourceID == uuid.Nil || jobID == uuid.Nil {
		return DirectorySyncJob{}, ErrDirectorySyncNotFound
	}
	job, err := scanDirectorySyncJob(repository.pool.QueryRow(ctx, `SELECT `+directorySyncJobColumns+`
FROM directory_sync_jobs WHERE id=$1 AND identity_source_id=$2`, jobID, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectorySyncJob{}, ErrDirectorySyncNotFound
	}
	if err != nil {
		return DirectorySyncJob{}, fmt.Errorf("get directory synchronization job: %w", err)
	}
	return job, nil
}

func (repository *PostgresRepository) ListDirectorySyncJobs(ctx context.Context, sourceID uuid.UUID, page Page) (DirectorySyncJobPage, error) {
	if repository == nil || repository.pool == nil || sourceID == uuid.Nil {
		return DirectorySyncJobPage{}, ErrIdentitySourceNotFound
	}
	limit, err := pageLimit(page)
	if err != nil {
		return DirectorySyncJobPage{}, err
	}
	rows, err := repository.pool.Query(ctx, `SELECT `+directorySyncJobColumns+`
FROM directory_sync_jobs
WHERE identity_source_id=$1
  AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3))
ORDER BY created_at DESC, id DESC
LIMIT $4`, sourceID, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return DirectorySyncJobPage{}, fmt.Errorf("list directory synchronization jobs: %w", err)
	}
	defer rows.Close()
	items := make([]DirectorySyncJob, 0, limit+1)
	for rows.Next() {
		job, scanErr := scanDirectorySyncJob(rows)
		if scanErr != nil {
			return DirectorySyncJobPage{}, fmt.Errorf("scan directory synchronization job: %w", scanErr)
		}
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return DirectorySyncJobPage{}, fmt.Errorf("iterate directory synchronization jobs: %w", err)
	}
	result := DirectorySyncJobPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		result.Items = items[:limit]
		result.NextCursor = encodeIAMCursor(last.CreatedAt, last.ID)
	}
	return result, nil
}

func (repository *PostgresRepository) ListDirectorySyncConflicts(ctx context.Context, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, page Page) (DirectorySyncConflictPage, error) {
	if repository == nil || repository.pool == nil || sourceID == uuid.Nil || !validDirectoryConflictStatusFilter(status) {
		return DirectorySyncConflictPage{}, ErrDirectorySyncNotFound
	}
	limit, err := pageLimit(page)
	if err != nil {
		return DirectorySyncConflictPage{}, err
	}
	rows, err := repository.pool.Query(ctx, `
SELECT `+directorySyncConflictColumns+`
FROM directory_sync_conflicts AS conflict
WHERE conflict.identity_source_id=$1
  AND ($2::text = 'all' OR conflict.status = $2)
  AND ($3::timestamptz IS NULL OR (conflict.created_at, conflict.id) < ($3, $4))
ORDER BY conflict.created_at DESC, conflict.id DESC
LIMIT $5`, sourceID, status, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return DirectorySyncConflictPage{}, fmt.Errorf("list directory synchronization conflicts: %w", err)
	}
	defer rows.Close()
	items := make([]DirectorySyncConflict, 0, limit+1)
	for rows.Next() {
		conflict, scanErr := scanDirectorySyncConflict(rows)
		if scanErr != nil {
			return DirectorySyncConflictPage{}, fmt.Errorf("scan directory synchronization conflict: %w", scanErr)
		}
		items = append(items, conflict)
	}
	if err := rows.Err(); err != nil {
		return DirectorySyncConflictPage{}, fmt.Errorf("iterate directory synchronization conflicts: %w", err)
	}
	result := DirectorySyncConflictPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		result.Items = items[:limit]
		result.NextCursor = encodeIAMCursor(last.CreatedAt, last.ID)
	}
	return result, nil
}

const directorySyncConflictColumns = `conflict.id, conflict.sync_job_id, conflict.identity_source_id,
conflict.object_type, conflict.external_id, conflict.conflict_code, conflict.details, conflict.status,
conflict.version, COALESCE(conflict.resolution_decision, ''), COALESCE(conflict.resolution_reason, ''),
COALESCE(conflict.resolved_by, ''), conflict.resolved_at, conflict.created_at`

func (repository *PostgresRepository) GetDirectorySyncConflict(ctx context.Context, sourceID, conflictID uuid.UUID) (DirectorySyncConflict, DirectorySyncStatus, error) {
	if repository == nil || repository.pool == nil || sourceID == uuid.Nil || conflictID == uuid.Nil {
		return DirectorySyncConflict{}, "", ErrDirectoryConflictNotFound
	}
	return scanDirectorySyncConflictWithJob(repository.pool.QueryRow(ctx, `SELECT `+directorySyncConflictColumns+`, sync_job.status
FROM directory_sync_conflicts AS conflict
JOIN directory_sync_jobs AS sync_job ON sync_job.id=conflict.sync_job_id
WHERE conflict.id=$1 AND conflict.identity_source_id=$2`, conflictID, sourceID))
}

func (repository *PostgresRepository) LockDirectorySyncConflict(ctx context.Context, tx pgx.Tx, sourceID, conflictID uuid.UUID) (DirectorySyncConflict, DirectorySyncStatus, error) {
	if repository == nil || repository.pool == nil || tx == nil || sourceID == uuid.Nil || conflictID == uuid.Nil {
		return DirectorySyncConflict{}, "", ErrDirectoryConflictNotFound
	}
	return scanDirectorySyncConflictWithJob(tx.QueryRow(ctx, `SELECT `+directorySyncConflictColumns+`, sync_job.status
FROM directory_sync_conflicts AS conflict
JOIN directory_sync_jobs AS sync_job ON sync_job.id=conflict.sync_job_id
WHERE conflict.id=$1 AND conflict.identity_source_id=$2
FOR UPDATE OF conflict, sync_job`, conflictID, sourceID))
}

func (repository *PostgresRepository) ResolveDirectorySyncConflict(ctx context.Context, tx pgx.Tx, conflict DirectorySyncConflict, expectedVersion int64) error {
	if repository == nil || repository.pool == nil || tx == nil || conflict.ID == uuid.Nil || expectedVersion < 1 ||
		conflict.Status != string(DirectorySyncConflictStatusResolved) || conflict.ResolutionDecision != DirectoryConflictResolutionKeepLastSafe || conflict.ResolvedAt == nil {
		return ErrDirectorySyncConfiguration
	}
	command, err := tx.Exec(ctx, `
UPDATE directory_sync_conflicts
SET status='resolved', resolution_decision=$1, resolution_reason=$2, resolved_by=$3,
    resolved_at=$4, version=$5
WHERE id=$6 AND identity_source_id=$7 AND status='open' AND version=$8`,
		conflict.ResolutionDecision, conflict.ResolutionReason, conflict.ResolvedBy, conflict.ResolvedAt, conflict.Version,
		conflict.ID, conflict.IdentitySourceID, expectedVersion)
	if err != nil {
		return fmt.Errorf("resolve directory synchronization conflict: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func scanDirectorySyncConflict(row pgx.Row) (DirectorySyncConflict, error) {
	var conflict DirectorySyncConflict
	var resolvedAt *time.Time
	err := row.Scan(&conflict.ID, &conflict.SyncJobID, &conflict.IdentitySourceID, &conflict.ObjectType, &conflict.ExternalID,
		&conflict.Code, &conflict.Details, &conflict.Status, &conflict.Version, &conflict.ResolutionDecision,
		&conflict.ResolutionReason, &conflict.ResolvedBy, &resolvedAt, &conflict.CreatedAt)
	if resolvedAt != nil {
		value := resolvedAt.UTC()
		conflict.ResolvedAt = &value
	}
	return conflict, err
}

func scanDirectorySyncConflictWithJob(row pgx.Row) (DirectorySyncConflict, DirectorySyncStatus, error) {
	var conflict DirectorySyncConflict
	var jobStatus DirectorySyncStatus
	var resolvedAt *time.Time
	err := row.Scan(&conflict.ID, &conflict.SyncJobID, &conflict.IdentitySourceID, &conflict.ObjectType, &conflict.ExternalID,
		&conflict.Code, &conflict.Details, &conflict.Status, &conflict.Version, &conflict.ResolutionDecision,
		&conflict.ResolutionReason, &conflict.ResolvedBy, &resolvedAt, &conflict.CreatedAt, &jobStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectorySyncConflict{}, "", ErrDirectoryConflictNotFound
	}
	if err != nil {
		return DirectorySyncConflict{}, "", fmt.Errorf("get directory synchronization conflict: %w", err)
	}
	if resolvedAt != nil {
		value := resolvedAt.UTC()
		conflict.ResolvedAt = &value
	}
	return conflict, jobStatus, nil
}

func scanDirectorySyncJob(row pgx.Row) (DirectorySyncJob, error) {
	var job DirectorySyncJob
	var completedAt *time.Time
	err := row.Scan(
		&job.ID, &job.IdentitySourceID, &job.SourceVersion, &job.RunMarker, &job.Mode, &job.Status, &job.Phase,
		&job.CreateCount, &job.UpdateCount, &job.DisableCount, &job.ConflictCount,
		&job.ProcessedUsers, &job.ProcessedOrganizations, &job.ProcessedMemberships,
		&job.ErrorCode, &job.RequestedBy, &job.RequestID, &job.CreatedAt, &job.UpdatedAt, &completedAt, &job.Cursor,
	)
	if err != nil {
		return DirectorySyncJob{}, err
	}
	if completedAt != nil {
		job.CompletedAt = completedAt.UTC()
	}
	return job, nil
}
