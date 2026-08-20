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

func (repository *PostgresRepository) ListDirectorySyncConflicts(ctx context.Context, sourceID uuid.UUID, page Page) (DirectorySyncConflictPage, error) {
	if repository == nil || repository.pool == nil || sourceID == uuid.Nil {
		return DirectorySyncConflictPage{}, ErrDirectorySyncNotFound
	}
	limit, err := pageLimit(page)
	if err != nil {
		return DirectorySyncConflictPage{}, err
	}
	rows, err := repository.pool.Query(ctx, `
SELECT id, sync_job_id, identity_source_id, object_type, external_id, conflict_code,
       details, status, created_at
FROM directory_sync_conflicts
WHERE identity_source_id=$1
  AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3))
ORDER BY created_at DESC, id DESC
LIMIT $4`, sourceID, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return DirectorySyncConflictPage{}, fmt.Errorf("list directory synchronization conflicts: %w", err)
	}
	defer rows.Close()
	items := make([]DirectorySyncConflict, 0, limit+1)
	for rows.Next() {
		var conflict DirectorySyncConflict
		if err := rows.Scan(
			&conflict.ID, &conflict.SyncJobID, &conflict.IdentitySourceID, &conflict.ObjectType, &conflict.ExternalID,
			&conflict.Code, &conflict.Details, &conflict.Status, &conflict.CreatedAt,
		); err != nil {
			return DirectorySyncConflictPage{}, fmt.Errorf("scan directory synchronization conflict: %w", err)
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
