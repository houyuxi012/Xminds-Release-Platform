package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
)

const (
	defaultDirectorySyncBatchSize = 100
	maximumDirectorySyncBatchSize = 500
)

var directoryConflictCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

type PostgresDirectorySyncExecutorConfig struct {
	Pool      *pgxpool.Pool
	Auditor   AuditAppender
	Sessions  SessionRevoker
	Clock     func() time.Time
	BatchSize int
}

type PostgresDirectorySyncExecutor struct {
	pool       *pgxpool.Pool
	repository *PostgresRepository
	auditor    AuditAppender
	sessions   SessionRevoker
	clock      func() time.Time
	batchSize  int
}

func NewPostgresDirectorySyncExecutor(config PostgresDirectorySyncExecutorConfig) (*PostgresDirectorySyncExecutor, error) {
	if config.BatchSize == 0 {
		config.BatchSize = defaultDirectorySyncBatchSize
	}
	if config.Pool == nil || config.Auditor == nil || config.Sessions == nil || config.Clock == nil || config.BatchSize < 1 || config.BatchSize > maximumDirectorySyncBatchSize {
		return nil, ErrDirectorySyncConfiguration
	}
	return &PostgresDirectorySyncExecutor{
		pool: config.Pool, repository: NewPostgresRepository(config.Pool), auditor: config.Auditor,
		sessions: config.Sessions, clock: config.Clock, batchSize: config.BatchSize,
	}, nil
}

func (executor *PostgresDirectorySyncExecutor) Load(ctx context.Context, jobID, sourceID uuid.UUID) (DirectorySyncJob, IdentitySource, error) {
	if executor == nil || executor.pool == nil || jobID == uuid.Nil || sourceID == uuid.Nil {
		return DirectorySyncJob{}, IdentitySource{}, ErrDirectorySyncNotFound
	}
	job, err := executor.repository.GetDirectorySyncJob(ctx, sourceID, jobID)
	if err != nil {
		return DirectorySyncJob{}, IdentitySource{}, err
	}
	source, err := executor.repository.GetIdentitySource(ctx, nil, sourceID)
	if err != nil {
		return DirectorySyncJob{}, IdentitySource{}, err
	}
	return job, source, nil
}

func (executor *PostgresDirectorySyncExecutor) Stage(ctx context.Context, expectedJob DirectorySyncJob, expectedSource IdentitySource, page SyncPage) error {
	if executor == nil || executor.pool == nil || expectedJob.ID == uuid.Nil || expectedSource.ID == uuid.Nil || expectedJob.IdentitySourceID != expectedSource.ID ||
		(page.Complete && page.NextCursor != "") || (!page.Complete && strings.TrimSpace(page.NextCursor) == "") || len(page.NextCursor) > 2048 {
		return ErrDirectorySyncConfiguration
	}
	return database.WithTx(ctx, executor.pool, func(tx pgx.Tx) error {
		job, source, err := executor.lockExecution(ctx, tx, expectedJob.ID, expectedSource.ID)
		if err != nil {
			return err
		}
		if job.SourceVersion != source.Version || job.SourceVersion != expectedJob.SourceVersion || source.Version != expectedSource.Version || source.Status != IdentitySourceStatusVerified {
			return ErrDirectorySourceChanged
		}
		if job.Status != DirectorySyncStatusPending && job.Status != DirectorySyncStatusRunning {
			return ErrDirectorySyncConfiguration
		}
		if job.Phase != DirectorySyncPhaseFetch || job.Cursor != expectedJob.Cursor {
			if job.Cursor == page.NextCursor || job.Phase == DirectorySyncPhasePrepare {
				return nil
			}
			return ErrIAMConflict
		}
		for _, user := range page.Users {
			if _, err := tx.Exec(ctx, `
INSERT INTO directory_sync_stage_users (
    sync_job_id, external_subject, username, display_name, email, enabled
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (sync_job_id, external_subject) DO UPDATE
SET occurrence_count=directory_sync_stage_users.occurrence_count+1,
    conflicting=TRUE,
    updated_at=clock_timestamp()`, job.ID, user.ExternalSubject, user.Username, user.DisplayName, user.Email, user.Enabled); err != nil {
				return fmt.Errorf("stage directory user: %w", err)
			}
		}
		for _, organization := range page.Organizations {
			if _, err := tx.Exec(ctx, `
INSERT INTO directory_sync_stage_organizations (sync_job_id, external_id, name)
VALUES ($1, $2, $3)
ON CONFLICT (sync_job_id, external_id) DO UPDATE
SET occurrence_count=directory_sync_stage_organizations.occurrence_count+1,
    conflicting=TRUE,
    updated_at=clock_timestamp()`, job.ID, organization.ExternalID, organization.Name); err != nil {
				return fmt.Errorf("stage directory organization: %w", err)
			}
			if organization.ParentExternalID != "" {
				if _, err := tx.Exec(ctx, `
INSERT INTO directory_sync_stage_parents (sync_job_id, organization_external_id, parent_external_id)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, job.ID, organization.ExternalID, organization.ParentExternalID); err != nil {
					return fmt.Errorf("stage directory organization parent: %w", err)
				}
			}
		}
		for _, membership := range page.Memberships {
			if _, err := tx.Exec(ctx, `
INSERT INTO directory_sync_stage_memberships (sync_job_id, organization_external_id, user_external_subject)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, job.ID, membership.OrganizationExternalID, membership.UserExternalSubject); err != nil {
				return fmt.Errorf("stage directory membership: %w", err)
			}
		}
		for _, parent := range page.OrganizationParents {
			if _, err := tx.Exec(ctx, `
INSERT INTO directory_sync_stage_parents (sync_job_id, organization_external_id, parent_external_id)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, job.ID, parent.OrganizationExternalID, parent.ParentExternalID); err != nil {
				return fmt.Errorf("stage directory organization parent: %w", err)
			}
		}
		phase := DirectorySyncPhaseFetch
		if page.Complete {
			phase = DirectorySyncPhasePrepare
		}
		result, err := tx.Exec(ctx, `
UPDATE directory_sync_jobs
SET status='running', phase=$2, cursor=$3, updated_at=$4
WHERE id=$1 AND identity_source_id=$5 AND source_version=$6 AND phase='fetch' AND cursor=$7`,
			job.ID, phase, page.NextCursor, executor.now(), job.IdentitySourceID, job.SourceVersion, expectedJob.Cursor)
		if err != nil {
			return fmt.Errorf("advance directory staging cursor: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrIAMConflict
		}
		return nil
	})
}

func (executor *PostgresDirectorySyncExecutor) Advance(ctx context.Context, expectedJob DirectorySyncJob, expectedSource IdentitySource) (DirectorySyncJob, error) {
	if executor == nil || executor.pool == nil || expectedJob.ID == uuid.Nil || expectedSource.ID == uuid.Nil {
		return DirectorySyncJob{}, ErrDirectorySyncConfiguration
	}
	var advanced DirectorySyncJob
	err := database.WithTx(ctx, executor.pool, func(tx pgx.Tx) error {
		if expectedJob.Mode == DirectorySyncModeApply {
			if err := executor.repository.LockBreakGlassInvariant(ctx, tx); err != nil {
				return err
			}
		}
		job, source, err := executor.lockExecution(ctx, tx, expectedJob.ID, expectedSource.ID)
		if err != nil {
			return err
		}
		if job.SourceVersion != source.Version || job.SourceVersion != expectedJob.SourceVersion || source.Version != expectedSource.Version || source.Status != IdentitySourceStatusVerified {
			return ErrDirectorySourceChanged
		}
		if job.Status == DirectorySyncStatusCompleted || job.Status == DirectorySyncStatusFailed {
			advanced = job
			return nil
		}
		switch job.Phase {
		case DirectorySyncPhasePrepare:
			err = executor.prepareSnapshot(ctx, tx, &job, &source)
		case DirectorySyncPhaseUsers:
			err = executor.applyUsers(ctx, tx, &job)
		case DirectorySyncPhaseOrganizations:
			err = executor.applyOrganizations(ctx, tx, &job)
		case DirectorySyncPhaseMemberships:
			err = executor.applyMemberships(ctx, tx, &job)
		case DirectorySyncPhaseFinalize:
			err = executor.finalizeApply(ctx, tx, &job)
		default:
			err = ErrDirectorySyncConfiguration
		}
		if err != nil {
			return err
		}
		advanced = job
		return nil
	})
	return advanced, err
}

func (executor *PostgresDirectorySyncExecutor) Fail(ctx context.Context, jobID, sourceID uuid.UUID, code string) error {
	code = strings.TrimSpace(code)
	if executor == nil || executor.pool == nil || jobID == uuid.Nil || sourceID == uuid.Nil || !directorySyncErrorCodePattern.MatchString(code) || len(code) > 128 {
		return ErrDirectorySyncConfiguration
	}
	return database.WithTx(ctx, executor.pool, func(tx pgx.Tx) error {
		return executor.FailWithinTransaction(ctx, tx, jobID, sourceID, code)
	})
}

func (executor *PostgresDirectorySyncExecutor) FailWithinTransaction(ctx context.Context, tx pgx.Tx, jobID, sourceID uuid.UUID, code string) error {
	code = strings.TrimSpace(code)
	if executor == nil || executor.pool == nil || jobID == uuid.Nil || sourceID == uuid.Nil || !directorySyncErrorCodePattern.MatchString(code) || len(code) > 128 {
		return ErrDirectorySyncConfiguration
	}
	job, _, err := executor.lockExecution(ctx, tx, jobID, sourceID)
	if err != nil {
		return err
	}
	if job.Status == DirectorySyncStatusCompleted || job.Status == DirectorySyncStatusFailed {
		return nil
	}
	now := executor.now()
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_jobs SET status='failed', error_code=$2, completed_at=$3, updated_at=$3
WHERE id=$1 AND identity_source_id=$4`, job.ID, code, now, sourceID); err != nil {
		return fmt.Errorf("fail directory synchronization job: %w", err)
	}
	_, err = executor.auditor.Append(ctx, tx, audit.AppendCommand{
		Actor: directorySyncWorkerPrincipal(), Action: "identity.directory_sync.failed", ResourceType: "directory_sync_job", ResourceID: job.ID.String(),
		Outcome: audit.OutcomeFailed, RequestID: job.RequestID.String(),
		Metadata: map[string]any{"identity_source_id": sourceID.String(), "mode": job.Mode, "error_code": code, "requested_by": job.RequestedBy},
	})
	return err
}

func (executor *PostgresDirectorySyncExecutor) lockExecution(ctx context.Context, tx pgx.Tx, jobID, sourceID uuid.UUID) (DirectorySyncJob, IdentitySource, error) {
	job, err := scanDirectorySyncJob(tx.QueryRow(ctx, `SELECT `+directorySyncJobColumns+`
FROM directory_sync_jobs WHERE id=$1 AND identity_source_id=$2 FOR UPDATE`, jobID, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectorySyncJob{}, IdentitySource{}, ErrDirectorySyncNotFound
	}
	if err != nil {
		return DirectorySyncJob{}, IdentitySource{}, fmt.Errorf("lock directory synchronization job: %w", err)
	}
	source, err := executor.repository.GetIdentitySource(ctx, tx, sourceID)
	return job, source, err
}

func (executor *PostgresDirectorySyncExecutor) now() time.Time {
	return executor.clock().UTC().Truncate(time.Microsecond)
}

func (executor *PostgresDirectorySyncExecutor) requireBreakGlassContinuity(ctx context.Context, tx pgx.Tx, at time.Time) error {
	evaluation, err := executor.repository.EvaluateBreakGlassInvariant(ctx, tx, at.UTC())
	if err != nil {
		return err
	}
	if evaluation.CurrentUsableAdministrators < 1 || !evaluation.FirstScheduledPermissionGap.IsZero() {
		return ErrLastEmergencyAdministrator
	}
	return nil
}

func directorySyncWorkerPrincipal() identity.Principal {
	return identity.Principal{
		Subject: "system:directory-sync-worker", Kind: identity.PrincipalKindWorkload,
		Provider: identity.WorkloadProviderAPIToken, TokenID: "directory-sync-worker",
	}
}

func (executor *PostgresDirectorySyncExecutor) insertConflict(ctx context.Context, tx pgx.Tx, job DirectorySyncJob, objectType, externalID, code, field string, count int) error {
	if !directoryConflictCodePattern.MatchString(code) || (objectType != "user" && objectType != "organization" && objectType != "membership") ||
		strings.TrimSpace(externalID) == "" || len(externalID) > 512 || len(field) > 128 || count < 0 {
		return ErrDirectorySyncConfiguration
	}
	details, err := json.Marshal(map[string]any{"stable_id": externalID, "field": field, "count": count})
	if err != nil {
		return err
	}
	conflictID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO directory_sync_conflicts (
    id, sync_job_id, identity_source_id, object_type, external_id, conflict_code, details, status, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', $8)
ON CONFLICT (sync_job_id, object_type, external_id, conflict_code) DO NOTHING`,
		conflictID, job.ID, job.IdentitySourceID, objectType, externalID, code, details, executor.now())
	if err != nil {
		return fmt.Errorf("insert directory synchronization conflict: %w", err)
	}
	return nil
}
