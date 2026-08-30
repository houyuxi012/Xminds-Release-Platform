package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

const returnedJobFields = `
job.id, job.kind, job.aggregate_id, job.payload, job.status, job.attempts, job.available_at,
COALESCE(job.lease_owner, ''), job.lease_expires_at, COALESCE(job.last_error_code, ''),
job.created_at, job.updated_at`

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) Enqueue(ctx context.Context, tx pgx.Tx, job Job) error {
	_, err := tx.Exec(ctx, `
INSERT INTO outbox_jobs (id, kind, aggregate_id, payload, status, attempts, available_at)
VALUES ($1, $2, $3, $4, 'pending', 0, $5)
`, job.ID, job.Kind, job.AggregateID, job.Payload, job.AvailableAt)
	if err != nil {
		return fmt.Errorf("enqueue outbox job: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) Lease(ctx context.Context, owner string, limit int, lease time.Duration) ([]Job, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, ErrLeaseOwnerRequired
	}
	if limit <= 0 || limit > 1000 {
		return nil, ErrLeaseLimitInvalid
	}
	if lease <= 0 || lease > 24*time.Hour {
		return nil, ErrLeaseInvalid
	}

	rows, err := repository.pool.Query(ctx, `
WITH candidates AS (
    SELECT id
    FROM outbox_jobs
    WHERE (status = 'pending' AND available_at <= clock_timestamp())
       OR (status = 'leased' AND lease_expires_at <= clock_timestamp())
    ORDER BY available_at, created_at
    FOR UPDATE SKIP LOCKED
    LIMIT $1
)
UPDATE outbox_jobs AS job
SET status = 'leased',
    attempts = job.attempts + 1,
    lease_owner = $2,
    lease_expires_at = clock_timestamp() + ($3 * interval '1 millisecond'),
    updated_at = clock_timestamp()
FROM candidates
WHERE job.id = candidates.id
RETURNING `+returnedJobFields, limit, owner, lease.Milliseconds())
	if err != nil {
		return nil, fmt.Errorf("lease outbox jobs: %w", err)
	}
	defer rows.Close()

	leased := make([]Job, 0, limit)
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan leased outbox job: %w", scanErr)
		}
		leased = append(leased, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leased outbox jobs: %w", err)
	}
	return leased, nil
}

func (repository *PostgresRepository) Complete(ctx context.Context, owner string, id uuid.UUID) error {
	return repository.transition(ctx, owner, id, `
UPDATE outbox_jobs
SET status = 'completed', lease_owner = NULL, lease_expires_at = NULL, updated_at = clock_timestamp()
WHERE id = $1 AND status = 'leased' AND lease_owner = $2
`)
}

func (repository *PostgresRepository) Renew(ctx context.Context, owner string, id uuid.UUID, lease time.Duration) error {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ErrLeaseOwnerRequired
	}
	if lease <= 0 || lease > 24*time.Hour {
		return ErrLeaseInvalid
	}
	result, err := repository.pool.Exec(ctx, `
UPDATE outbox_jobs
SET lease_expires_at = clock_timestamp() + ($3 * interval '1 millisecond'),
    updated_at = clock_timestamp()
WHERE id = $1 AND status = 'leased' AND lease_owner = $2
  AND lease_expires_at > clock_timestamp()
`, id, owner, lease.Milliseconds())
	if err != nil {
		return fmt.Errorf("renew outbox job lease: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseNotOwned
	}
	return nil
}

func (repository *PostgresRepository) Retry(ctx context.Context, owner string, id uuid.UUID, code string, availableAt time.Time) error {
	if availableAt.IsZero() {
		return ErrAvailableAtInvalid
	}
	return repository.transition(ctx, owner, id, `
UPDATE outbox_jobs
SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL,
    last_error_code = $3, available_at = $4, updated_at = clock_timestamp()
WHERE id = $1 AND status = 'leased' AND lease_owner = $2
`, strings.TrimSpace(code), availableAt.UTC())
}

func (repository *PostgresRepository) DeadLetter(ctx context.Context, owner string, id uuid.UUID, code string) error {
	return repository.transition(ctx, owner, id, `
UPDATE outbox_jobs
SET status = 'dead_letter', lease_owner = NULL, lease_expires_at = NULL,
    last_error_code = $3, updated_at = clock_timestamp()
WHERE id = $1 AND status = 'leased' AND lease_owner = $2
`, strings.TrimSpace(code))
}

func (repository *PostgresRepository) SettleDeadLetter(
	ctx context.Context,
	owner string,
	id uuid.UUID,
	code string,
	transition func(pgx.Tx) error,
) error {
	owner = strings.TrimSpace(owner)
	code = strings.TrimSpace(code)
	if repository == nil || repository.pool == nil || owner == "" || id == uuid.Nil || !errorCodePattern.MatchString(code) || len(code) > 128 {
		return ErrWorkerConfiguration
	}
	return database.WithTx(ctx, repository.pool, func(tx pgx.Tx) error {
		var status, leaseOwner string
		if err := tx.QueryRow(ctx, `
SELECT status, COALESCE(lease_owner, '')
FROM outbox_jobs
WHERE id=$1
FOR UPDATE`, id).Scan(&status, &leaseOwner); err != nil {
			if err == pgx.ErrNoRows {
				return ErrLeaseNotOwned
			}
			return fmt.Errorf("lock outbox job for dead-letter settlement: %w", err)
		}
		if status != string(StatusLeased) || leaseOwner != owner {
			return ErrLeaseNotOwned
		}
		if transition != nil {
			if err := transition(tx); err != nil {
				return fmt.Errorf("apply dead-letter domain transition: %w", err)
			}
		}
		result, err := tx.Exec(ctx, `
UPDATE outbox_jobs
SET status = 'dead_letter', lease_owner = NULL, lease_expires_at = NULL,
    last_error_code = $3, updated_at = clock_timestamp()
WHERE id = $1 AND status = 'leased' AND lease_owner = $2
`, id, owner, code)
		if err != nil {
			return fmt.Errorf("transition outbox job to dead letter: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrLeaseNotOwned
		}
		return nil
	})
}

func (repository *PostgresRepository) transition(ctx context.Context, owner string, id uuid.UUID, statement string, arguments ...any) error {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ErrLeaseOwnerRequired
	}
	allArguments := append([]any{id, owner}, arguments...)
	result, err := repository.pool.Exec(ctx, statement, allArguments...)
	if err != nil {
		return fmt.Errorf("transition outbox job: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseNotOwned
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(row rowScanner) (Job, error) {
	var job Job
	err := row.Scan(
		&job.ID,
		&job.Kind,
		&job.AggregateID,
		&job.Payload,
		&job.Status,
		&job.Attempts,
		&job.AvailableAt,
		&job.LeaseOwner,
		&job.LeaseExpiresAt,
		&job.LastErrorCode,
		&job.CreatedAt,
		&job.UpdatedAt,
	)
	return job, err
}
