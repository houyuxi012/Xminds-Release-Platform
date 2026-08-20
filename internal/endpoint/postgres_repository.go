package endpoint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	if repository == nil || repository.pool == nil || function == nil {
		return ErrEndpointTransactor
	}
	return database.WithTx(ctx, repository.pool, function)
}

func (repository *PostgresRepository) Create(ctx context.Context, tx pgx.Tx, record Endpoint) error {
	if tx == nil {
		return ErrEndpointTransactor
	}
	_, err := tx.Exec(ctx, `
INSERT INTO distribution_endpoints (
    id, product_id, name, endpoint_type, region, priority, base_url, path_prefix,
    health_path, tls_ca_ref, status, last_root_digest, last_timestamp_digest,
    last_checked_at, failure_count, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NULL,NULL,0,$12,$12)
`, record.ID, record.ProductID, record.Name, record.Type, record.Region, record.Priority,
		record.BaseURL, record.PathPrefix, record.HealthPath, record.TLSCARef, record.Status, record.CreatedAt)
	if err != nil {
		return fmt.Errorf("create distribution endpoint: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) Get(ctx context.Context, id uuid.UUID) (Endpoint, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return Endpoint{}, ErrEndpointNotFound
	}
	record, err := scanEndpoint(repository.pool.QueryRow(ctx, endpointSelect+` WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Endpoint{}, ErrEndpointNotFound
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("get distribution endpoint: %w", err)
	}
	return record, nil
}

func (repository *PostgresRepository) MarkHealthy(ctx context.Context, tx pgx.Tx, id uuid.UUID, rootDigest, timestampDigest string, at time.Time) (Endpoint, error) {
	if tx == nil {
		return Endpoint{}, ErrEndpointTransactor
	}
	record, err := scanEndpoint(tx.QueryRow(ctx, `
UPDATE distribution_endpoints
SET status = 'active', last_root_digest = $2, last_timestamp_digest = $3,
    last_checked_at = $4, failure_count = 0, updated_at = $4
WHERE id = $1 AND status <> 'disabled'
RETURNING id, product_id, name, endpoint_type, region, priority, base_url, path_prefix,
          health_path, tls_ca_ref, status, last_root_digest, last_timestamp_digest,
          last_checked_at, failure_count, created_at, updated_at
`, id, rootDigest, timestampDigest, at.UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return Endpoint{}, ErrEndpointNotFound
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("mark distribution endpoint healthy: %w", err)
	}
	return record, nil
}

func (repository *PostgresRepository) MarkFailure(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time) (Endpoint, error) {
	if tx == nil {
		return Endpoint{}, ErrEndpointTransactor
	}
	record, err := scanEndpoint(tx.QueryRow(ctx, `
UPDATE distribution_endpoints
SET failure_count = failure_count + 1,
    status = CASE WHEN failure_count + 1 >= 3 THEN 'unhealthy' ELSE status END,
    last_checked_at = $2, updated_at = $2
WHERE id = $1 AND status <> 'disabled'
RETURNING id, product_id, name, endpoint_type, region, priority, base_url, path_prefix,
          health_path, tls_ca_ref, status, last_root_digest, last_timestamp_digest,
          last_checked_at, failure_count, created_at, updated_at
`, id, at.UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return Endpoint{}, ErrEndpointNotFound
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("mark distribution endpoint failure: %w", err)
	}
	return record, nil
}

const endpointSelect = `
SELECT id, product_id, name, endpoint_type, region, priority, base_url, path_prefix,
       health_path, tls_ca_ref, status, last_root_digest, last_timestamp_digest,
       last_checked_at, failure_count, created_at, updated_at
FROM distribution_endpoints`

type endpointRow interface{ Scan(dest ...any) error }

func scanEndpoint(row endpointRow) (Endpoint, error) {
	var record Endpoint
	var rootDigest, timestampDigest *string
	err := row.Scan(
		&record.ID, &record.ProductID, &record.Name, &record.Type, &record.Region, &record.Priority,
		&record.BaseURL, &record.PathPrefix, &record.HealthPath, &record.TLSCARef, &record.Status,
		&rootDigest, &timestampDigest, &record.LastCheckedAt, &record.FailureCount, &record.CreatedAt, &record.UpdatedAt,
	)
	if rootDigest != nil {
		record.LastRootDigest = *rootDigest
	}
	if timestampDigest != nil {
		record.LastTimestampDigest = *timestampDigest
	}
	return record, err
}

var _ Repository = (*PostgresRepository)(nil)
var _ Transactor = (*PostgresRepository)(nil)
