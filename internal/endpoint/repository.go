package endpoint

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Repository interface {
	Create(ctx context.Context, tx pgx.Tx, record Endpoint) error
	Get(ctx context.Context, id uuid.UUID) (Endpoint, error)
	MarkHealthy(ctx context.Context, tx pgx.Tx, id uuid.UUID, rootDigest, timestampDigest string, at time.Time) (Endpoint, error)
	MarkFailure(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time) (Endpoint, error)
}

type Transactor interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
}
