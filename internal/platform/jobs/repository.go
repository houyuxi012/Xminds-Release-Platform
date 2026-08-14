package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrLeaseOwnerRequired = errors.New("lease owner is required")
	ErrLeaseInvalid       = errors.New("lease duration is invalid")
	ErrLeaseLimitInvalid  = errors.New("lease limit is invalid")
	ErrLeaseNotOwned      = errors.New("job lease is not owned by the caller")
)

type Repository interface {
	Enqueue(ctx context.Context, tx pgx.Tx, job Job) error
	Lease(ctx context.Context, owner string, limit int, lease time.Duration) ([]Job, error)
	Complete(ctx context.Context, owner string, id uuid.UUID) error
	Retry(ctx context.Context, owner string, id uuid.UUID, code string, availableAt time.Time) error
	DeadLetter(ctx context.Context, owner string, id uuid.UUID, code string) error
}
