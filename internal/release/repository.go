package release

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

type Repository interface {
	Create(ctx context.Context, tx pgx.Tx, record Release) error
	Get(ctx context.Context, productID string, releaseID uuid.UUID) (Release, error)
	Transition(ctx context.Context, tx pgx.Tx, command TransitionCommand) (Release, error)
	LockOperation(ctx context.Context, tx pgx.Tx, releaseID uuid.UUID, kind AttemptKind, idempotencyKey string) error
	FindAttempt(ctx context.Context, tx pgx.Tx, releaseID uuid.UUID, kind AttemptKind, idempotencyKey string) (Attempt, error)
	CreateAttempt(ctx context.Context, tx pgx.Tx, attempt Attempt) (Attempt, error)
	Revoke(ctx context.Context, tx pgx.Tx, command RevokeCommand) (Release, error)
}

type Transactor interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
}

type PoolTransactor struct {
	Pool *pgxpool.Pool
}

func (transactor PoolTransactor) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	if transactor.Pool == nil {
		return ErrTransactorRequired
	}
	return database.WithTx(ctx, transactor.Pool, function)
}
