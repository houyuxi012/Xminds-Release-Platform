package product

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

var (
	ErrRepositoryRequired    = errors.New("product repository is required")
	ErrTransactorRequired    = errors.New("product transactor is required")
	ErrAuditAppenderRequired = errors.New("product audit appender is required")
	ErrProductIDExists       = errors.New("product ID already exists")
	ErrManifestDigestExists  = errors.New("product manifest digest already exists")
	ErrProductNotFound       = errors.New("product was not found")
)

type Repository interface {
	Create(ctx context.Context, tx pgx.Tx, product Product, channels []Channel) error
	Get(ctx context.Context, productID string) (Product, error)
	List(ctx context.Context, productIDs []string, page Page) (ProductPage, error)
	Deactivate(ctx context.Context, tx pgx.Tx, productID string, deactivatedAt time.Time) (Product, error)
}

type Transactor interface {
	WithinTransaction(ctx context.Context, fn func(pgx.Tx) error) error
}

type PoolTransactor struct {
	Pool *pgxpool.Pool
}

func (transactor PoolTransactor) WithinTransaction(ctx context.Context, fn func(pgx.Tx) error) error {
	if transactor.Pool == nil {
		return ErrTransactorRequired
	}
	return database.WithTx(ctx, transactor.Pool, fn)
}
