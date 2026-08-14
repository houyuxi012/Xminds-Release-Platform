package artifact

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

type Repository interface {
	CreateUpload(ctx context.Context, tx pgx.Tx, upload Upload) error
	GetUpload(ctx context.Context, id uuid.UUID) (Upload, error)
	SavePart(ctx context.Context, part UploadPart) error
	ListParts(ctx context.Context, uploadID uuid.UUID) ([]UploadPart, error)
	Quarantine(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, at time.Time) error
	Expire(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, at time.Time) error
	Complete(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, candidate Artifact) (Artifact, error)
	GetArtifact(ctx context.Context, productID string, artifactID uuid.UUID) (Artifact, error)
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
