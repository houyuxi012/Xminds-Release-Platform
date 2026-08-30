package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Repository interface {
	Append(ctx context.Context, tx pgx.Tx, event Event) (Event, error)
	Query(ctx context.Context, filter QueryFilter) ([]Event, error)
	StartExport(ctx context.Context, tx pgx.Tx, export Export) error
	GetExport(ctx context.Context, id uuid.UUID) (Export, error)
}
