package logcenter

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PartitionService struct{ pool *pgxpool.Pool }

func NewPartitionService(pool *pgxpool.Pool) *PartitionService { return &PartitionService{pool: pool} }

func (service *PartitionService) EnsureMonthlyPartitions(ctx context.Context, month time.Time) error {
	if service == nil || service.pool == nil {
		return ErrRepositoryUnavailable
	}
	_, err := service.pool.Exec(ctx, `SELECT ensure_log_monthly_partitions($1)`, month.UTC().Format("2006-01-02"))
	return err
}
