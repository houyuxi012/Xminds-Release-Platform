package logcenter

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type ExportJob struct {
	ID         uuid.UUID
	ExportID   uuid.UUID
	LeaseToken uuid.UUID
	Attempts   int
	NextRunAt  time.Time
	Status     string
}

var ErrExportRetryExhausted = errors.New("export retry exhausted")
var ErrExportRuntimeConfiguration = errors.New("export runtime configuration is invalid")
var ErrInvalidExportJob = errors.New("invalid export job")
var ErrExportLeaseLost = errors.New("export job lease lost")

type ExportRuntimeStore interface {
	ClaimExportJob(context.Context, time.Time) (ExportJob, bool, error)
	CompleteExportJob(context.Context, uuid.UUID, uuid.UUID) error
	FailExportJob(context.Context, uuid.UUID, uuid.UUID, time.Time) error
	ExhaustExportJob(context.Context, uuid.UUID, uuid.UUID, error) error
}

func ValidateExportRuntimeConfig(store ExportRuntimeStore, maxAttempts int) error {
	if store == nil || maxAttempts < 1 {
		return ErrExportRuntimeConfiguration
	}
	return nil
}

type ExportExecutor interface {
	ExecuteExport(context.Context, ExportJob) error
}

type ExportRuntimeObserver interface {
	ObserveExportRuntime(context.Context, ExportJob, string, error)
}

type ExportRuntime struct {
	Store       ExportRuntimeStore
	Executor    ExportExecutor
	Observer    ExportRuntimeObserver
	Now         func() time.Time
	MaxAttempts int
}

// RunOnce claims one due job, executes it, and durably transitions it to
// completed, retryable, or exhausted. The store owns the transaction and
// lease fencing; this runner never treats an in-memory result as durable.
func (r *ExportRuntime) RunOnce(ctx context.Context) (bool, error) {
	if r == nil || r.Store == nil || r.Executor == nil || r.MaxAttempts < 1 {
		return false, ErrExportUnavailable
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	job, found, err := r.Store.ClaimExportJob(ctx, now)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	if job.Status != "running" || job.ID == uuid.Nil || job.ExportID == uuid.Nil {
		err = ErrInvalidExportJob
		if job.ID != uuid.Nil && job.LeaseToken != uuid.Nil {
			if exhaustErr := r.Store.ExhaustExportJob(ctx, job.ID, job.LeaseToken, err); exhaustErr != nil {
				return true, exhaustErr
			}
		}
		r.observe(ctx, job, "exhausted", err)
		return true, err
	} else {
		err = r.Executor.ExecuteExport(ctx, job)
	}
	if err == nil {
		if transitionErr := r.Store.CompleteExportJob(ctx, job.ID, job.LeaseToken); transitionErr != nil {
			err = transitionErr
		} else {
			r.observe(ctx, job, "completed", nil)
			return true, nil
		}
	}
	if retryErr := RetryExportJob(ctx, r.Store, job, now, r.MaxAttempts); retryErr == nil {
		r.observe(ctx, job, "retry_scheduled", err)
		return true, nil
	} else if errors.Is(retryErr, ErrExportRetryExhausted) {
		if exhaustErr := r.Store.ExhaustExportJob(ctx, job.ID, job.LeaseToken, err); exhaustErr != nil {
			return true, exhaustErr
		}
		r.observe(ctx, job, "exhausted", err)
		return true, nil
	} else {
		return true, retryErr
	}
}

func (r *ExportRuntime) observe(ctx context.Context, job ExportJob, state string, err error) {
	if r.Observer != nil {
		r.Observer.ObserveExportRuntime(ctx, job, state, err)
	}
}

func RetryExportJob(ctx context.Context, store ExportRuntimeStore, job ExportJob, now time.Time, max int) error {
	if store == nil {
		return ErrExportUnavailable
	}
	if max < 1 || job.ID == uuid.Nil || job.ExportID == uuid.Nil || job.LeaseToken == uuid.Nil || job.Attempts < 0 || job.Status != "running" {
		return ErrInvalidExportJob
	}
	if job.Attempts >= max {
		return ErrExportRetryExhausted
	}
	delay := time.Duration(1<<min(job.Attempts, 10)) * time.Minute
	if delay > time.Hour {
		delay = time.Hour
	}
	return store.FailExportJob(ctx, job.ID, job.LeaseToken, now.Add(delay))
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
