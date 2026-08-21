package iam

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	mfaSecretGCLeaseDuration = 30 * time.Second
	mfaSecretGCFailureCode   = "SECRET_DELETE_FAILED"
)

type mfaSecretGCRepository interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	ListDueMFASecretGC(ctx context.Context, at time.Time, limit int) ([]MFASecretGCItem, error)
	LeaseDueMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, at time.Time, leaseToken uuid.UUID, leasedUntil time.Time) (bool, error)
	CompleteMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, leaseToken uuid.UUID) error
	FailMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, leaseToken uuid.UUID, retryAt time.Time, errorCode string, failedAt time.Time) error
	LockMFASecretReference(ctx context.Context, tx pgx.Tx, reference string) error
	MFASecretReferenceIsLive(ctx context.Context, tx pgx.Tx, reference string, at time.Time) (bool, error)
	MFASecretReferenceHasTombstone(ctx context.Context, tx pgx.Tx, reference string) (bool, error)
	EnqueueMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, notBefore, createdAt time.Time) error
}

type MFASecretGCWorkerConfig struct {
	Repository mfaSecretGCRepository
	Secrets    MFASecretStore
	Clock      func() time.Time
}

type MFASecretGCWorker struct {
	repository mfaSecretGCRepository
	secrets    MFASecretStore
	clock      func() time.Time
}

func NewMFASecretGCWorker(config MFASecretGCWorkerConfig) (*MFASecretGCWorker, error) {
	if config.Repository == nil || config.Secrets == nil || config.Clock == nil {
		return nil, ErrIAMConfiguration
	}
	return &MFASecretGCWorker{repository: config.Repository, secrets: config.Secrets, clock: config.Clock}, nil
}

func (worker *MFASecretGCWorker) RunOnce(ctx context.Context) (int, error) {
	if worker == nil || ctx == nil {
		return 0, ErrIAMConfiguration
	}
	now := worker.clock().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return 0, ErrIAMConfiguration
	}
	var runErrors []error
	if err := worker.reconcileOrphans(ctx, now); err != nil {
		runErrors = append(runErrors, err)
	}
	items, err := worker.repository.ListDueMFASecretGC(ctx, now, mfaSecretMaximumBatch)
	if err != nil {
		return 0, errors.Join(append(runErrors, err)...)
	}
	processed := 0
	for _, item := range items {
		if ctx.Err() != nil {
			runErrors = append(runErrors, ctx.Err())
			break
		}
		leaseToken, tokenErr := uuid.NewV7()
		if tokenErr != nil {
			runErrors = append(runErrors, ErrIAMConfiguration)
			continue
		}
		leaseNow := worker.clock().UTC().Truncate(time.Microsecond)
		if leaseNow.IsZero() {
			runErrors = append(runErrors, ErrIAMConfiguration)
			continue
		}
		leased := false
		err := worker.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			var leaseErr error
			leased, leaseErr = worker.repository.LeaseDueMFASecretGC(ctx, tx, item.SecretReference, leaseNow, leaseToken, leaseNow.Add(mfaSecretGCLeaseDuration))
			return leaseErr
		})
		if err != nil {
			runErrors = append(runErrors, err)
			continue
		}
		if !leased {
			continue
		}
		if deleteErr := worker.secrets.Delete(ctx, item.SecretReference); deleteErr != nil {
			failedAt := worker.clock().UTC().Truncate(time.Microsecond)
			if failedAt.IsZero() {
				runErrors = append(runErrors, errors.Join(deleteErr, ErrIAMConfiguration))
				continue
			}
			retryAt := failedAt.Add(mfaSecretGCRetryDelay(item.Attempts))
			persistErr := worker.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
				return worker.repository.FailMFASecretGC(ctx, tx, item.SecretReference, leaseToken, retryAt, mfaSecretGCFailureCode, failedAt)
			})
			runErrors = append(runErrors, errors.Join(deleteErr, persistErr))
			continue
		}
		if err := worker.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			return worker.repository.CompleteMFASecretGC(ctx, tx, item.SecretReference, leaseToken)
		}); err != nil {
			// The leased tombstone remains durable. A later worker can take over
			// after expiry and idempotently repeat Delete before completing it.
			runErrors = append(runErrors, err)
			continue
		}
		processed++
	}
	return processed, errors.Join(runErrors...)
}

func (worker *MFASecretGCWorker) reconcileOrphans(ctx context.Context, now time.Time) error {
	candidates, err := worker.secrets.ListOrphanCandidates(ctx, now.Add(-mfaSecretOrphanGrace), mfaSecretMaximumBatch)
	if err != nil {
		return err
	}
	var reconciliationErrors []error
	for _, reference := range candidates {
		err := worker.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			if err := worker.repository.LockMFASecretReference(ctx, tx, reference); err != nil {
				return err
			}
			live, err := worker.repository.MFASecretReferenceIsLive(ctx, tx, reference, now)
			if err != nil || live {
				return err
			}
			tombstone, err := worker.repository.MFASecretReferenceHasTombstone(ctx, tx, reference)
			if err != nil || tombstone {
				return err
			}
			return worker.repository.EnqueueMFASecretGC(ctx, tx, reference, now, now)
		})
		if err != nil {
			reconciliationErrors = append(reconciliationErrors, err)
		}
	}
	return errors.Join(reconciliationErrors...)
}

func mfaSecretGCRetryDelay(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 5 {
		attempts = 5
	}
	return time.Minute * time.Duration(1<<attempts)
}
