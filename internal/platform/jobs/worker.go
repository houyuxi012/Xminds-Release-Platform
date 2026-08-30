package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultBatchSize     = 10
	defaultLeaseDuration = 30 * time.Second
	defaultRenewInterval = 10 * time.Second
	maximumJobAttempts   = 5
)

var (
	ErrWorkerConfiguration = errors.New("job worker configuration is invalid")
	ErrLeaseLost           = errors.New("job lease was lost")
)

var retryDelays = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute}

type WorkerRepository interface {
	Lease(ctx context.Context, owner string, limit int, lease time.Duration) ([]Job, error)
	Renew(ctx context.Context, owner string, id uuid.UUID, lease time.Duration) error
	Complete(ctx context.Context, owner string, id uuid.UUID) error
	Retry(ctx context.Context, owner string, id uuid.UUID, code string, availableAt time.Time) error
	DeadLetter(ctx context.Context, owner string, id uuid.UUID, code string) error
}

type DeadLetterHandler interface {
	HandleDeadLetter(ctx context.Context, job Job, code string) error
}

// TransactionalDeadLetterHandler applies the domain failure transition and its
// immutable audit record within the outbox settlement transaction supplied by
// the repository.
type TransactionalDeadLetterHandler interface {
	HandleDeadLetterTx(ctx context.Context, tx pgx.Tx, job Job, code string) error
}

type TransactionalDeadLetterRepository interface {
	SettleDeadLetter(ctx context.Context, owner string, id uuid.UUID, code string, transition func(pgx.Tx) error) error
}

type TransactionalDeadLetterResolver interface {
	ResolveTransactionalDeadLetter(kind string) (TransactionalDeadLetterHandler, bool)
}

type WorkerConfig struct {
	Owner                                string
	Repository                           WorkerRepository
	Handlers                             *HandlerRegistry
	DeadLetters                          DeadLetterHandler
	RequiredTransactionalDeadLetterKinds []string
	Clock                                func() time.Time
	BatchSize                            int
	LeaseDuration                        time.Duration
	RenewInterval                        time.Duration
}

type Worker struct {
	owner                            string
	repository                       WorkerRepository
	handlers                         *HandlerRegistry
	deadLetters                      DeadLetterHandler
	requiredTransactionalDeadLetters map[string]struct{}
	clock                            func() time.Time
	batchSize                        int
	leaseDuration                    time.Duration
	renewInterval                    time.Duration
}

func NewWorker(config WorkerConfig) (*Worker, error) {
	config.Owner = strings.TrimSpace(config.Owner)
	if config.BatchSize == 0 {
		config.BatchSize = defaultBatchSize
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = defaultLeaseDuration
	}
	if config.RenewInterval == 0 {
		config.RenewInterval = defaultRenewInterval
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Owner == "" || config.Repository == nil || config.Handlers == nil || config.BatchSize < 1 || config.BatchSize > 10 ||
		config.LeaseDuration <= 0 || config.RenewInterval <= 0 || config.RenewInterval >= config.LeaseDuration {
		return nil, ErrWorkerConfiguration
	}
	requiredTransactional := make(map[string]struct{}, len(config.RequiredTransactionalDeadLetterKinds))
	for _, kind := range config.RequiredTransactionalDeadLetterKinds {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			return nil, ErrWorkerConfiguration
		}
		requiredTransactional[kind] = struct{}{}
	}
	if len(requiredTransactional) > 0 {
		if _, ok := config.Repository.(TransactionalDeadLetterRepository); !ok || config.DeadLetters == nil {
			return nil, ErrWorkerConfiguration
		}
		for kind := range requiredTransactional {
			if !resolvesTransactionalDeadLetter(config.DeadLetters, kind) {
				return nil, fmt.Errorf("%w: transactional dead-letter handler is not registered for %s", ErrWorkerConfiguration, kind)
			}
		}
	}
	return &Worker{
		owner: config.Owner, repository: config.Repository, handlers: config.Handlers,
		deadLetters: config.DeadLetters, requiredTransactionalDeadLetters: requiredTransactional,
		clock: config.Clock, batchSize: config.BatchSize,
		leaseDuration: config.LeaseDuration, renewInterval: config.RenewInterval,
	}, nil
}

func (worker *Worker) RunOnce(ctx context.Context) (int, error) {
	if worker == nil || worker.repository == nil {
		return 0, ErrWorkerConfiguration
	}
	leased, err := worker.repository.Lease(ctx, worker.owner, worker.batchSize, worker.leaseDuration)
	if err != nil {
		return 0, fmt.Errorf("lease jobs: %w", err)
	}
	if len(leased) == 0 {
		return 0, nil
	}
	var waitGroup sync.WaitGroup
	errorsByJob := make(chan error, len(leased))
	for _, job := range leased {
		job := job
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if processErr := worker.process(ctx, job); processErr != nil {
				errorsByJob <- fmt.Errorf("process job %s: %w", job.ID, processErr)
			}
		}()
	}
	waitGroup.Wait()
	close(errorsByJob)
	collected := make([]error, 0, len(errorsByJob))
	for processErr := range errorsByJob {
		collected = append(collected, processErr)
	}
	return len(leased), errors.Join(collected...)
}

func (worker *Worker) Run(ctx context.Context, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		return ErrWorkerConfiguration
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-timer.C:
			processed, err := worker.RunOnce(ctx)
			if err != nil {
				return err
			}
			if processed > 0 {
				timer.Reset(time.Millisecond)
			} else {
				timer.Reset(pollInterval)
			}
		}
	}
}

func (worker *Worker) process(parent context.Context, job Job) error {
	handler, exists := worker.handlers.Resolve(job.Kind)
	if !exists {
		return worker.settle(parent, job, NewCodedError("job_handler_unregistered", errors.New("job handler is not registered")))
	}
	handlerContext, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	result := make(chan error, 1)
	go func() { result <- handler.Handle(handlerContext, job) }()
	ticker := time.NewTicker(worker.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case handlerErr := <-result:
			if cause := context.Cause(handlerContext); cause != nil {
				return cause
			}
			return worker.settle(parent, job, handlerErr)
		case <-ticker.C:
			if err := worker.repository.Renew(parent, worker.owner, job.ID, worker.leaseDuration); err != nil {
				cancel(ErrLeaseLost)
				return fmt.Errorf("%w: %v", ErrLeaseLost, err)
			}
		case <-parent.Done():
			cancel(context.Cause(parent))
			return context.Cause(parent)
		}
	}
}

func (worker *Worker) settle(ctx context.Context, job Job, handlerErr error) error {
	if handlerErr == nil {
		if err := worker.repository.Complete(ctx, worker.owner, job.ID); err != nil {
			return fmt.Errorf("complete job: %w", err)
		}
		return nil
	}
	code := ErrorCode(handlerErr)
	if job.Attempts >= maximumJobAttempts {
		if _, required := worker.requiredTransactionalDeadLetters[job.Kind]; required {
			repository, ok := worker.repository.(TransactionalDeadLetterRepository)
			if !ok {
				return ErrWorkerConfiguration
			}
			transition, err := worker.transactionalDeadLetterTransition(ctx, job, code)
			if err != nil {
				return err
			}
			if transition == nil {
				return fmt.Errorf("%w: transactional dead-letter handler is not registered", ErrWorkerConfiguration)
			}
			if err := repository.SettleDeadLetter(ctx, worker.owner, job.ID, code, transition); err != nil {
				return fmt.Errorf("atomically dead-letter job: %w", err)
			}
			return nil
		}
		if worker.deadLetters != nil {
			if err := worker.deadLetters.HandleDeadLetter(ctx, job, code); err != nil {
				return fmt.Errorf("handle job dead letter domain transition: %w", err)
			}
		}
		if err := worker.repository.DeadLetter(ctx, worker.owner, job.ID, code); err != nil {
			return fmt.Errorf("dead-letter job: %w", err)
		}
		return nil
	}
	delayIndex := job.Attempts - 1
	if delayIndex < 0 {
		delayIndex = 0
	}
	if delayIndex >= len(retryDelays) {
		delayIndex = len(retryDelays) - 1
	}
	availableAt := worker.clock().UTC().Add(retryDelays[delayIndex])
	if err := worker.repository.Retry(ctx, worker.owner, job.ID, code, availableAt); err != nil {
		return fmt.Errorf("retry job: %w", err)
	}
	return nil
}

func (worker *Worker) transactionalDeadLetterTransition(ctx context.Context, job Job, code string) (func(pgx.Tx) error, error) {
	if worker.deadLetters == nil {
		return nil, nil
	}
	if handler, ok := worker.deadLetters.(TransactionalDeadLetterHandler); ok {
		return func(tx pgx.Tx) error { return handler.HandleDeadLetterTx(ctx, tx, job, code) }, nil
	}
	resolver, ok := worker.deadLetters.(TransactionalDeadLetterResolver)
	if !ok {
		return nil, nil
	}
	handler, exists := resolver.ResolveTransactionalDeadLetter(job.Kind)
	if !exists {
		return nil, nil
	}
	return func(tx pgx.Tx) error { return handler.HandleDeadLetterTx(ctx, tx, job, code) }, nil
}

func resolvesTransactionalDeadLetter(deadLetters DeadLetterHandler, kind string) bool {
	if _, ok := deadLetters.(TransactionalDeadLetterHandler); ok {
		return true
	}
	resolver, ok := deadLetters.(TransactionalDeadLetterResolver)
	if !ok {
		return false
	}
	_, exists := resolver.ResolveTransactionalDeadLetter(kind)
	return exists
}
