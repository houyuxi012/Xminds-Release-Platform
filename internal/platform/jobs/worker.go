package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

type WorkerConfig struct {
	Owner         string
	Repository    WorkerRepository
	Handlers      *HandlerRegistry
	DeadLetters   DeadLetterHandler
	Clock         func() time.Time
	BatchSize     int
	LeaseDuration time.Duration
	RenewInterval time.Duration
}

type Worker struct {
	owner         string
	repository    WorkerRepository
	handlers      *HandlerRegistry
	deadLetters   DeadLetterHandler
	clock         func() time.Time
	batchSize     int
	leaseDuration time.Duration
	renewInterval time.Duration
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
	return &Worker{
		owner: config.Owner, repository: config.Repository, handlers: config.Handlers,
		deadLetters: config.DeadLetters, clock: config.Clock, batchSize: config.BatchSize,
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
