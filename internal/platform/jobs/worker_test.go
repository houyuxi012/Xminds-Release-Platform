package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWorkerRetriesFirstFailureWithStableDelayAndCode(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 5, 0, 0, 0, time.UTC)
	repository := &workerRepositoryFake{leased: []Job{{ID: uuid.New(), Kind: "catalog.publish.v1", Attempts: 1}}}
	worker := mustWorker(t, WorkerConfig{
		Owner: "worker-a", Repository: repository,
		Handlers: NewHandlerRegistry(map[string]Handler{
			"catalog.publish.v1": HandlerFunc(func(context.Context, Job) error {
				return NewCodedError("catalog_store_unavailable", errors.New("store unavailable"))
			}),
		}),
		Clock: func() time.Time { return now },
	})

	processed, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	if repository.retryCode != "catalog_store_unavailable" {
		t.Fatalf("retry code = %q", repository.retryCode)
	}
	if want := now.Add(5 * time.Second); !repository.retryAt.Equal(want) {
		t.Fatalf("retry at = %v, want %v", repository.retryAt, want)
	}
	if repository.leaseLimit != 10 || repository.leaseDuration != 30*time.Second {
		t.Fatalf("lease limit/duration = %d/%v", repository.leaseLimit, repository.leaseDuration)
	}
}

func TestWorkerDeadLettersFifthFailureAfterDomainFailureTransition(t *testing.T) {
	t.Parallel()

	job := Job{ID: uuid.New(), Kind: "catalog.publish.v1", Attempts: 5}
	repository := &workerRepositoryFake{leased: []Job{job}}
	deadLetters := &deadLetterHandlerFake{}
	worker := mustWorker(t, WorkerConfig{
		Owner: "worker-a", Repository: repository, DeadLetters: deadLetters,
		Handlers: NewHandlerRegistry(map[string]Handler{
			"catalog.publish.v1": HandlerFunc(func(context.Context, Job) error {
				return NewCodedError("catalog_signing_failed", errors.New("signing failed"))
			}),
		}),
	})

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if deadLetters.calls != 1 || deadLetters.code != "catalog_signing_failed" {
		t.Fatalf("dead-letter domain handler calls/code = %d/%q", deadLetters.calls, deadLetters.code)
	}
	if repository.deadLetterCode != "catalog_signing_failed" {
		t.Fatalf("repository dead-letter code = %q", repository.deadLetterCode)
	}
	if repository.retryCode != "" {
		t.Fatalf("fifth failure was retried with %q", repository.retryCode)
	}
}

func TestWorkerCancelsHandlerAndDoesNotCommitWhenLeaseRenewalFails(t *testing.T) {
	t.Parallel()

	repository := &workerRepositoryFake{
		leased:   []Job{{ID: uuid.New(), Kind: "catalog.publish.v1", Attempts: 1}},
		renewErr: ErrLeaseNotOwned,
	}
	handlerCanceled := make(chan struct{})
	worker := mustWorker(t, WorkerConfig{
		Owner: "worker-a", Repository: repository, RenewInterval: time.Millisecond,
		Handlers: NewHandlerRegistry(map[string]Handler{
			"catalog.publish.v1": HandlerFunc(func(ctx context.Context, _ Job) error {
				<-ctx.Done()
				close(handlerCanceled)
				return context.Cause(ctx)
			}),
		}),
	})

	_, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("RunOnce() error = %v, want %v", err, ErrLeaseLost)
	}
	select {
	case <-handlerCanceled:
	case <-time.After(time.Second):
		t.Fatal("handler was not canceled after lease renewal failure")
	}
	if repository.completed || repository.retryCode != "" || repository.deadLetterCode != "" {
		t.Fatal("lost-lease job result was committed")
	}
}

func TestWorkerDoesNotWaitForMisbehavingHandlerAfterLeaseLoss(t *testing.T) {
	t.Parallel()

	repository := &workerRepositoryFake{
		leased:   []Job{{ID: uuid.New(), Kind: "catalog.publish.v1", Attempts: 1}},
		renewErr: ErrLeaseNotOwned,
	}
	unblock := make(chan struct{})
	defer close(unblock)
	worker := mustWorker(t, WorkerConfig{
		Owner: "worker-a", Repository: repository, RenewInterval: time.Millisecond,
		Handlers: NewHandlerRegistry(map[string]Handler{
			"catalog.publish.v1": HandlerFunc(func(context.Context, Job) error {
				<-unblock
				return nil
			}),
		}),
	})
	result := make(chan error, 1)
	go func() {
		_, err := worker.RunOnce(context.Background())
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("RunOnce() error = %v, want %v", err, ErrLeaseLost)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("RunOnce() waited for a handler that ignored lease-loss cancellation")
	}
}

func TestWorkerCompletesSuccessfulRegisteredHandler(t *testing.T) {
	t.Parallel()

	repository := &workerRepositoryFake{leased: []Job{{ID: uuid.New(), Kind: "audit.export.v1", Attempts: 1}}}
	worker := mustWorker(t, WorkerConfig{
		Owner: "worker-a", Repository: repository,
		Handlers: NewHandlerRegistry(map[string]Handler{
			"audit.export.v1": HandlerFunc(func(context.Context, Job) error { return nil }),
		}),
	})

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if !repository.completed {
		t.Fatal("successful job was not completed")
	}
}

func TestDeadLetterRegistryRoutesByJobKind(t *testing.T) {
	t.Parallel()

	catalogHandler := &deadLetterHandlerFake{}
	auditHandler := &deadLetterHandlerFake{}
	registry := NewDeadLetterRegistry(map[string]DeadLetterHandler{
		"catalog.publish.v1": catalogHandler,
		"audit.export.v1":    auditHandler,
	})
	if err := registry.HandleDeadLetter(context.Background(), Job{Kind: "audit.export.v1"}, "audit_export_failed"); err != nil {
		t.Fatal(err)
	}
	if catalogHandler.calls != 0 || auditHandler.calls != 1 {
		t.Fatalf("catalog/audit calls = %d/%d", catalogHandler.calls, auditHandler.calls)
	}
}

func mustWorker(t *testing.T, config WorkerConfig) *Worker {
	t.Helper()
	if config.Clock == nil {
		config.Clock = time.Now
	}
	worker, err := NewWorker(config)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	return worker
}

type workerRepositoryFake struct {
	mu             sync.Mutex
	leased         []Job
	leaseLimit     int
	leaseDuration  time.Duration
	renewErr       error
	completed      bool
	retryCode      string
	retryAt        time.Time
	deadLetterCode string
}

func (repository *workerRepositoryFake) Lease(_ context.Context, _ string, limit int, lease time.Duration) ([]Job, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.leaseLimit = limit
	repository.leaseDuration = lease
	result := append([]Job(nil), repository.leased...)
	repository.leased = nil
	return result, nil
}

func (repository *workerRepositoryFake) Renew(context.Context, string, uuid.UUID, time.Duration) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.renewErr
}

func (repository *workerRepositoryFake) Complete(context.Context, string, uuid.UUID) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.completed = true
	return nil
}

func (repository *workerRepositoryFake) Retry(_ context.Context, _ string, _ uuid.UUID, code string, availableAt time.Time) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.retryCode = code
	repository.retryAt = availableAt
	return nil
}

func (repository *workerRepositoryFake) DeadLetter(_ context.Context, _ string, _ uuid.UUID, code string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.deadLetterCode = code
	return nil
}

type deadLetterHandlerFake struct {
	calls int
	code  string
}

func (handler *deadLetterHandlerFake) HandleDeadLetter(_ context.Context, _ Job, code string) error {
	handler.calls++
	handler.code = code
	return nil
}
