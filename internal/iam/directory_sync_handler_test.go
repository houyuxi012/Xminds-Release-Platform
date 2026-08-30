package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/platform/jobs"
)

func TestDirectorySyncWorkerPayloadRejectsDuplicateMembers(t *testing.T) {
	jobID, sourceID := uuid.New(), uuid.New()
	payload := []byte(fmt.Sprintf(`{"job_id":%q,"source_id":%q,"mode":"apply","mode":"apply"}`, jobID, sourceID))
	_, err := decodeDirectorySyncJob(jobs.Job{ID: uuid.New(), Kind: JobKindDirectorySync, AggregateID: jobID, Payload: payload})
	if !errors.Is(err, ErrDirectorySyncConfiguration) {
		t.Fatalf("decodeDirectorySyncJob() error=%v", err)
	}
}

func TestDirectorySyncWorkerPayloadRejectsCaseFoldAliases(t *testing.T) {
	jobID, sourceID := uuid.New(), uuid.New()
	payload := []byte(fmt.Sprintf(`{"job_id":%q,"source_id":%q,"mode":"apply","Mode":"preview"}`, jobID, sourceID))
	_, err := decodeDirectorySyncJob(jobs.Job{ID: uuid.New(), Kind: JobKindDirectorySync, AggregateID: jobID, Payload: payload})
	if !errors.Is(err, ErrDirectorySyncConfiguration) {
		t.Fatalf("decodeDirectorySyncJob() error=%v", err)
	}
}

func TestDirectorySyncHandlerRetryResumesFromDurableCursorWithoutRestagingCommittedPage(t *testing.T) {
	jobID, sourceID := uuid.New(), uuid.New()
	payload, err := json.Marshal(DirectorySyncJobPayload{JobID: jobID, SourceID: sourceID, Mode: DirectorySyncModeApply})
	if err != nil {
		t.Fatal(err)
	}
	executor := &directorySyncExecutorFake{
		job:                  DirectorySyncJob{ID: jobID, IdentitySourceID: sourceID, SourceVersion: 5, Mode: DirectorySyncModeApply, Status: DirectorySyncStatusPending, Phase: DirectorySyncPhaseFetch},
		source:               IdentitySource{ID: sourceID, Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, Version: 5},
		crashAfterFirstStage: true,
	}
	adapter := &directorySyncAdapterFake{pages: map[string]SyncPage{
		"":         {Users: []DirectoryUser{{ExternalSubject: "user-1", Username: "alice", DisplayName: "Alice", Enabled: true}}, NextCursor: "cursor-2"},
		"cursor-2": {Users: []DirectoryUser{{ExternalSubject: "user-2", Username: "bob", DisplayName: "Bob", Enabled: true}}, Complete: true},
	}}
	handler, err := NewDirectorySyncHandler(DirectorySyncHandlerConfig{Executor: executor, Directory: adapter, MaximumTransitions: 20})
	if err != nil {
		t.Fatalf("NewDirectorySyncHandler() error = %v", err)
	}
	job := jobs.Job{ID: uuid.New(), Kind: JobKindDirectorySync, AggregateID: jobID, Payload: payload, Attempts: 1}
	if err := handler.Handle(context.Background(), job); err == nil {
		t.Fatal("Handle(first) error = nil, want simulated crash")
	}
	if executor.job.Cursor != "cursor-2" || executor.stagedPages != 1 {
		t.Fatalf("after crash cursor=%q staged=%d", executor.job.Cursor, executor.stagedPages)
	}
	executor.crashAfterFirstStage = false
	job.Attempts = 2
	if err := handler.Handle(context.Background(), job); err != nil {
		t.Fatalf("Handle(retry) error = %v", err)
	}
	if got := adapter.cursors; len(got) != 2 || got[0] != "" || got[1] != "cursor-2" {
		t.Fatalf("adapter cursors = %v", got)
	}
	if executor.stagedPages != 2 || executor.job.Status != DirectorySyncStatusCompleted {
		t.Fatalf("completed job=%#v staged=%d", executor.job, executor.stagedPages)
	}
}

func TestDirectorySyncHandlerOperationDeadlineDoesNotResetAcrossSyncPages(t *testing.T) {
	jobID, sourceID := uuid.New(), uuid.New()
	payload, err := json.Marshal(DirectorySyncJobPayload{JobID: jobID, SourceID: sourceID, Mode: DirectorySyncModeApply})
	if err != nil {
		t.Fatal(err)
	}
	executor := &directorySyncExecutorFake{
		job:    DirectorySyncJob{ID: jobID, IdentitySourceID: sourceID, SourceVersion: 5, Mode: DirectorySyncModeApply, Status: DirectorySyncStatusPending, Phase: DirectorySyncPhaseFetch},
		source: IdentitySource{ID: sourceID, Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, Version: 5},
	}
	adapter := &slowDirectorySyncAdapter{delay: 70 * time.Millisecond}
	handler, err := NewDirectorySyncHandler(DirectorySyncHandlerConfig{
		Executor: executor, Directory: adapter, MaximumTransitions: 20, OperationTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = handler.Handle(context.Background(), jobs.Job{ID: uuid.New(), Kind: JobKindDirectorySync, AggregateID: jobID, Payload: payload, Attempts: 1})
	if err == nil || jobs.ErrorCode(err) != "directory_upstream_rejected" || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("Handle() error=%v code=%q elapsed=%v", err, jobs.ErrorCode(err), time.Since(started))
	}
	if adapter.calls != 2 {
		t.Fatalf("Sync calls=%d, want shared deadline to stop on second page", adapter.calls)
	}
}

func TestDirectorySyncHandlerFailsClosedWhenSourceVersionChanges(t *testing.T) {
	jobID, sourceID := uuid.New(), uuid.New()
	payload, _ := json.Marshal(DirectorySyncJobPayload{JobID: jobID, SourceID: sourceID, Mode: DirectorySyncModePreview})
	executor := &directorySyncExecutorFake{
		job:    DirectorySyncJob{ID: jobID, IdentitySourceID: sourceID, SourceVersion: 4, Mode: DirectorySyncModePreview, Status: DirectorySyncStatusPending, Phase: DirectorySyncPhaseFetch},
		source: IdentitySource{ID: sourceID, Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, Version: 5},
	}
	handler, err := NewDirectorySyncHandler(DirectorySyncHandlerConfig{Executor: executor, Directory: &directorySyncAdapterFake{}, MaximumTransitions: 5})
	if err != nil {
		t.Fatal(err)
	}
	err = handler.Handle(context.Background(), jobs.Job{ID: uuid.New(), Kind: JobKindDirectorySync, AggregateID: jobID, Payload: payload, Attempts: 1})
	if err != nil || executor.job.Status != DirectorySyncStatusFailed || executor.job.ErrorCode != "directory_source_changed" {
		t.Fatalf("Handle() error=%v job=%#v", err, executor.job)
	}
}

func TestDirectorySyncHandlerDeadLetterIsIdempotentAndRedactsWorkerError(t *testing.T) {
	jobID, sourceID := uuid.New(), uuid.New()
	payload, _ := json.Marshal(DirectorySyncJobPayload{JobID: jobID, SourceID: sourceID, Mode: DirectorySyncModeApply})
	executor := &directorySyncExecutorFake{job: DirectorySyncJob{ID: jobID, IdentitySourceID: sourceID, Status: DirectorySyncStatusRunning}}
	handler, err := NewDirectorySyncHandler(DirectorySyncHandlerConfig{Executor: executor, Directory: &directorySyncAdapterFake{}, MaximumTransitions: 5})
	if err != nil {
		t.Fatal(err)
	}
	job := jobs.Job{ID: uuid.New(), Kind: JobKindDirectorySync, AggregateID: jobID, Payload: payload, Attempts: 5}
	if err := handler.HandleDeadLetter(context.Background(), job, "directory_upstream_rejected"); err != nil {
		t.Fatalf("HandleDeadLetter(first) error = %v", err)
	}
	if err := handler.HandleDeadLetter(context.Background(), job, "token=must-not-leak"); err != nil {
		t.Fatalf("HandleDeadLetter(retry) error = %v", err)
	}
	if executor.failCalls != 2 || executor.job.Status != DirectorySyncStatusFailed || executor.job.ErrorCode != "directory_upstream_rejected" {
		t.Fatalf("dead-letter job=%#v calls=%d", executor.job, executor.failCalls)
	}
}

type directorySyncExecutorFake struct {
	job                  DirectorySyncJob
	source               IdentitySource
	stagedPages          int
	failCalls            int
	crashAfterFirstStage bool
}

func (executor *directorySyncExecutorFake) Load(context.Context, uuid.UUID, uuid.UUID) (DirectorySyncJob, IdentitySource, error) {
	return executor.job, executor.source, nil
}

func (executor *directorySyncExecutorFake) Stage(_ context.Context, job DirectorySyncJob, _ IdentitySource, page SyncPage) error {
	executor.stagedPages++
	executor.job.Status = DirectorySyncStatusRunning
	executor.job.Cursor = page.NextCursor
	if page.Complete {
		executor.job.Phase = DirectorySyncPhasePrepare
	}
	if executor.crashAfterFirstStage && executor.stagedPages == 1 {
		return errors.New("simulated process crash after commit")
	}
	return nil
}

func (executor *directorySyncExecutorFake) Advance(_ context.Context, job DirectorySyncJob, _ IdentitySource) (DirectorySyncJob, error) {
	executor.job = job
	switch executor.job.Phase {
	case DirectorySyncPhasePrepare:
		if executor.job.Mode == DirectorySyncModePreview {
			executor.job.Status = DirectorySyncStatusCompleted
		} else {
			executor.job.Phase = DirectorySyncPhaseUsers
		}
	case DirectorySyncPhaseUsers:
		executor.job.Phase = DirectorySyncPhaseOrganizations
	case DirectorySyncPhaseOrganizations:
		executor.job.Phase = DirectorySyncPhaseMemberships
	case DirectorySyncPhaseMemberships:
		executor.job.Phase = DirectorySyncPhaseFinalize
	case DirectorySyncPhaseFinalize:
		executor.job.Status = DirectorySyncStatusCompleted
	}
	return executor.job, nil
}

func (executor *directorySyncExecutorFake) Fail(_ context.Context, _, _ uuid.UUID, code string) error {
	executor.failCalls++
	if executor.job.Status == DirectorySyncStatusFailed {
		return nil
	}
	executor.job.Status = DirectorySyncStatusFailed
	executor.job.ErrorCode = code
	executor.job.CompletedAt = time.Now()
	return nil
}

type directorySyncAdapterFake struct {
	pages   map[string]SyncPage
	cursors []string
}

type slowDirectorySyncAdapter struct {
	delay time.Duration
	calls int
}

func (adapter *slowDirectorySyncAdapter) Verify(context.Context, IdentitySource) (CapabilityReport, error) {
	return CapabilityReport{}, nil
}

func (adapter *slowDirectorySyncAdapter) Preview(context.Context, IdentitySource) (SyncDiff, error) {
	return SyncDiff{}, nil
}

func (adapter *slowDirectorySyncAdapter) Sync(ctx context.Context, _ IdentitySource, cursor string) (SyncPage, error) {
	adapter.calls++
	timer := time.NewTimer(adapter.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return SyncPage{}, ctx.Err()
	case <-timer.C:
		return SyncPage{NextCursor: cursor + "x"}, nil
	}
}

func (adapter *directorySyncAdapterFake) Verify(context.Context, IdentitySource) (CapabilityReport, error) {
	return CapabilityReport{Reachable: true}, nil
}

func (adapter *directorySyncAdapterFake) Preview(context.Context, IdentitySource) (SyncDiff, error) {
	return SyncDiff{}, nil
}

func (adapter *directorySyncAdapterFake) Sync(_ context.Context, _ IdentitySource, cursor string) (SyncPage, error) {
	adapter.cursors = append(adapter.cursors, cursor)
	page, found := adapter.pages[cursor]
	if !found {
		return SyncPage{}, ErrDirectoryResponseInvalid
	}
	return page, nil
}
