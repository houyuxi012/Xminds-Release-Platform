package logcenter

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validManifestForTest() ExportManifest {
	return ExportManifest{SchemaVersion: 1, FiltersDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ScopeDigest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", RecordCount: 2, ByteSize: 128, DataSHA256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", CreatedAt: time.Unix(1, 0).UTC(), SigningKeyID: "archive-key-1"}
}

func TestExportManifestSignAndVerify(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, signature, err := SignExportManifest(validManifestForTest(), private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExportManifest(manifest, signature, pub); err != nil {
		t.Fatal(err)
	}
	manifest[len(manifest)-2] ^= 1
	if err := VerifyExportManifest(manifest, signature, pub); !errors.Is(err, ErrArchiveSignature) {
		t.Fatalf("err=%v, want signature failure", err)
	}
}

type exportRuntimeFake struct {
	next  time.Time
	job   ExportJob
	found bool
}

func (s *exportRuntimeFake) ClaimExportJob(context.Context, time.Time) (ExportJob, bool, error) {
	return s.job, s.found, nil
}
func (s *exportRuntimeFake) CompleteExportJob(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (s *exportRuntimeFake) FailExportJob(_ context.Context, _ uuid.UUID, _ uuid.UUID, next time.Time) error {
	s.next = next
	return nil
}
func (s *exportRuntimeFake) ExhaustExportJob(context.Context, uuid.UUID, uuid.UUID, error) error {
	return nil
}

type exportExecutorFake struct{ calls int }

func (e *exportExecutorFake) ExecuteExport(context.Context, ExportJob) error { e.calls++; return nil }

func TestExportRuntimeRunOnceClaimsAndCompletes(t *testing.T) {
	store := &exportRuntimeFake{job: ExportJob{ID: uuid.New(), ExportID: uuid.New(), LeaseToken: uuid.New(), Status: "running"}, found: true}
	executor := &exportExecutorFake{}
	runner := &ExportRuntime{Store: store, Executor: executor, MaxAttempts: 3}
	found, err := runner.RunOnce(context.Background())
	if err != nil || !found || executor.calls != 1 {
		t.Fatalf("found=%v err=%v execute_calls=%d", found, err, executor.calls)
	}
}

func TestRetryExportJobRequiresRunningAndUsesBoundedExponentialBackoff(t *testing.T) {
	store := &exportRuntimeFake{}
	job := ExportJob{ID: uuid.New(), ExportID: uuid.New(), LeaseToken: uuid.New(), Attempts: 3, Status: "running"}
	now := time.Unix(100, 0)
	if err := RetryExportJob(context.Background(), store, job, now, 10); err != nil {
		t.Fatal(err)
	}
	if !store.next.Equal(now.Add(8 * time.Minute)) {
		t.Fatalf("next=%s, want %s", store.next, now.Add(8*time.Minute))
	}
	job.Status = "queued"
	if err := RetryExportJob(context.Background(), store, job, now, 10); !errors.Is(err, ErrInvalidExportJob) {
		t.Fatalf("err=%v, want invalid job", err)
	}
}

func TestRetryExportJobRequiresLeaseToken(t *testing.T) {
	store := &exportRuntimeFake{}
	job := ExportJob{ID: uuid.New(), ExportID: uuid.New(), Attempts: 1, Status: "running"}
	if err := RetryExportJob(context.Background(), store, job, time.Unix(100, 0), 3); !errors.Is(err, ErrInvalidExportJob) {
		t.Fatalf("err=%v, want invalid job without lease token", err)
	}
}
