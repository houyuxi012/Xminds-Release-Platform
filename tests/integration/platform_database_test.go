package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/migrations"
)

func TestPlatformDatabaseConcurrentLeasesAreDisjoint(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer pool.Close()

	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("database.ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE outbox_jobs, idempotency_keys"); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}

	repository := jobs.NewPostgresRepository(pool)
	const totalJobs = 12
	err = database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		for index := 0; index < totalJobs; index++ {
			job, newErr := jobs.New(
				"release.catalog.publish",
				uuid.New(),
				json.RawMessage(`{"channel":"stable"}`),
				time.Now().Add(-time.Minute),
			)
			if newErr != nil {
				return newErr
			}
			if enqueueErr := repository.Enqueue(ctx, tx, job); enqueueErr != nil {
				return enqueueErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("enqueue jobs: %v", err)
	}

	type leaseResult struct {
		owner string
		jobs  []jobs.Job
		err   error
	}
	start := make(chan struct{})
	results := make(chan leaseResult, 2)
	var waitGroup sync.WaitGroup
	for _, owner := range []string{"worker-a", "worker-b"} {
		owner := owner
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			leased, leaseErr := repository.Lease(ctx, owner, totalJobs/2, time.Minute)
			results <- leaseResult{owner: owner, jobs: leased, err: leaseErr}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	seen := make(map[uuid.UUID]string, totalJobs)
	var ownedJob uuid.UUID
	for result := range results {
		if result.err != nil {
			t.Fatalf("Lease(%q) error = %v", result.owner, result.err)
		}
		for _, job := range result.jobs {
			if previousOwner, exists := seen[job.ID]; exists {
				t.Fatalf("job %s leased by both %q and %q", job.ID, previousOwner, result.owner)
			}
			seen[job.ID] = result.owner
			if result.owner == "worker-a" {
				ownedJob = job.ID
			}
		}
	}
	if len(seen) != totalJobs {
		t.Fatalf("leased jobs = %d, want %d", len(seen), totalJobs)
	}

	if ownedJob == uuid.Nil {
		t.Fatal("worker-a did not lease a job")
	}
	if err := repository.Renew(ctx, "worker-b", ownedJob, time.Minute); !errors.Is(err, jobs.ErrLeaseNotOwned) {
		t.Fatalf("wrong-owner Renew() error = %v, want %v", err, jobs.ErrLeaseNotOwned)
	}
	if err := repository.Renew(ctx, "worker-a", ownedJob, time.Minute); err != nil {
		t.Fatalf("owner Renew() error = %v", err)
	}
	if err := repository.Complete(ctx, "worker-b", ownedJob); !errors.Is(err, jobs.ErrLeaseNotOwned) {
		t.Fatalf("wrong-owner Complete() error = %v, want %v", err, jobs.ErrLeaseNotOwned)
	}
	if err := repository.Complete(ctx, "worker-a", ownedJob); err != nil {
		t.Fatalf("owner Complete() error = %v", err)
	}
}

func TestPlatformDatabaseRejectsMigrationChecksumDrift(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("database.ApplyMigrations() initial error = %v", err)
	}

	modified := fstest.MapFS{
		"000001_platform.up.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	}
	err = database.ApplyMigrations(ctx, pool, modified)
	if err == nil || !strings.Contains(err.Error(), "checksum changed") {
		t.Fatalf("modified migration error = %v, want checksum rejection", err)
	}
}

func integrationDatabaseURL(t *testing.T) string {
	t.Helper()

	rawURL := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_DATABASE_URL"))
	if rawURL == "" {
		t.Skip("XMINDS_RELEASE_TEST_DATABASE_URL is not configured")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse integration database URL: %v", err)
	}
	if !strings.Contains(strings.ToLower(strings.TrimPrefix(parsed.Path, "/")), "test") {
		t.Fatalf("refusing to use database without 'test' in its name: %q", parsed.Path)
	}
	return rawURL
}
