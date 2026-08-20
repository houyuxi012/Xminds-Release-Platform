package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/product"
	releasedomain "xminds-release-platform/internal/release"
	"xminds-release-platform/migrations"
)

func TestReleaseDatabaseEnforcesWorkflowIdempotencyAndImmutability(t *testing.T) {
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

	productID := "release-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, productID)
	insertReleaseIntegrationChannels(t, ctx, pool, productID)
	artifactID := insertReleaseIntegrationArtifact(t, ctx, pool, productID)
	publisher := identity.Principal{
		Subject: "release-publisher", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RolePublisher}, ProductIDs: []string{productID},
	}
	approver := identity.Principal{
		Subject: "release-approver", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RoleApprover}, ProductIDs: []string{productID},
	}
	repository := releasedomain.NewPostgresRepository(pool)
	service := releasedomain.NewService(
		repository, releasedomain.PoolTransactor{Pool: pool}, product.NewPostgresRepository(pool),
		releaseIntegrationArtifactReader{repository: artifact.NewPostgresRepository(pool)},
		audit.NewService(audit.NewPostgresRepository(pool)), jobs.NewPostgresRepository(pool),
	)
	command := releaseIntegrationCreateCommand(productID, artifactID)
	request := releasedomain.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.60"}
	created, err := service.Create(ctx, publisher, command, request)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := service.Create(ctx, publisher, command, request); !errors.Is(err, releasedomain.ErrReleaseVersionExists) {
		t.Fatalf("duplicate Create() error = %v, want %v", err, releasedomain.ErrReleaseVersionExists)
	}
	submitted, err := service.Submit(ctx, publisher, productID, created.ID, created.LockVersion, request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := service.Approve(ctx, approver, productID, created.ID, created.LockVersion, request); !errors.Is(err, releasedomain.ErrStaleRelease) {
		t.Fatalf("stale Approve() error = %v, want %v", err, releasedomain.ErrStaleRelease)
	}
	approved, err := service.Approve(ctx, approver, productID, submitted.ID, submitted.LockVersion, request)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	type publishResult struct {
		result releasedomain.OperationResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan publishResult, 2)
	var publishers sync.WaitGroup
	for range 2 {
		publishers.Add(1)
		go func() {
			defer publishers.Done()
			<-start
			result, publishErr := service.Publish(ctx, publisher, productID, approved.ID, approved.LockVersion, "release-publish-12345678", request)
			results <- publishResult{result: result, err: publishErr}
		}()
	}
	close(start)
	publishers.Wait()
	close(results)
	collected := make([]releasedomain.OperationResult, 0, 2)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent idempotent Publish() error = %v", result.err)
		}
		collected = append(collected, result.result)
	}
	first, second := collected[0], collected[1]
	if second.Attempt.ID != first.Attempt.ID || second.Release.Status != releasedomain.StatusPublishing {
		t.Fatalf("idempotent Publish() results: first=%#v second=%#v", first, second)
	}

	var attemptCount, jobCount, publishAuditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM release_attempts WHERE release_id = $1`, created.ID).Scan(&attemptCount); err != nil {
		t.Fatalf("query release attempts: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE aggregate_id = $1 AND kind = 'catalog.publish.v1'`, created.ID).Scan(&jobCount); err != nil {
		t.Fatalf("query publication jobs: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'release.publish'`, created.ID.String()).Scan(&publishAuditCount); err != nil {
		t.Fatalf("query publication audit: %v", err)
	}
	if attemptCount != 1 || jobCount != 1 || publishAuditCount != 1 {
		t.Fatalf("attempts=%d jobs=%d publish_audits=%d, want 1/1/1", attemptCount, jobCount, publishAuditCount)
	}
	loadedByID, err := repository.GetByID(ctx, created.ID)
	if err != nil || loadedByID.ID != created.ID {
		t.Fatalf("GetByID() release=%#v error=%v", loadedByID, err)
	}
	loadedAttempt, err := repository.GetAttemptByID(ctx, first.Attempt.ID)
	if err != nil || loadedAttempt.ID != first.Attempt.ID {
		t.Fatalf("GetAttemptByID() attempt=%#v error=%v", loadedAttempt, err)
	}
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.CompletePublication(ctx, tx, created.ID, first.Attempt.ID, completedAt)
	}); err != nil {
		t.Fatalf("CompletePublication() error = %v", err)
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.CompletePublication(ctx, tx, created.ID, first.Attempt.ID, completedAt)
	}); err != nil {
		t.Fatalf("idempotent CompletePublication() error = %v", err)
	}
	completedRelease, err := repository.GetByID(ctx, created.ID)
	if err != nil || completedRelease.Status != releasedomain.StatusPublished {
		t.Fatalf("completed release=%#v error=%v", completedRelease, err)
	}
	completedAttempt, err := repository.GetAttemptByID(ctx, first.Attempt.ID)
	if err != nil || completedAttempt.Status != releasedomain.AttemptStatusSucceeded {
		t.Fatalf("completed attempt=%#v error=%v", completedAttempt, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE releases SET version = '9.9.9', lock_version = lock_version + 1 WHERE id = $1`, created.ID); err == nil {
		t.Fatal("immutable release version was updated")
	}

	rollbackCommand := releaseIntegrationCreateCommand(productID, artifactID)
	rollbackCommand.Version = "1.2.4"
	rollbackCommand.Source.Tag = "v1.2.4"
	rollbackRelease, err := service.Create(ctx, publisher, rollbackCommand, request)
	if err != nil {
		t.Fatalf("Create(rollback release) error = %v", err)
	}
	rollbackRelease, err = service.Submit(ctx, publisher, productID, rollbackRelease.ID, rollbackRelease.LockVersion, request)
	if err != nil {
		t.Fatalf("Submit(rollback release) error = %v", err)
	}
	rollbackRelease, err = service.Approve(ctx, approver, productID, rollbackRelease.ID, rollbackRelease.LockVersion, request)
	if err != nil {
		t.Fatalf("Approve(rollback release) error = %v", err)
	}
	failingService := releasedomain.NewService(
		repository, releasedomain.PoolTransactor{Pool: pool}, product.NewPostgresRepository(pool),
		releaseIntegrationArtifactReader{repository: artifact.NewPostgresRepository(pool)},
		failingReleaseAuditAppender{}, jobs.NewPostgresRepository(pool),
	)
	if _, err := failingService.Publish(ctx, publisher, productID, rollbackRelease.ID, rollbackRelease.LockVersion, "release-rollback-12345678", request); err == nil {
		t.Fatal("Publish() succeeded despite audit failure")
	}
	rolledBack, err := service.Get(ctx, publisher, productID, rollbackRelease.ID)
	if err != nil {
		t.Fatalf("Get(rollback release) error = %v", err)
	}
	if rolledBack.Status != releasedomain.StatusApproved || rolledBack.LockVersion != rollbackRelease.LockVersion {
		t.Fatalf("release after failed publication transaction = %#v", rolledBack)
	}
	var rollbackAttempts, rollbackJobs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM release_attempts WHERE release_id = $1`, rollbackRelease.ID).Scan(&rollbackAttempts); err != nil {
		t.Fatalf("query rolled back attempts: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE aggregate_id = $1`, rollbackRelease.ID).Scan(&rollbackJobs); err != nil {
		t.Fatalf("query rolled back jobs: %v", err)
	}
	if rollbackAttempts != 0 || rollbackJobs != 0 {
		t.Fatalf("rolled back attempts=%d jobs=%d, want 0/0", rollbackAttempts, rollbackJobs)
	}
	failurePublication, err := service.Publish(ctx, publisher, productID, rollbackRelease.ID, rollbackRelease.LockVersion, "release-dead-letter-12345678", request)
	if err != nil {
		t.Fatalf("Publish(dead-letter release) error = %v", err)
	}
	failedAt := time.Now().UTC().Truncate(time.Microsecond)
	for range 2 {
		if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
			return repository.FailPublication(ctx, tx, rollbackRelease.ID, failurePublication.Attempt.ID, "catalog_signing_failed", failedAt)
		}); err != nil {
			t.Fatalf("idempotent FailPublication() error = %v", err)
		}
	}
	failedRelease, err := repository.GetByID(ctx, rollbackRelease.ID)
	if err != nil || failedRelease.Status != releasedomain.StatusFailed || failedRelease.PublicationFailureCode != "catalog_signing_failed" {
		t.Fatalf("failed release=%#v error=%v", failedRelease, err)
	}
	failedAttempt, err := repository.GetAttemptByID(ctx, failurePublication.Attempt.ID)
	if err != nil || failedAttempt.Status != releasedomain.AttemptStatusFailed || failedAttempt.ErrorCode != "catalog_signing_failed" {
		t.Fatalf("failed attempt=%#v error=%v", failedAttempt, err)
	}
}

type failingReleaseAuditAppender struct{}

func (failingReleaseAuditAppender) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, errors.New("simulated release audit outage")
}

func insertReleaseIntegrationChannels(t *testing.T, ctx context.Context, pool *pgxpool.Pool, productID string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := pool.Exec(ctx, `
INSERT INTO product_channels (product_id, name, display_name, position, created_at)
VALUES ($1, 'stable', 'Stable', 0, $2), ($1, 'preview', 'Preview', 1, $2)
`, productID, now)
	if err != nil {
		t.Fatalf("insert release product channels: %v", err)
	}
}

type releaseIntegrationArtifactReader struct {
	repository *artifact.PostgresRepository
}

func (reader releaseIntegrationArtifactReader) Get(ctx context.Context, _ identity.Principal, productID string, artifactID uuid.UUID) (artifact.Artifact, error) {
	return reader.repository.GetArtifact(ctx, productID, artifactID)
}

func insertReleaseIntegrationArtifact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, productID string) uuid.UUID {
	t.Helper()
	artifactID := uuid.Must(uuid.NewV7())
	digestBytes := sha256.Sum256([]byte(productID + ":release-artifact"))
	digest := hex.EncodeToString(digestBytes[:])
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := pool.Exec(ctx, `
INSERT INTO artifacts (id, sha256, size_bytes, object_key, created_by, created_at)
VALUES ($1, $2, 3, $3, 'release-integration', $4)
`, artifactID, digest, artifact.ArtifactObjectKey(digest), now)
	if err != nil {
		t.Fatalf("insert release physical artifact: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO artifact_product_bindings (product_id, artifact_id, artifact_type, filename, content_type, created_by, created_at)
VALUES ($1, $2, 'desktop', 'ngep.tar', 'application/x-tar', 'release-integration', $3)
`, productID, artifactID, now)
	if err != nil {
		t.Fatalf("bind release artifact to product: %v", err)
	}
	return artifactID
}

func releaseIntegrationCreateCommand(productID string, artifactID uuid.UUID) releasedomain.CreateCommand {
	notes := []byte("# Release 1.2.3\n\nIntegration release.")
	compatibility := []byte(`{"os":["darwin"],"arch":["arm64"]}`)
	return releasedomain.CreateCommand{
		ProductID: productID, Channel: "stable", Version: "1.2.3",
		ReleaseNotes: notes, ReleaseNotesSHA256: integrationDigest(notes),
		Compatibility: compatibility, CompatibilitySHA256: integrationDigest(compatibility),
		ArtifactIDs: []uuid.UUID{artifactID},
		Source: releasedomain.Source{
			Repository: "https://github.example.com/xminds/ngep.git",
			CommitSHA:  "0123456789abcdef0123456789abcdef01234567",
			Tag:        "v1.2.3", PipelineRef: "gitlab-ci:pipeline/123456",
		},
	}
}

func integrationDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
