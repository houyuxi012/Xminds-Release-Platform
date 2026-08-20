package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	releasedomain "xminds-release-platform/internal/release"
	"xminds-release-platform/migrations"
)

func TestCatalogPublicationPersistsFiveRolesSwitchesAtomicallyAndReplays(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	minioConfig := integrationMinIOConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.NewMinIOStore(minioConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}

	productID := "catalog-publication-test-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, productID)
	insertReleaseIntegrationChannels(t, ctx, pool, productID)
	releaseID := insertCatalogIntegrationRelease(t, ctx, pool, productID)
	attemptID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
INSERT INTO release_attempts (
    id, release_id, kind, attempt_number, idempotency_key, status, created_by, created_at, updated_at
) VALUES ($1, $2, 'publish', 1, 'catalog-publication-integration', 'pending', 'publisher', $3, $3)
`, attemptID, releaseID, now); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(catalog.PublicationJobPayload{ReleaseID: releaseID, AttemptID: attemptID})
	if err != nil {
		t.Fatal(err)
	}
	job := jobs.Job{ID: uuid.New(), Kind: catalog.JobKindCatalogPublish, AggregateID: releaseID, Payload: payload, Attempts: 1}
	builder := &integrationCatalogBuilder{bundle: integrationGoldenBundle(t)}
	catalogRepository := catalog.NewPostgresRepository(pool)
	releaseRepository := releasedomain.NewPostgresRepository(pool)
	service, err := catalog.NewPublicationService(catalog.PublicationConfig{
		Catalogs: catalogRepository, Releases: releaseRepository, Transactor: releasedomain.PoolTransactor{Pool: pool},
		Builder: builder, Store: store, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Handle(ctx, job); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	current, err := catalogRepository.Current(ctx, productID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if current.AttemptID != attemptID || len(current.Roles) != 5 {
		t.Fatalf("current catalog = %+v", current)
	}
	for role, document := range current.Roles {
		if _, err := store.Stat(ctx, document.ObjectKey); err != nil {
			t.Fatalf("Stat(%s) error = %v", role, err)
		}
	}
	if _, err := store.Stat(ctx, "catalogs/current/timestamp.json"); !errors.Is(err, objectstore.ErrObjectNotFound) {
		t.Fatalf("mutable current object error = %v", err)
	}
	completed, err := releaseRepository.GetByID(ctx, releaseID)
	if err != nil || completed.Status != releasedomain.StatusPublished {
		t.Fatalf("published release=%#v error=%v", completed, err)
	}
	if err := service.Handle(ctx, job); err != nil {
		t.Fatalf("replayed Handle() error = %v", err)
	}
	if builder.calls != 1 {
		t.Fatalf("builder calls = %d, want 1", builder.calls)
	}
}

type integrationCatalogBuilder struct {
	bundle catalog.Bundle
	calls  int
}

func (builder *integrationCatalogBuilder) RootVersion() uint64 { return 1 }

func (builder *integrationCatalogBuilder) Build(context.Context, releasedomain.Release, catalog.Versions) (catalog.Bundle, error) {
	builder.calls++
	return builder.bundle, nil
}

func (builder *integrationCatalogBuilder) BuildRevocation(context.Context, releasedomain.Release, catalog.Versions) (catalog.Bundle, error) {
	builder.calls++
	return builder.bundle, nil
}

func integrationGoldenBundle(t *testing.T) catalog.Bundle {
	t.Helper()
	read := func(name string) []byte {
		payload, err := os.ReadFile("../../internal/catalog/testdata/ngep-golden/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	return catalog.Bundle{
		Root: read("valid-root.json"), Targets: read("valid-targets.json"), Snapshot: read("valid-snapshot.json"),
		Timestamp: read("valid-timestamp.json"), Revocation: read("valid-revocation.json"),
	}
}
