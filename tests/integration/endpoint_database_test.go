package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/endpoint"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestEndpointDatabasePersistsHealthEjectionAndProductScopedArtifactLookup(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO products (
    id, display_name, schema_version, artifact_types, version_scheme, compatibility_keys,
    catalog_format, manifest_json, manifest_digest, status, created_by, created_at, updated_at
) VALUES (
    'endpoint-integration', 'Endpoint Integration', 'xminds-product-manifest/v1', ARRAY['binary'], 'semver', '{}',
    'xminds-tuf-v1', '{"schema_version":"xminds-product-manifest/v1","product_id":"endpoint-integration"}',
    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'active', 'integration-test', clock_timestamp(), clock_timestamp()
) ON CONFLICT (id) DO NOTHING
`)
	if err != nil {
		t.Fatal(err)
	}
	endpointID := uuid.New()
	repository := endpoint.NewPostgresRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := endpoint.Endpoint{ID: endpointID, ProductID: "endpoint-integration", Name: "origin-" + endpointID.String(), Type: endpoint.TypeOrigin, Region: "cn-east-1", Priority: 10, BaseURL: "https://download.example", PathPrefix: "/releases", HealthPath: "/health/catalog", Status: endpoint.StatusActive, CreatedAt: now, UpdatedAt: now}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error { return repository.Create(ctx, tx, record) }); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			_, markErr := repository.MarkFailure(ctx, tx, endpointID, now.Add(time.Duration(attempt+1)*time.Minute))
			return markErr
		}); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := repository.Get(ctx, endpointID)
	if err != nil || stored.Status != endpoint.StatusUnhealthy || stored.FailureCount != 3 {
		t.Fatalf("stored endpoint = %+v, %v", stored, err)
	}
	digest := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	artifactID := uuid.New()
	_, err = pool.Exec(ctx, `
INSERT INTO artifacts (id, sha256, size_bytes, object_key, created_by, created_at)
VALUES ($1, $2, 10, $3, 'integration-test', clock_timestamp())
ON CONFLICT (sha256) DO NOTHING
`, artifactID, digest, artifact.ArtifactObjectKey(digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM artifacts WHERE sha256 = $1`, digest).Scan(&artifactID); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO artifact_product_bindings (product_id, artifact_id, artifact_type, filename, content_type, created_by, created_at)
VALUES ('endpoint-integration', $1, 'binary', 'release.bin', 'application/octet-stream', 'integration-test', clock_timestamp())
ON CONFLICT (product_id, artifact_id) DO NOTHING
`, artifactID)
	if err != nil {
		t.Fatal(err)
	}
	item, err := artifact.NewPostgresRepository(pool).GetByDigest(ctx, "endpoint-integration", digest)
	if err != nil || item.ID != artifactID || item.ProductID != "endpoint-integration" {
		t.Fatalf("artifact lookup = %+v, %v", item, err)
	}
}
