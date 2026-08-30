package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestArtifactDatabaseDeduplicatesPhysicalObjectAcrossProducts(t *testing.T) {
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

	firstProductID := "artifact-a-" + uuid.NewString()
	secondProductID := "artifact-b-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, firstProductID)
	insertIntegrationProduct(t, ctx, pool, secondProductID)
	repository := artifact.NewPostgresRepository(pool)
	artifactDigest := sha256.Sum256([]byte(firstProductID + ":" + secondProductID))
	digest := hex.EncodeToString(artifactDigest[:])
	var first artifact.Artifact
	for index, productID := range []string{firstProductID, secondProductID} {
		upload := integrationArtifactUpload(productID, digest, time.Now().UTC().Truncate(time.Microsecond))
		if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
			return repository.CreateUpload(ctx, tx, upload)
		}); err != nil {
			t.Fatalf("CreateUpload(%q) error = %v", productID, err)
		}
		part := artifact.UploadPart{
			UploadID: upload.ID, PartNumber: 1, Size: upload.ExpectedSize,
			SHA256: digest, ETag: "etag-latest", CreatedAt: upload.CreatedAt, UpdatedAt: upload.CreatedAt,
		}
		if err := repository.SavePart(ctx, part); err != nil {
			t.Fatalf("SavePart(%q) error = %v", productID, err)
		}
		part.ETag = "etag-retry"
		part.UpdatedAt = upload.CreatedAt.Add(time.Second)
		if err := repository.SavePart(ctx, part); err != nil {
			t.Fatalf("retry SavePart(%q) error = %v", productID, err)
		}
		parts, err := repository.ListParts(ctx, upload.ID)
		if err != nil {
			t.Fatalf("ListParts(%q) error = %v", productID, err)
		}
		if len(parts) != 1 || parts[0].ETag != "etag-retry" {
			t.Fatalf("parts after retry = %#v", parts)
		}

		candidate := artifact.Artifact{
			ID: uuid.Must(uuid.NewV7()), ProductID: productID, ArtifactType: "desktop",
			Filename: productID + ".tar", ContentType: "application/x-tar",
			Size: upload.ExpectedSize, SHA256: digest, ObjectKey: artifact.ArtifactObjectKey(digest),
			CreatedBy: "publisher-integration", CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		var completed artifact.Artifact
		if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
			var completeErr error
			completed, completeErr = repository.Complete(ctx, tx, upload.ID, candidate)
			return completeErr
		}); err != nil {
			t.Fatalf("Complete(%q) error = %v", productID, err)
		}
		if index == 0 {
			first = completed
		} else if completed.ID != first.ID {
			t.Fatalf("deduplicated artifact ID = %s, want %s", completed.ID, first.ID)
		}
	}

	var physicalCount, bindingCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM artifacts WHERE sha256 = $1`, digest).Scan(&physicalCount); err != nil {
		t.Fatalf("query physical artifacts: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM artifact_product_bindings WHERE artifact_id = $1`, first.ID).Scan(&bindingCount); err != nil {
		t.Fatalf("query product bindings: %v", err)
	}
	if physicalCount != 1 || bindingCount != 2 {
		t.Fatalf("physical artifacts = %d, bindings = %d", physicalCount, bindingCount)
	}
	if _, err := pool.Exec(ctx, `UPDATE artifacts SET sha256 = $2 WHERE id = $1`, first.ID, strings.Repeat("b", 64)); err == nil {
		t.Fatal("immutable artifact digest was updated")
	}
	if _, err := pool.Exec(ctx, `UPDATE artifact_uploads SET status = 'uploading' WHERE artifact_id = $1`, first.ID); err == nil {
		t.Fatal("completed upload returned to uploading")
	}
}

func TestArtifactDatabasePreservesMonotonicTimestampAcrossClockDomains(t *testing.T) {
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

	productID := "artifact-clock-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, productID)
	digestBytes := sha256.Sum256([]byte(productID))
	digest := hex.EncodeToString(digestBytes[:])
	applicationTime := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond)
	upload := integrationArtifactUpload(productID, digest, applicationTime)
	repository := artifact.NewPostgresRepository(pool)
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.CreateUpload(ctx, tx, upload)
	}); err != nil {
		t.Fatalf("CreateUpload() error = %v", err)
	}
	candidate := artifact.Artifact{
		ID: uuid.Must(uuid.NewV7()), ProductID: productID, ArtifactType: "desktop",
		Filename: productID + ".tar", ContentType: "application/x-tar", Size: 3,
		SHA256: digest, ObjectKey: artifact.ArtifactObjectKey(digest),
		CreatedBy: "publisher-integration", CreatedAt: applicationTime,
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, completeErr := repository.Complete(ctx, tx, upload.ID, candidate)
		return completeErr
	}); err != nil {
		t.Fatalf("Complete() across clock domains error = %v", err)
	}
	stored, err := repository.GetUpload(ctx, upload.ID)
	if err != nil {
		t.Fatalf("GetUpload() error = %v", err)
	}
	if stored.UpdatedAt.Before(stored.CreatedAt) {
		t.Fatalf("artifact upload timestamps regressed: created=%s updated=%s", stored.CreatedAt, stored.UpdatedAt)
	}
}

func insertIntegrationProduct(t *testing.T, ctx context.Context, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, productID string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	manifest := integrationManifest(productID)
	manifestDigest := sha256.Sum256(manifest)
	_, err := pool.Exec(ctx, `
INSERT INTO products (
    id, display_name, schema_version, artifact_types, version_scheme,
    compatibility_keys, catalog_format, manifest_json, manifest_digest,
    status, created_by, created_at, updated_at
)
VALUES ($1, 'Artifact Integration Product', 'xminds-product-manifest/v1', ARRAY['desktop'], 'semver',
        ARRAY['os', 'arch'], 'xminds-tuf-v1', $2, $3, 'active', 'integration-test', $4, $4)
`, productID, manifest, hex.EncodeToString(manifestDigest[:]), now)
	if err != nil {
		t.Fatalf("insert product %q: %v", productID, err)
	}
}

func integrationArtifactUpload(productID string, digest string, createdAt time.Time) artifact.Upload {
	uploadID := uuid.Must(uuid.NewV7())
	return artifact.Upload{
		ID: uploadID, ProductID: productID, ArtifactType: "desktop",
		Filename: productID + ".tar", ContentType: "application/x-tar",
		ExpectedSize: 3, ExpectedSHA256: digest,
		StagingKey: "uploads/" + uploadID.String(), ObjectUploadID: "object-upload-" + uploadID.String(),
		Status: artifact.UploadStatusUploading, ExpiresAt: createdAt.Add(artifact.UploadLifetime),
		CreatedBy: "publisher-integration", CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}
