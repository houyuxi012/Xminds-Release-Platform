package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/product"
	"xminds-release-platform/migrations"
)

func TestArtifactMinIOMultipartPromotionAndRangeRead(t *testing.T) {
	configuration := integrationMinIOConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := objectstore.NewMinIOStore(configuration)
	if err != nil {
		t.Fatalf("objectstore.NewMinIOStore() error = %v", err)
	}
	if err := store.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() error = %v", err)
	}

	payload := []byte("abc-" + uuid.NewString())
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	stagingKey := "uploads/" + uuid.NewString()
	finalKey := "artifacts/sha256/" + digest[:2] + "/" + digest
	uploadID, err := store.BeginMultipart(ctx, stagingKey, "application/octet-stream")
	if err != nil {
		t.Fatalf("BeginMultipart() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.AbortMultipart(context.Background(), stagingKey, uploadID)
		_ = store.Delete(context.Background(), stagingKey)
	})
	part, err := store.PutPart(ctx, stagingKey, uploadID, 1, bytes.NewReader(payload), int64(len(payload)), digest)
	if err != nil {
		t.Fatalf("PutPart() error = %v", err)
	}
	if err := store.CompleteMultipart(ctx, stagingKey, uploadID, []objectstore.Part{part}); err != nil {
		t.Fatalf("CompleteMultipart() error = %v", err)
	}
	promoted, err := store.Promote(ctx, stagingKey, finalKey)
	if err != nil {
		t.Fatalf("Promote() error = %v", err)
	}
	if promoted.Key != finalKey || promoted.Size != int64(len(payload)) {
		t.Fatalf("Promote() object info = %#v", promoted)
	}
	if _, err := store.Stat(ctx, stagingKey); !errors.Is(err, objectstore.ErrObjectNotFound) {
		t.Fatalf("staging Stat() error = %v, want %v", err, objectstore.ErrObjectNotFound)
	}

	reader, information, err := store.Open(ctx, finalKey, 1, 1)
	if err != nil {
		t.Fatalf("Open(range) error = %v", err)
	}
	defer reader.Close()
	ranged, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read range: %v", err)
	}
	if string(ranged) != "b" || information.Size != int64(len(payload)) {
		t.Fatalf("range = %q, object info = %#v", ranged, information)
	}
}

func TestArtifactServiceCompletesVerifiedUploadWithPostgresAndMinIO(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	configuration := integrationMinIOConfig(t)
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
	store, err := objectstore.NewMinIOStore(configuration)
	if err != nil {
		t.Fatalf("objectstore.NewMinIOStore() error = %v", err)
	}
	if err := store.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() error = %v", err)
	}

	productID := "artifact-e2e-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, productID)
	payload := []byte("verified-service-payload:" + uuid.NewString())
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	principal := identity.Principal{
		Subject: "artifact-integration-publisher", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RolePublisher}, ProductIDs: []string{productID},
	}
	service := artifact.NewService(
		artifact.NewPostgresRepository(pool), artifact.PoolTransactor{Pool: pool},
		product.NewPostgresRepository(pool), store,
		audit.NewService(audit.NewPostgresRepository(pool)), jobs.NewPostgresRepository(pool),
	)
	requestContext := artifact.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.40"}
	upload, err := service.BeginUpload(ctx, principal, artifact.BeginUpload{
		ProductID: productID, ArtifactType: "desktop", Filename: "xminds-10.x.tar",
		ContentType: "application/x-tar", Size: int64(len(payload)), SHA256: digest,
	}, requestContext)
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	if _, err := service.PutPart(ctx, principal, productID, upload.ID, artifact.PutPart{
		PartNumber: 1, Size: int64(len(payload)), SHA256: digest,
	}, bytes.NewReader(payload), requestContext); err != nil {
		t.Fatalf("PutPart() error = %v", err)
	}
	completed, err := service.Complete(ctx, principal, productID, upload.ID, requestContext)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if completed.SHA256 != digest || completed.ObjectKey != artifact.ArtifactObjectKey(digest) {
		t.Fatalf("completed artifact = %#v", completed)
	}
	loaded, err := service.Get(ctx, principal, productID, completed.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if loaded.ID != completed.ID || loaded.SHA256 != digest {
		t.Fatalf("loaded artifact = %#v", loaded)
	}
	stored, err := store.Stat(ctx, artifact.ArtifactObjectKey(digest))
	if err != nil || stored.Size != int64(len(payload)) {
		t.Fatalf("verified object stat = %#v, error = %v", stored, err)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM audit_events
WHERE product_id = $1 AND action IN ('artifact.upload.begin', 'artifact.upload.complete')
`, productID).Scan(&auditCount); err != nil {
		t.Fatalf("query artifact audit events: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("artifact audit events = %d, want 2", auditCount)
	}
}

func integrationMinIOConfig(t *testing.T) objectstore.MinIOConfig {
	t.Helper()
	endpoint := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_MINIO_URL"))
	accessKey := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_MINIO_ACCESS_KEY"))
	secretKey := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_MINIO_SECRET_KEY"))
	bucket := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_MINIO_BUCKET"))
	if endpoint == "" || accessKey == "" || secretKey == "" || bucket == "" {
		t.Skip("MinIO integration environment is not configured")
	}
	return objectstore.MinIOConfig{
		EndpointURL: endpoint,
		Bucket:      bucket,
		AccessKey:   accessKey,
		SecretKey:   secretKey,
	}
}
