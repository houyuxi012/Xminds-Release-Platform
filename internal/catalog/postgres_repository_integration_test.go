package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestPostgresRepositoryPersistsAndReadsCompleteCatalogVersion(t *testing.T) {
	databaseURL := catalogIntegrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	productID := "catalog-package-" + uuid.NewString()
	releaseID := insertCatalogPackageScope(t, ctx, pool, productID)
	repository := NewPostgresRepository(pool)
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, reserveErr := repository.ReserveVersions(ctx, tx, "", "stable", 1); !errors.Is(reserveErr, ErrVersionsInvalid) {
			t.Fatalf("invalid ReserveVersions() error = %v", reserveErr)
		}
		if createErr := repository.Create(ctx, tx, VersionRecord{}); !errors.Is(createErr, ErrVersionRecordInvalid) {
			t.Fatalf("invalid Create() error = %v", createErr)
		}
		if switchErr := repository.SetCurrent(ctx, tx, "", "stable", uuid.Nil, time.Time{}); !errors.Is(switchErr, ErrVersionRecordInvalid) {
			t.Fatalf("invalid SetCurrent() error = %v", switchErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var versions Versions
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var reserveErr error
		versions, reserveErr = repository.ReserveVersions(ctx, tx, productID, "stable", 1)
		return reserveErr
	}); err != nil {
		t.Fatal(err)
	}
	record := validRepositoryRecord()
	record.ProductID = productID
	record.Channel = "stable"
	record.ReleaseID = releaseID
	record.Versions = versions
	for role, version := range map[Role]uint64{RoleRoot: versions.Root, RoleTargets: versions.Targets, RoleSnapshot: versions.Snapshot, RoleTimestamp: versions.Timestamp, RoleRevocation: versions.Revocation} {
		document := record.Roles[role]
		document.Version = version
		record.Roles[role] = document
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error { return repository.Create(ctx, tx, record) }); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != record.ID || len(stored.Roles) != 5 || stored.PublishedAt != nil {
		t.Fatalf("stored catalog = %+v", stored)
	}
	if _, err := repository.Current(ctx, productID, "stable"); !errors.Is(err, ErrCurrentCatalogNotFound) {
		t.Fatalf("missing Current() error = %v", err)
	}
	switchedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.SetCurrent(ctx, tx, productID, "stable", record.ID, switchedAt)
	}); err != nil {
		t.Fatal(err)
	}
	current, err := repository.Current(ctx, productID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if current.PublishedAt == nil || !current.PublishedAt.Equal(switchedAt) {
		t.Fatalf("published_at = %v, want %v", current.PublishedAt, switchedAt)
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error { return repository.Create(ctx, tx, record) }); !errors.Is(err, ErrVersionRecordExists) {
		t.Fatalf("duplicate Create() error = %v", err)
	}
	if _, err := repository.Get(ctx, uuid.New()); !errors.Is(err, ErrVersionRecordNotFound) {
		t.Fatalf("missing Get() error = %v", err)
	}
}

func TestPostgresRepositoryFindsCrashRecoveryEnvelopeByPublicationAttempt(t *testing.T) {
	databaseURL := catalogIntegrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	productID := "catalog-attempt-" + uuid.NewString()
	releaseID := insertCatalogPackageScope(t, ctx, pool, productID)
	attemptID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
INSERT INTO release_attempts (
    id, release_id, kind, attempt_number, idempotency_key, status, created_by, created_at, updated_at
) VALUES ($1, $2, 'publish', 1, 'catalog-attempt-recovery', 'pending', 'publisher', $3, $3)
`, attemptID, releaseID, now); err != nil {
		t.Fatal(err)
	}
	repository := NewPostgresRepository(pool)
	var versions Versions
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var reserveErr error
		versions, reserveErr = repository.ReserveVersions(ctx, tx, productID, "stable", 1)
		return reserveErr
	}); err != nil {
		t.Fatal(err)
	}
	record := validRepositoryRecord()
	record.ProductID = productID
	record.Channel = "stable"
	record.ReleaseID = releaseID
	record.AttemptID = attemptID
	record.Versions = versions
	for role, version := range map[Role]uint64{RoleRoot: versions.Root, RoleTargets: versions.Targets, RoleSnapshot: versions.Snapshot, RoleTimestamp: versions.Timestamp, RoleRevocation: versions.Revocation} {
		document := record.Roles[role]
		document.Version = version
		document.Envelope = []byte(`{"signed":{"_type":"` + string(role) + `"},"signatures":[{"keyid":"test","sig":"test"}]}`)
		record.Roles[role] = document
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error { return repository.Create(ctx, tx, record) }); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.FindByAttempt(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != record.ID || stored.AttemptID != attemptID {
		t.Fatalf("stored record = %+v", stored)
	}
	for role, document := range stored.Roles {
		if len(document.Envelope) == 0 {
			t.Fatalf("role %s envelope is empty", role)
		}
	}
}

func TestPostgresRepositoryRejectsMissingDependenciesAndTransactions(t *testing.T) {
	var repository *PostgresRepository
	if _, err := repository.Get(context.Background(), uuid.New()); !errors.Is(err, ErrRepositoryRequired) {
		t.Fatalf("nil Get() error = %v", err)
	}
	if _, err := repository.Current(context.Background(), "product", "stable"); !errors.Is(err, ErrRepositoryRequired) {
		t.Fatalf("nil Current() error = %v", err)
	}
	repository = &PostgresRepository{}
	if _, err := repository.ReserveVersions(context.Background(), nil, "product", "stable", 1); !errors.Is(err, ErrTransactionRequired) {
		t.Fatalf("nil ReserveVersions() tx error = %v", err)
	}
	if err := repository.Create(context.Background(), nil, VersionRecord{}); !errors.Is(err, ErrTransactionRequired) {
		t.Fatalf("nil Create() tx error = %v", err)
	}
	if err := repository.SetCurrent(context.Background(), nil, "product", "stable", uuid.New(), time.Now()); !errors.Is(err, ErrTransactionRequired) {
		t.Fatalf("nil SetCurrent() tx error = %v", err)
	}
}

func catalogIntegrationDatabaseURL(t *testing.T) string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_DATABASE_URL"))
	if raw == "" {
		t.Skip("XMINDS_RELEASE_TEST_DATABASE_URL is not configured")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.Contains(strings.ToLower(strings.TrimPrefix(parsed.Path, "/")), "test") {
		t.Fatalf("refusing unsafe integration database URL %q", raw)
	}
	return raw
}

func insertCatalogPackageScope(t *testing.T, ctx context.Context, tx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, productID string) uuid.UUID {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	manifest := []byte(`{"schema_version":"xminds-product-manifest/v1","product_id":"` + productID + `"}`)
	manifestDigest := sha256.Sum256(manifest)
	if _, err := tx.Exec(ctx, `
INSERT INTO products (
    id, display_name, schema_version, artifact_types, version_scheme, compatibility_keys,
    catalog_format, manifest_json, manifest_digest, status, created_by, created_at, updated_at
)
VALUES ($1, 'Catalog Package Test', 'xminds-product-manifest/v1', ARRAY['desktop'], 'semver', ARRAY[]::TEXT[],
        'xminds-tuf-v1', $2::jsonb, $3, 'active', 'catalog-test', $4, $4)
`, productID, manifest, hex.EncodeToString(manifestDigest[:]), now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO product_channels (product_id, name, display_name, position, created_at)
VALUES ($1, 'stable', 'Stable', 0, $2)
`, productID, now); err != nil {
		t.Fatal(err)
	}
	releaseID := uuid.Must(uuid.NewV7())
	notes := []byte("# Catalog package test")
	notesDigest := sha256.Sum256(notes)
	compatibility := []byte(`{"os":["darwin"]}`)
	compatibilityDigest := sha256.Sum256(compatibility)
	if _, err := tx.Exec(ctx, `
INSERT INTO releases (
    id, product_id, channel_name, version, status, lock_version,
    release_notes, release_notes_sha256, compatibility_bytes, compatibility_json, compatibility_sha256,
    source_repository, source_commit_sha, source_tag, source_pipeline_ref,
    created_by, created_at, updated_at, submitted_by, submitted_at, approved_by, approved_at
)
VALUES ($1, $2, 'stable', '1.2.3', 'PUBLISHING', 4,
        $3, $4, $5, $6::jsonb, $7,
        'https://github.example.com/xminds/catalog.git', '0123456789abcdef0123456789abcdef01234567', 'v1.2.3', 'integration/123',
        'publisher', $8, $8, 'publisher', $8, 'approver', $8)
`, releaseID, productID, string(notes), hex.EncodeToString(notesDigest[:]), compatibility, string(compatibility), hex.EncodeToString(compatibilityDigest[:]), now); err != nil {
		t.Fatal(err)
	}
	return releaseID
}
