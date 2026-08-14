package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestCatalogDatabaseAllocatesMonotonicVersionsAndSwitchesCurrentAtomically(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
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

	productID := "catalog-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, productID)
	insertReleaseIntegrationChannels(t, ctx, pool, productID)
	releaseID := insertCatalogIntegrationRelease(t, ctx, pool, productID)
	repository := catalog.NewPostgresRepository(pool)

	first := reserveCatalogVersions(t, ctx, pool, repository, productID, 3)
	second := reserveCatalogVersions(t, ctx, pool, repository, productID, 3)
	if first != (catalog.Versions{Root: 3, Targets: 1, Snapshot: 1, Timestamp: 1, Revocation: 1}) {
		t.Fatalf("first versions = %+v", first)
	}
	if second != (catalog.Versions{Root: 3, Targets: 2, Snapshot: 2, Timestamp: 2, Revocation: 2}) {
		t.Fatalf("second versions = %+v", second)
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, reserveErr := repository.ReserveVersions(ctx, tx, productID, "stable", 2)
		return reserveErr
	}); !errors.Is(err, catalog.ErrMetadataVersionRollback) {
		t.Fatalf("root rollback error = %v", err)
	}

	firstRecord := catalogIntegrationVersion(productID, releaseID, first)
	secondRecord := catalogIntegrationVersion(productID, releaseID, second)
	for _, record := range []catalog.VersionRecord{firstRecord, secondRecord} {
		if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error { return repository.Create(ctx, tx, record) }); err != nil {
			t.Fatalf("Create(%s) error = %v", record.ID, err)
		}
	}
	if _, err := repository.Current(ctx, productID, "stable"); !errors.Is(err, catalog.ErrCurrentCatalogNotFound) {
		t.Fatalf("Current() before switch error = %v", err)
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.SetCurrent(ctx, tx, productID, "stable", firstRecord.ID, time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.SetCurrent(ctx, tx, productID, "stable", secondRecord.ID, time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	current, err := repository.Current(ctx, productID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != secondRecord.ID || current.Versions != second {
		t.Fatalf("current catalog = %+v", current)
	}
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.SetCurrent(ctx, tx, productID, "stable", firstRecord.ID, time.Now().UTC())
	}); !errors.Is(err, catalog.ErrMetadataVersionRollback) {
		t.Fatalf("current pointer rollback error = %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE catalog_role_documents SET envelope_sha256 = $1 WHERE catalog_version_id = $2 AND role = 'targets'`, repeatIntegration("f", 64), firstRecord.ID); err == nil {
		t.Fatal("immutable catalog role digest was updated")
	}
}

func reserveCatalogVersions(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repository *catalog.PostgresRepository, productID string, rootVersion uint64) catalog.Versions {
	t.Helper()
	var versions catalog.Versions
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var reserveErr error
		versions, reserveErr = repository.ReserveVersions(ctx, tx, productID, "stable", rootVersion)
		return reserveErr
	}); err != nil {
		t.Fatal(err)
	}
	return versions
}

func catalogIntegrationVersion(productID string, releaseID uuid.UUID, versions catalog.Versions) catalog.VersionRecord {
	id := uuid.Must(uuid.NewV7())
	roles := make(map[catalog.Role]catalog.RoleDocument, 5)
	for _, item := range []struct {
		role    catalog.Role
		version uint64
	}{{catalog.RoleRoot, versions.Root}, {catalog.RoleTargets, versions.Targets}, {catalog.RoleSnapshot, versions.Snapshot}, {catalog.RoleTimestamp, versions.Timestamp}, {catalog.RoleRevocation, versions.Revocation}} {
		digest := sha256.Sum256([]byte(id.String() + ":" + string(item.role)))
		roles[item.role] = catalog.RoleDocument{
			Role: item.role, Version: item.version, EnvelopeSHA256: hex.EncodeToString(digest[:]),
			ObjectKey:  "catalogs/" + productID + "/stable/" + id.String() + "/" + string(item.role) + ".json",
			Signatures: json.RawMessage(`[{"keyid":"integration-key","sig":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}]`),
		}
	}
	bundleDigest := sha256.Sum256([]byte(id.String()))
	return catalog.VersionRecord{
		ID: id, ProductID: productID, Channel: "stable", ReleaseID: releaseID,
		Versions: versions, BundleSHA256: hex.EncodeToString(bundleDigest[:]), Roles: roles,
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

func insertCatalogIntegrationRelease(t *testing.T, ctx context.Context, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, productID string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	notes := "# Catalog integration"
	compatibility := `{"os":["darwin"],"arch":["arm64"]}`
	_, err := pool.Exec(ctx, `
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
`, id, productID, notes, integrationDigest([]byte(notes)), []byte(compatibility), compatibility, integrationDigest([]byte(compatibility)), now)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func repeatIntegration(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
