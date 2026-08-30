package integration_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/scm"
	"xminds-release-platform/migrations"
)

func TestSCMDatabasePersistsOnlyEncryptedCredentialsAndImmutableDeliveries(t *testing.T) {
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
    'scm-integration', 'SCM Integration', 'xminds-product-manifest/v1', ARRAY['binary'], 'semver', '{}',
    'xminds-tuf-v1', '{"schema_version":"xminds-product-manifest/v1","product_id":"scm-integration"}',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'active', 'integration-test', clock_timestamp(), clock_timestamp()
) ON CONFLICT (id) DO NOTHING
`)
	if err != nil {
		t.Fatalf("create product fixture: %v", err)
	}
	connectionID := uuid.New()
	_, err = pool.Exec(ctx, `
INSERT INTO scm_connections (
    id, product_id, name, provider, status, api_base_url, resolved_addresses,
    capabilities, certificate_sha256, created_at, updated_at
) VALUES ($1, 'scm-integration', 'GitHub Enterprise', 'github', 'active',
          'https://github.corp/api/v3', ARRAY['10.20.30.40'], '{}',
          'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', clock_timestamp(), clock_timestamp())
`, connectionID)
	if err != nil {
		t.Fatalf("create SCM connection fixture: %v", err)
	}
	repository := scm.NewPostgresRepository(pool)
	cipher, err := scm.NewAESGCMCredentialCipher("integration-key", map[string][]byte{"integration-key": bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := scm.NewCredentialService(repository, repository, cipher, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Rotate(ctx, connectionID, scm.CredentialKindGitHubToken, []byte("plain-provider-secret-one"), "credential-one", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Rotate(ctx, connectionID, scm.CredentialKindGitHubToken, []byte("plain-provider-secret-two"), "credential-two", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || second.Version != 2 {
		t.Fatalf("credential versions = %d/%d", first.Version, second.Version)
	}
	var activeCount, plaintextMatches int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE revoked_at IS NULL),
       count(*) FILTER (WHERE position(convert_to('plain-provider-secret', 'UTF8') in ciphertext) > 0)
FROM scm_credentials WHERE connection_id = $1
`, connectionID).Scan(&activeCount, &plaintextMatches); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 || plaintextMatches != 0 {
		t.Fatalf("active/plaintext matches = %d/%d", activeCount, plaintextMatches)
	}
	var boundCredentialID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT credential_id FROM scm_connections WHERE id = $1`, connectionID).Scan(&boundCredentialID); err != nil || boundCredentialID != second.ID {
		t.Fatalf("bound credential = %s, want %s: %v", boundCredentialID, second.ID, err)
	}
	delivery := scm.Delivery{ID: uuid.New(), ConnectionID: connectionID, EventID: "event-42", EventType: "push", PayloadDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Repository: "acme/ngep", CommitSHA: "abcdefabcdefabcdefabcdefabcdefabcdefabcd", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC()}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error { return repository.CreateDelivery(ctx, tx, delivery) }); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scm_webhook_deliveries SET event_type = 'pipeline' WHERE id = $1`, delivery.ID); err == nil {
		t.Fatal("immutable webhook delivery accepted an update")
	}
}
