package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestIdentityDatabaseStoresOnlyAPITokenHash(t *testing.T) {
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

	id := uuid.New()
	secret := strings.Repeat("c4", 24)
	secretHash, err := identity.HashAPITokenSecret(secret)
	if err != nil {
		t.Fatalf("HashAPITokenSecret() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens (
    id, secret_hash, subject, roles, product_ids, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)
`, id, secretHash, "release-automation", []string{"publisher"}, []string{"product-a"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert API token record: %v", err)
	}

	verifier := identity.NewAPITokenVerifier(identity.NewPostgresAPITokenStore(pool))
	principal, err := verifier.Verify(ctx, "xrp."+id.String()+"."+secret)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Subject != "release-automation" || principal.Provider != identity.WorkloadProviderAPIToken {
		t.Fatalf("principal = %#v", principal)
	}
	var storedHash string
	if err := pool.QueryRow(ctx, "SELECT secret_hash FROM api_tokens WHERE id = $1", id).Scan(&storedHash); err != nil {
		t.Fatalf("query stored API token hash: %v", err)
	}
	if storedHash == secret || strings.Contains(storedHash, secret) {
		t.Fatal("raw API token secret was persisted")
	}
}
