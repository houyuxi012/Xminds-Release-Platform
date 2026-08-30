package integration_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/product"
	"xminds-release-platform/migrations"
)

func TestProductDatabaseRegistersChannelsAndAuditTransactionally(t *testing.T) {
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

	productID := "product-" + uuid.NewString()
	principal := identity.Principal{
		Subject:    "product-admin",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAdmin},
		ProductIDs: []string{productID},
	}
	repository := product.NewPostgresRepository(pool)
	service := product.NewService(repository, product.PoolTransactor{Pool: pool}, audit.NewService(audit.NewPostgresRepository(pool)))
	created, err := service.Register(ctx, principal, integrationManifest(productID), product.RequestContext{
		RequestID: uuid.NewString(),
		SourceIP:  "192.0.2.20",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if created.ID != productID || len(created.Channels) != 2 {
		t.Fatalf("created product = %#v", created)
	}
	stored, err := service.Get(ctx, principal, productID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(stored.Channels) != 2 || stored.Channels[0].Name != "stable" || stored.Channels[1].Name != "preview" {
		t.Fatalf("stored channels = %#v", stored.Channels)
	}
	if _, err := pool.Exec(ctx, `UPDATE products SET manifest_digest = repeat('0', 64) WHERE id = $1`, productID); err == nil {
		t.Fatal("immutable registered manifest digest was updated")
	}
	if _, err := service.Register(ctx, principal, integrationManifest(productID), product.RequestContext{RequestID: uuid.NewString()}); !errors.Is(err, product.ErrProductIDExists) {
		t.Fatalf("duplicate Register() error = %v, want %v", err, product.ErrProductIDExists)
	}

	var eventCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE product_id = $1 AND action = 'product.register'`, productID).Scan(&eventCount); err != nil {
		t.Fatalf("query product audit event: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("product registration audit events = %d, want 1", eventCount)
	}
}

func TestProductDatabaseRollsBackWhenAuditAppendFails(t *testing.T) {
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

	productID := "rollback-" + uuid.NewString()
	principal := identity.Principal{Subject: "product-admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
	service := product.NewService(product.NewPostgresRepository(pool), product.PoolTransactor{Pool: pool}, failingProductAuditAppender{})
	_, err = service.Register(ctx, principal, integrationManifest(productID), product.RequestContext{RequestID: uuid.NewString()})
	if err == nil {
		t.Fatal("Register() succeeded despite audit failure")
	}

	var productCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM products WHERE id = $1`, productID).Scan(&productCount); err != nil {
		t.Fatalf("query rolled back product: %v", err)
	}
	if productCount != 0 {
		t.Fatalf("products after rollback = %d, want 0", productCount)
	}
}

func TestProductDatabaseGovernedPlatformListAppliesExplicitDeny(t *testing.T) {
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

	allowedID := "allowed-" + uuid.NewString()
	deniedID := "denied-" + uuid.NewString()
	repository := product.NewPostgresRepository(pool)
	service := product.NewService(repository, product.PoolTransactor{Pool: pool}, audit.NewService(audit.NewPostgresRepository(pool)))
	for _, productID := range []string{allowedID, deniedID} {
		registrar := identity.Principal{
			Subject: "product-admin", Kind: identity.PrincipalKindHuman,
			Roles: []identity.Role{identity.RoleAdmin}, ProductIDs: []string{productID},
		}
		if _, err := service.Register(ctx, registrar, integrationManifest(productID), product.RequestContext{RequestID: uuid.NewString()}); err != nil {
			t.Fatalf("Register(%q) error = %v", productID, err)
		}
	}

	governed := identity.Principal{
		Subject: "governed-admin", Kind: identity.PrincipalKindLocal, Governed: true,
		AuthenticationAssurance: 1,
		RoleScopes: []identity.RoleScope{
			{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"},
			{Role: identity.RoleViewer, Effect: "deny", ScopeType: "product", ProductID: deniedID},
		},
	}
	page, err := service.List(ctx, governed, product.Page{Limit: 200})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	foundAllowed, foundDenied := false, false
	for _, item := range page.Items {
		foundAllowed = foundAllowed || item.ID == allowedID
		foundDenied = foundDenied || item.ID == deniedID
	}
	if !foundAllowed || foundDenied {
		t.Fatalf("governed list allowed=%t denied=%t, want true/false", foundAllowed, foundDenied)
	}
}

func TestProductDatabaseGovernedPlatformAdministratorRegistersProduct(t *testing.T) {
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

	productID := "governed-" + uuid.NewString()
	principal := identity.Principal{
		Subject: "governed-admin", Kind: identity.PrincipalKindLocal, Governed: true,
		AuthenticationAssurance: 1,
		RoleScopes:              []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
	service := product.NewService(
		product.NewPostgresRepository(pool),
		product.PoolTransactor{Pool: pool},
		audit.NewService(audit.NewPostgresRepository(pool)),
	)
	created, err := service.Register(ctx, principal, integrationManifest(productID), product.RequestContext{
		RequestID: uuid.NewString(), SourceIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if created.ID != productID {
		t.Fatalf("created product = %q, want %q", created.ID, productID)
	}
}

func TestProductDatabaseRegistersManifestWithEmptyCompatibilityKeys(t *testing.T) {
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

	productID := "empty-keys-" + uuid.NewString()
	principal := identity.Principal{
		Subject: "product-admin", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RoleAdmin}, ProductIDs: []string{productID},
	}
	service := product.NewService(
		product.NewPostgresRepository(pool),
		product.PoolTransactor{Pool: pool},
		audit.NewService(audit.NewPostgresRepository(pool)),
	)
	manifest := strings.Replace(string(integrationManifest(productID)), `"compatibility_keys":["os","arch"]`, `"compatibility_keys":[]`, 1)
	created, err := service.Register(ctx, principal, []byte(manifest), product.RequestContext{
		RequestID: uuid.NewString(), SourceIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if created.CompatibilityKeys == nil || len(created.CompatibilityKeys) != 0 {
		t.Fatalf("compatibility keys = %#v, want non-nil empty collection", created.CompatibilityKeys)
	}
}

type failingProductAuditAppender struct{}

func (failingProductAuditAppender) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, errors.New("simulated audit outage")
}

func integrationManifest(productID string) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":"xminds-product-manifest/v1",
  "product_id":%q,
  "display_name":"Integration Product",
  "artifact_types":["desktop"],
  "version_scheme":"semver",
  "compatibility_keys":["os","arch"],
  "catalog_format":"xminds-tuf-v1",
  "default_channels":[
    {"name":"stable","display_name":"Stable"},
    {"name":"preview","display_name":"Preview"}
  ]
}`, productID))
}
