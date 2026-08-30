package product

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

func TestRegisterTwoProductsWithoutNGEPSpecialCase(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	auditor := &recordingAuditAppender{}
	service := NewService(repository, passThroughTransactor{}, auditor)
	principal := identity.Principal{
		Subject:    "platform-admin",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAdmin},
		ProductIDs: []string{"ngep", "xminds-desktop"},
	}

	for _, fixture := range []string{"testdata/valid-ngep.json", "testdata/valid-second-product.json"} {
		if _, err := service.Register(context.Background(), principal, mustReadFixture(t, fixture), RequestContext{
			RequestID: "019c1547-e880-7831-949c-7302a34724c0",
			SourceIP:  "192.0.2.10",
		}); err != nil {
			t.Fatalf("Register(%q) error = %v", fixture, err)
		}
	}

	page, err := service.List(context.Background(), principal, Page{Limit: 20})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("products = %d, want 2", len(page.Items))
	}
	if len(auditor.commands) != 2 {
		t.Fatalf("audit events = %d, want 2", len(auditor.commands))
	}
	for _, command := range auditor.commands {
		if command.Action != "product.register" || command.Outcome != audit.OutcomeSuccess {
			t.Fatalf("audit command = %#v", command)
		}
	}
}

func TestRegisterRejectsDuplicateIDAndDigest(t *testing.T) {
	t.Parallel()

	service := NewService(newMemoryRepository(), passThroughTransactor{}, &recordingAuditAppender{})
	principal := adminPrincipal("ngep", "other-product")
	raw := mustReadFixture(t, "testdata/valid-ngep.json")
	request := RequestContext{RequestID: "019c1547-e880-7831-949c-7302a34724c1"}

	if _, err := service.Register(context.Background(), principal, raw, request); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	if _, err := service.Register(context.Background(), principal, raw, request); !errors.Is(err, ErrProductIDExists) {
		t.Fatalf("duplicate ID error = %v, want %v", err, ErrProductIDExists)
	}
}

func TestPublisherCannotRegisterProduct(t *testing.T) {
	t.Parallel()

	service := NewService(newMemoryRepository(), passThroughTransactor{}, &recordingAuditAppender{})
	publisher := identity.Principal{
		Subject: "publisher",
		Kind:    identity.PrincipalKindHuman,
		Roles:   []identity.Role{identity.RolePublisher},
	}
	_, err := service.Register(context.Background(), publisher, mustReadFixture(t, "testdata/valid-ngep.json"), RequestContext{
		RequestID: "019c1547-e880-7831-949c-7302a34724c2",
	})
	if !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("Register() error = %v, want %v", err, identity.ErrActionDenied)
	}
}

func TestListAndGetEnforceProductScope(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	service := NewService(repository, passThroughTransactor{}, &recordingAuditAppender{})
	registrar := adminPrincipal()
	request := RequestContext{RequestID: "019c1547-e880-7831-949c-7302a34724c4"}
	for _, fixture := range []string{"testdata/valid-ngep.json", "testdata/valid-second-product.json"} {
		if _, err := service.Register(context.Background(), registrar, mustReadFixture(t, fixture), request); err != nil {
			t.Fatalf("Register(%q) error = %v", fixture, err)
		}
	}
	ngepOnly := adminPrincipal("ngep")
	page, err := service.List(context.Background(), ngepOnly, Page{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "ngep" {
		t.Fatalf("scoped products = %#v", page.Items)
	}
	if _, err := service.Get(context.Background(), ngepOnly, "xminds-desktop"); !errors.Is(err, identity.ErrProductScopeDenied) {
		t.Fatalf("out-of-scope Get() error = %v, want %v", err, identity.ErrProductScopeDenied)
	}
}

func TestGovernedPlatformAdministratorListsAllProductsExceptExplicitDenies(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	service := NewService(repository, passThroughTransactor{}, &recordingAuditAppender{})
	registrar := adminPrincipal()
	request := RequestContext{RequestID: "019c1547-e880-7831-949c-7302a34724c7"}
	for _, fixture := range []string{"testdata/valid-ngep.json", "testdata/valid-second-product.json"} {
		if _, err := service.Register(context.Background(), registrar, mustReadFixture(t, fixture), request); err != nil {
			t.Fatalf("Register(%q) error = %v", fixture, err)
		}
	}

	principal := identity.Principal{
		Subject: "governed-admin", Kind: identity.PrincipalKindLocal, Governed: true,
		AuthenticationAssurance: 1,
		RoleScopes: []identity.RoleScope{
			{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"},
			{Role: identity.RoleViewer, Effect: "deny", ScopeType: "product", ProductID: "xminds-desktop"},
		},
	}
	page, err := service.List(context.Background(), principal, Page{Limit: 20})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "ngep" {
		t.Fatalf("governed products = %#v, want only ngep", page.Items)
	}
}

func TestDeactivateWritesAuditAndPreservesProduct(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	auditor := &recordingAuditAppender{}
	service := NewService(repository, passThroughTransactor{}, auditor)
	principal := adminPrincipal("ngep")
	if _, err := service.Register(context.Background(), principal, mustReadFixture(t, "testdata/valid-ngep.json"), RequestContext{
		RequestID: "019c1547-e880-7831-949c-7302a34724c5",
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	deactivated, err := service.Deactivate(context.Background(), principal, "ngep", RequestContext{
		RequestID: "019c1547-e880-7831-949c-7302a34724c6",
	})
	if err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if deactivated.Status != ProductStatusInactive || deactivated.DeactivatedAt == nil {
		t.Fatalf("deactivated product = %#v", deactivated)
	}
	if len(auditor.commands) != 2 || auditor.commands[1].Action != "product.deactivate" {
		t.Fatalf("audit commands = %#v", auditor.commands)
	}
}

type passThroughTransactor struct{}

func (passThroughTransactor) WithinTransaction(ctx context.Context, fn func(pgx.Tx) error) error {
	return fn(nil)
}

type recordingAuditAppender struct {
	commands []audit.AppendCommand
}

func (appender *recordingAuditAppender) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	appender.commands = append(appender.commands, command)
	return audit.Event{}, nil
}

type memoryRepository struct {
	products map[string]Product
	channels map[string][]Channel
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{products: map[string]Product{}, channels: map[string][]Channel{}}
}

func (repository *memoryRepository) Create(_ context.Context, _ pgx.Tx, product Product, channels []Channel) error {
	if _, exists := repository.products[product.ID]; exists {
		return ErrProductIDExists
	}
	for _, existing := range repository.products {
		if existing.ManifestDigest == product.ManifestDigest {
			return ErrManifestDigestExists
		}
	}
	repository.products[product.ID] = product
	repository.channels[product.ID] = append([]Channel(nil), channels...)
	return nil
}

func (repository *memoryRepository) Get(_ context.Context, productID string) (Product, error) {
	product, exists := repository.products[productID]
	if !exists {
		return Product{}, ErrProductNotFound
	}
	product.Channels = append([]Channel(nil), repository.channels[productID]...)
	return product, nil
}

func (repository *memoryRepository) List(_ context.Context, scope ProductListScope, page Page) (ProductPage, error) {
	allowed := make(map[string]struct{}, len(scope.IncludedProductIDs))
	for _, productID := range scope.IncludedProductIDs {
		allowed[productID] = struct{}{}
	}
	excluded := make(map[string]struct{}, len(scope.ExcludedProductIDs))
	for _, productID := range scope.ExcludedProductIDs {
		excluded[productID] = struct{}{}
	}
	items := make([]Product, 0, len(repository.products))
	for productID, product := range repository.products {
		if _, denied := excluded[productID]; denied {
			continue
		}
		if _, ok := allowed[productID]; !scope.AllProducts && !ok {
			continue
		}
		items = append(items, product)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	if page.Limit > 0 && len(items) > page.Limit {
		items = items[:page.Limit]
	}
	return ProductPage{Items: items}, nil
}

func (repository *memoryRepository) Deactivate(_ context.Context, _ pgx.Tx, productID string, deactivatedAt time.Time) (Product, error) {
	product, exists := repository.products[productID]
	if !exists {
		return Product{}, ErrProductNotFound
	}
	product.Status = ProductStatusInactive
	product.DeactivatedAt = &deactivatedAt
	repository.products[productID] = product
	return product, nil
}

func adminPrincipal(productIDs ...string) identity.Principal {
	return identity.Principal{
		Subject:    "platform-admin",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAdmin},
		ProductIDs: productIDs,
	}
}
