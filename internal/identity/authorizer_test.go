package identity

import (
	"errors"
	"testing"
)

func TestApproverCannotApproveOutsideProductScope(t *testing.T) {
	t.Parallel()

	principal := Principal{
		Subject:    "alice",
		Kind:       PrincipalKindHuman,
		Roles:      []Role{RoleApprover},
		ProductIDs: []string{"product-a"},
	}

	err := NewAuthorizer().Require(principal, ActionReleaseApprove, "product-b")
	if !errors.Is(err, ErrProductScopeDenied) {
		t.Fatalf("Require() error = %v, want %v", err, ErrProductScopeDenied)
	}
}

func TestPublisherCannotApproveRelease(t *testing.T) {
	t.Parallel()

	principal := Principal{
		Subject:    "publisher-1",
		Kind:       PrincipalKindHuman,
		Roles:      []Role{RolePublisher},
		ProductIDs: []string{"product-a"},
	}

	err := NewAuthorizer().Require(principal, ActionReleaseApprove, "product-a")
	if !errors.Is(err, ErrActionDenied) {
		t.Fatalf("Require() error = %v, want %v", err, ErrActionDenied)
	}
}

func TestOnlyAdminCanRegisterProductWithoutExistingProductScope(t *testing.T) {
	t.Parallel()

	admin := Principal{Subject: "admin", Kind: PrincipalKindHuman, Roles: []Role{RoleAdmin}}
	if err := NewAuthorizer().Require(admin, ActionProductRegister, ""); err != nil {
		t.Fatalf("admin product registration error = %v", err)
	}
	publisher := Principal{Subject: "publisher", Kind: PrincipalKindHuman, Roles: []Role{RolePublisher}}
	if err := NewAuthorizer().Require(publisher, ActionProductRegister, ""); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("publisher product registration error = %v, want %v", err, ErrActionDenied)
	}
}

func TestAuditorCanReadAuditWithinProductScope(t *testing.T) {
	t.Parallel()

	principal := Principal{
		Subject:    "auditor-1",
		Kind:       PrincipalKindHuman,
		Roles:      []Role{RoleAuditor},
		ProductIDs: []string{"product-a"},
	}

	if err := NewAuthorizer().Require(principal, ActionAuditRead, "product-a"); err != nil {
		t.Fatalf("Require() error = %v", err)
	}
}

func TestAuditorCannotPerformReleaseWrite(t *testing.T) {
	t.Parallel()

	principal := Principal{
		Subject:    "auditor-1",
		Kind:       PrincipalKindHuman,
		Roles:      []Role{RoleAuditor},
		ProductIDs: []string{"product-a"},
	}

	err := NewAuthorizer().Require(principal, ActionReleasePublish, "product-a")
	if !errors.Is(err, ErrActionDenied) {
		t.Fatalf("Require() error = %v, want %v", err, ErrActionDenied)
	}
}

func TestViewerCanReadScopedProductButCannotWrite(t *testing.T) {
	t.Parallel()

	principal := Principal{
		Subject: "viewer-1", Kind: PrincipalKindHuman, Roles: []Role{RoleViewer}, ProductIDs: []string{"product-a"},
	}
	if err := NewAuthorizer().Require(principal, ActionProductRead, "product-a"); err != nil {
		t.Fatalf("viewer product read error = %v", err)
	}
	if err := NewAuthorizer().Require(principal, ActionReleaseCreate, "product-a"); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("viewer release create error = %v", err)
	}
}

func TestLocalAdminIsDevelopmentOnly(t *testing.T) {
	t.Parallel()

	_, err := NewLocalAdminVerifier("production", true)
	if !errors.Is(err, ErrLocalAdminForbidden) {
		t.Fatalf("NewLocalAdminVerifier() error = %v, want %v", err, ErrLocalAdminForbidden)
	}
}
