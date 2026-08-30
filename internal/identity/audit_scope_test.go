package identity

import (
	"errors"
	"testing"
)

func TestResolveAuditReadScopePlatformAllowWithProductDeny(t *testing.T) {
	principal := Principal{
		Subject: "auditor", Kind: PrincipalKindHuman, Governed: true,
		RoleScopes: []RoleScope{
			{Role: RoleAuditor, Effect: "allow", ScopeType: "platform"},
			{Role: RoleAuditor, Effect: "deny", ScopeType: "product", ProductID: "restricted"},
		},
	}
	scope, err := ResolveAuditReadScope(principal)
	if err != nil || !scope.AllowGlobal || !scope.AllProducts || len(scope.ExcludedProductIDs) != 1 || scope.ExcludedProductIDs[0] != "restricted" {
		t.Fatalf("scope=%+v err=%v", scope, err)
	}
}

func TestResolveAuditReadScopeRejectsChannelBinding(t *testing.T) {
	principal := Principal{
		Subject: "auditor", Kind: PrincipalKindHuman, Governed: true,
		RoleScopes: []RoleScope{{Role: RoleAuditor, Effect: "deny", ScopeType: "channel", ProductID: "p", ChannelName: "stable"}},
	}
	if _, err := ResolveAuditReadScope(principal); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("error=%v, want action denied", err)
	}
}

func TestResolveAuditReadScopeProductDenyWinsRegardlessOfBindingOrder(t *testing.T) {
	principal := Principal{
		Subject: "auditor", Kind: PrincipalKindHuman, Governed: true,
		RoleScopes: []RoleScope{
			{Role: RoleAuditor, Effect: "deny", ScopeType: "product", ProductID: "p"},
			{Role: RoleAuditor, Effect: "allow", ScopeType: "product", ProductID: "p"},
		},
	}
	if _, err := ResolveAuditReadScope(principal); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("error=%v, want action denied after deny precedence", err)
	}
}

func TestResolveAuditReadScopeRequiresMFAForLocalAdmin(t *testing.T) {
	principal := Principal{
		Subject: "local-admin", Kind: PrincipalKindLocal, Roles: []Role{RoleAdmin}, ProductIDs: []string{"p"},
	}
	if _, err := ResolveAuditReadScope(principal); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("error=%v, want action denied before MFA", err)
	}
}
