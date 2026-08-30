package identity

import (
	"sort"
	"strings"
)

// AuditReadScope is the identity-domain representation of the evidence a
// principal may read. The log center adapts it to its query scope without
// reimplementing role-binding precedence.
type AuditReadScope struct {
	AllowGlobal        bool
	AllProducts        bool
	IncludedProductIDs []string
	ExcludedProductIDs []string
}

// ResolveAuditReadScope evaluates admin/auditor bindings with deny precedence.
// Channel bindings are rejected because the log query contract has no channel
// predicate and granting them would overexpose events from other channels.
func ResolveAuditReadScope(principal Principal) (AuditReadScope, error) {
	if err := principal.Validate(); err != nil {
		return AuditReadScope{}, ErrActionDenied
	}
	if !principal.Governed {
		for _, role := range principal.Roles {
			if principal.Kind == PrincipalKindLocal && principal.AuthenticationAssurance < 1 && role == RoleAdmin {
				continue
			}
			if role == RoleAdmin || role == RoleAuditor {
				if len(principal.ProductIDs) == 0 {
					return AuditReadScope{}, ErrActionDenied
				}
				return AuditReadScope{IncludedProductIDs: append([]string(nil), principal.ProductIDs...)}, nil
			}
		}
		return AuditReadScope{}, ErrActionDenied
	}

	allowed := false
	allProducts := false
	allowGlobal := false
	included := make(map[string]struct{})
	excluded := make(map[string]struct{})
	for _, binding := range principal.RoleScopes {
		if binding.Role != RoleAdmin && binding.Role != RoleAuditor {
			continue
		}
		if !scopeAllowedByAuthenticationAssurance(principal, binding) {
			continue
		}
		effect := strings.ToLower(strings.TrimSpace(binding.Effect))
		scopeType := strings.ToLower(strings.TrimSpace(binding.ScopeType))
		switch scopeType {
		case "platform":
			if effect == "deny" {
				return AuditReadScope{}, ErrActionDenied
			}
			if effect != "allow" {
				return AuditReadScope{}, ErrActionDenied
			}
			allowed, allProducts, allowGlobal = true, true, true
		case "product":
			productID := strings.TrimSpace(binding.ProductID)
			if productID == "" {
				return AuditReadScope{}, ErrActionDenied
			}
			switch effect {
			case "deny":
				excluded[productID] = struct{}{}
				delete(included, productID)
			case "allow":
				allowed = true
				if _, denied := excluded[productID]; !denied {
					included[productID] = struct{}{}
				}
			default:
				return AuditReadScope{}, ErrActionDenied
			}
		case "channel":
			return AuditReadScope{}, ErrActionDenied
		default:
			return AuditReadScope{}, ErrActionDenied
		}
	}
	if !allowed || (!allProducts && len(included) == 0) {
		return AuditReadScope{}, ErrActionDenied
	}
	return AuditReadScope{
		AllowGlobal:        allowGlobal,
		AllProducts:        allProducts,
		IncludedProductIDs: mapKeys(included),
		ExcludedProductIDs: mapKeys(excluded),
	}, nil
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
