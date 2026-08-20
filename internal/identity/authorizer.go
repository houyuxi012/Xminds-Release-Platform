package identity

import (
	"errors"
	"strings"
)

type Action string

const (
	ActionProductRead       Action = "product.read"
	ActionProductRegister   Action = "product.register"
	ActionProductManage     Action = "product.manage"
	ActionArtifactPublish   Action = "artifact.publish"
	ActionReleaseCreate     Action = "release.create"
	ActionReleaseSubmit     Action = "release.submit"
	ActionReleaseApprove    Action = "release.approve"
	ActionReleasePublish    Action = "release.publish"
	ActionAuditRead         Action = "audit.read"
	ActionIdentityManage    Action = "identity.manage"
	ActionIntegrationManage Action = "integration.manage"
)

var (
	ErrActionDenied       = errors.New("action is not allowed")
	ErrProductIDRequired  = errors.New("product ID is required")
	ErrProductScopeDenied = errors.New("product scope is not allowed")
)

type Authorizer struct {
	permissions map[Role]map[Action]struct{}
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{permissions: map[Role]map[Action]struct{}{
		RoleAdmin: actionSet(
			ActionProductRead,
			ActionProductRegister,
			ActionProductManage,
			ActionArtifactPublish,
			ActionReleaseCreate,
			ActionReleaseSubmit,
			ActionReleaseApprove,
			ActionReleasePublish,
			ActionAuditRead,
			ActionIdentityManage,
			ActionIntegrationManage,
		),
		RolePublisher: actionSet(
			ActionProductRead,
			ActionArtifactPublish,
			ActionReleaseCreate,
			ActionReleaseSubmit,
			ActionReleasePublish,
		),
		RoleApprover: actionSet(
			ActionProductRead,
			ActionReleaseApprove,
		),
		RoleAuditor: actionSet(
			ActionProductRead,
			ActionAuditRead,
		),
		RoleViewer: actionSet(
			ActionProductRead,
		),
	}}
}

func (authorizer *Authorizer) Require(principal Principal, action Action, productID string) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if principal.Governed {
		return authorizer.requireGoverned(principal, action, productID, "")
	}
	if isProductScoped(action) {
		productID = strings.TrimSpace(productID)
		if productID == "" {
			return ErrProductIDRequired
		}
		if !contains(principal.ProductIDs, productID) {
			return ErrProductScopeDenied
		}
	}
	for _, role := range principal.Roles {
		if _, allowed := authorizer.permissions[role][action]; allowed {
			return nil
		}
	}
	return ErrActionDenied
}

func (authorizer *Authorizer) requireGoverned(principal Principal, action Action, productID, channel string) error {
	if isProductScoped(action) && strings.TrimSpace(productID) == "" {
		return ErrProductIDRequired
	}
	allowed := false
	for _, scope := range principal.RoleScopes {
		if _, permits := authorizer.permissions[scope.Role][action]; !permits || !scopeMatches(scope, productID, channel, isProductScoped(action)) {
			continue
		}
		if scope.Effect == "deny" {
			return ErrActionDenied
		}
		if scope.Effect == "allow" {
			allowed = true
		}
	}
	if !allowed {
		return ErrActionDenied
	}
	return nil
}

func scopeMatches(scope RoleScope, productID, channel string, productScoped bool) bool {
	switch scope.ScopeType {
	case "platform":
		return true
	case "product":
		return productScoped && scope.ProductID == strings.TrimSpace(productID)
	case "channel":
		return productScoped && channel != "" && scope.ProductID == strings.TrimSpace(productID) && scope.ChannelName == strings.TrimSpace(channel)
	default:
		return false
	}
}

func (authorizer *Authorizer) Allowed(principal Principal, action Action, productID string) bool {
	return authorizer.Require(principal, action, productID) == nil
}

// RequireProductReadCandidate performs the coarse authorization required before
// loading a product-scoped resource whose persisted channel is not known yet.
// A matching channel allow is sufficient to cross the product boundary, while
// platform and product denies still fail closed. The caller must immediately
// follow a successful resource lookup with RequireInChannel.
func (authorizer *Authorizer) RequireProductReadCandidate(principal Principal, productID string) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if !principal.Governed {
		return authorizer.Require(principal, ActionProductRead, productID)
	}
	productID = strings.TrimSpace(productID)
	if productID == "" {
		return ErrProductIDRequired
	}
	allowed := false
	for _, scope := range principal.RoleScopes {
		if _, permits := authorizer.permissions[scope.Role][ActionProductRead]; !permits {
			continue
		}
		switch scope.ScopeType {
		case "platform":
			if scope.Effect == "deny" {
				return ErrActionDenied
			}
			allowed = allowed || scope.Effect == "allow"
		case "product":
			if scope.ProductID != productID {
				continue
			}
			if scope.Effect == "deny" {
				return ErrActionDenied
			}
			allowed = allowed || scope.Effect == "allow"
		case "channel":
			if scope.ProductID == productID && scope.Effect == "allow" {
				allowed = true
			}
		}
	}
	if !allowed {
		return ErrActionDenied
	}
	return nil
}

func (authorizer *Authorizer) RequireInChannel(principal Principal, action Action, productID, channel string) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if principal.Governed {
		return authorizer.requireGoverned(principal, action, productID, channel)
	}
	return authorizer.Require(principal, action, productID)
}

func actionSet(actions ...Action) map[Action]struct{} {
	result := make(map[Action]struct{}, len(actions))
	for _, action := range actions {
		result[action] = struct{}{}
	}
	return result
}

func isProductScoped(action Action) bool {
	return action != ActionIdentityManage && action != ActionProductRegister
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == wanted {
			return true
		}
	}
	return false
}
