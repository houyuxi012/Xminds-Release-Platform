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
	}}
}

func (authorizer *Authorizer) Require(principal Principal, action Action, productID string) error {
	if err := principal.Validate(); err != nil {
		return err
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

func (authorizer *Authorizer) Allowed(principal Principal, action Action, productID string) bool {
	return authorizer.Require(principal, action, productID) == nil
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
