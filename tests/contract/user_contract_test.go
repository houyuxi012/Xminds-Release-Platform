package contract_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"

	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
)

func TestMountedUserRoutesHaveOpenAPIOperations(t *testing.T) {
	t.Parallel()

	handler := iam.NewHTTPHandler(userRouteContractApplication{})
	for _, route := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/v1/local-users"},
		{method: http.MethodGet, path: "/api/v1/users"},
		{method: http.MethodGet, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e58"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("runtime %s %s status = %d, want authenticated route status %d", route.method, route.path, response.Code, http.StatusUnauthorized)
		}
	}

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}
	for _, operation := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/v1/local-users"},
		{method: http.MethodGet, path: "/api/v1/users"},
		{method: http.MethodGet, path: "/api/v1/users/{user_id}"},
	} {
		pathItem := document.Paths.Find(operation.path)
		if pathItem == nil || pathItem.GetOperation(operation.method) == nil {
			t.Fatalf("runtime %s %s is not documented", operation.method, operation.path)
		}
	}
}

type userRouteContractApplication struct{}

var _ iam.IAMApplication = userRouteContractApplication{}

func (userRouteContractApplication) CreateLocalUser(context.Context, identity.Principal, iam.CreateLocalUserCommand, iam.RequestContext) (iam.LocalUserProvisioning, error) {
	return iam.LocalUserProvisioning{}, nil
}

func (userRouteContractApplication) GetUser(context.Context, identity.Principal, uuid.UUID) (iam.UserPrincipal, error) {
	return iam.UserPrincipal{}, nil
}

func (userRouteContractApplication) ListUsers(context.Context, identity.Principal, iam.Page) (iam.UserPage, error) {
	return iam.UserPage{}, nil
}

func (userRouteContractApplication) CreateOrganization(context.Context, identity.Principal, iam.CreateOrganizationCommand, iam.RequestContext) (iam.OrganizationUnit, error) {
	return iam.OrganizationUnit{}, nil
}

func (userRouteContractApplication) ListOrganizations(context.Context, identity.Principal, iam.Page) (iam.OrganizationPage, error) {
	return iam.OrganizationPage{}, nil
}

func (userRouteContractApplication) ListRoleBindings(context.Context, identity.Principal, iam.Page) (iam.RoleBindingPage, error) {
	return iam.RoleBindingPage{}, nil
}

func (userRouteContractApplication) CreateRoleBinding(context.Context, identity.Principal, iam.CreateRoleBindingCommand, iam.HighRiskProof, iam.RequestContext) (iam.RoleBinding, error) {
	return iam.RoleBinding{}, nil
}

func (userRouteContractApplication) DeleteRoleBinding(context.Context, identity.Principal, uuid.UUID, int64, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}

func (userRouteContractApplication) DisableUser(context.Context, identity.Principal, uuid.UUID, int64, string, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}

func (userRouteContractApplication) EnableUser(context.Context, identity.Principal, uuid.UUID, int64, string, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}

func (userRouteContractApplication) RevokeUserSessions(context.Context, identity.Principal, uuid.UUID, int64, string, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}

func (userRouteContractApplication) CreateIdentitySource(context.Context, identity.Principal, iam.CreateIdentitySourceCommand, iam.RequestContext) (iam.IdentitySource, error) {
	return iam.IdentitySource{}, nil
}

func (userRouteContractApplication) ListIdentitySources(context.Context, identity.Principal, iam.Page) (iam.IdentitySourcePage, error) {
	return iam.IdentitySourcePage{}, nil
}

func (userRouteContractApplication) PatchIdentitySourceDraft(context.Context, identity.Principal, uuid.UUID, iam.PatchIdentitySourceCommand, iam.RequestContext) (iam.IdentitySource, error) {
	return iam.IdentitySource{}, nil
}

func (userRouteContractApplication) EnableSSO(context.Context, identity.Principal, uuid.UUID, int64, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}

func (userRouteContractApplication) DisableSSO(context.Context, identity.Principal, uuid.UUID, int64, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}
