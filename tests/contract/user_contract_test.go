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
		{method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e58/mfa/enrollments"},
		{method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e58/mfa/enrollments/018f835d-7e4b-7abc-9f42-67a2f5f48e59/confirm"},
		{method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e58/mfa/recovery-codes/regenerate"},
		{method: http.MethodPost, path: "/api/v1/emergency-users"},
		{method: http.MethodPost, path: "/api/v1/emergency-users/018f835d-7e4b-7abc-9f42-67a2f5f48e58/activation-token/reissue"},
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
		{method: http.MethodPost, path: "/api/v1/users/{user_id}/mfa/enrollments"},
		{method: http.MethodPost, path: "/api/v1/users/{user_id}/mfa/enrollments/{enrollment_id}/confirm"},
		{method: http.MethodPost, path: "/api/v1/users/{user_id}/mfa/recovery-codes/regenerate"},
		{method: http.MethodPost, path: "/api/v1/emergency-users"},
		{method: http.MethodPost, path: "/api/v1/emergency-users/{user_id}/activation-token/reissue"},
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

func (userRouteContractApplication) GetOrganization(context.Context, identity.Principal, uuid.UUID) (iam.OrganizationUnit, error) {
	return iam.OrganizationUnit{}, nil
}

func (userRouteContractApplication) ListOrganizationChildren(context.Context, identity.Principal, uuid.UUID, iam.Page) (iam.OrganizationPage, error) {
	return iam.OrganizationPage{}, nil
}

func (userRouteContractApplication) ListOrganizationMemberships(context.Context, identity.Principal, uuid.UUID, iam.Page) (iam.OrganizationMembershipPage, error) {
	return iam.OrganizationMembershipPage{}, nil
}

func (userRouteContractApplication) CreateOrganizationMembership(context.Context, identity.Principal, uuid.UUID, iam.CreateOrganizationMembershipCommand, iam.HighRiskProof, iam.RequestContext) (iam.OrganizationMembership, error) {
	return iam.OrganizationMembership{}, nil
}

func (userRouteContractApplication) DeleteOrganizationMembership(context.Context, identity.Principal, uuid.UUID, uuid.UUID, iam.DeleteOrganizationMembershipCommand, iam.HighRiskProof, iam.RequestContext) error {
	return nil
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

func (userRouteContractApplication) GetIdentitySource(context.Context, identity.Principal, uuid.UUID) (iam.IdentitySource, error) {
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

func (userRouteContractApplication) BeginMFARotation(context.Context, identity.Principal, uuid.UUID, iam.BeginMFARotationCommand, iam.HighRiskProof, iam.RequestContext) (iam.MFAEnrollmentStart, error) {
	return iam.MFAEnrollmentStart{}, nil
}

func (userRouteContractApplication) ConfirmMFARotation(context.Context, identity.Principal, uuid.UUID, uuid.UUID, iam.ConfirmMFARotationCommand, iam.RequestContext) (iam.LocalActivationResult, error) {
	return iam.LocalActivationResult{}, nil
}

func (userRouteContractApplication) RegenerateMFARecoveryCodes(context.Context, identity.Principal, uuid.UUID, iam.RegenerateMFARecoveryCodesCommand, iam.HighRiskProof, iam.RequestContext) (iam.LocalActivationResult, error) {
	return iam.LocalActivationResult{}, nil
}

func (userRouteContractApplication) ProvisionEmergencyUser(context.Context, identity.Principal, iam.CreateEmergencyUserCommand, iam.HighRiskProof, iam.RequestContext) (iam.LocalUserProvisioning, error) {
	return iam.LocalUserProvisioning{}, nil
}

func (userRouteContractApplication) ReissueEmergencyActivation(context.Context, identity.Principal, uuid.UUID, iam.ReissueEmergencyActivationCommand, iam.HighRiskProof, iam.RequestContext) (iam.LocalUserProvisioning, error) {
	return iam.LocalUserProvisioning{}, nil
}
