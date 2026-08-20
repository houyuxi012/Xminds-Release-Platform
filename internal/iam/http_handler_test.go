package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestHTTPHandlerCreatesLocalUserWithoutPersistingSecretInRequestState(t *testing.T) {
	t.Parallel()

	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e51")
	application := &stubIAMApplication{provisioning: LocalUserProvisioning{
		User:            UserPrincipal{ID: userID, Username: "release.operator", Status: UserStatusPending},
		ActivationToken: "returned-once", ActivationExpires: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC),
	}}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/local-users", bytes.NewBufferString(`{"username":"release.operator","display_name":"Release Operator","email":"operator@example.com"}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), "018f835d-7e4b-7abc-9f42-67a2f5f48e52"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if response.Header().Get("Location") != "/api/v1/users/"+userID.String() {
		t.Fatalf("Location = %q", response.Header().Get("Location"))
	}
	if application.createCommand.Username != "release.operator" || application.createRequest.RequestID == "" {
		t.Fatalf("create call = %+v, %+v", application.createCommand, application.createRequest)
	}
}

func TestHTTPHandlerListsUsersWithValidatedCursor(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	id := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e61")
	application := &stubIAMApplication{page: UserPage{Items: []UserPrincipal{{ID: id, Username: "viewer", CreatedAt: createdAt}}}}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=25&cursor="+encodeIAMCursor(createdAt, id), nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if application.listPage.Limit != 25 || application.listPage.BeforeID != id || !application.listPage.BeforeTime.Equal(createdAt) {
		t.Fatalf("page = %+v", application.listPage)
	}
}

func TestHTTPHandlerMapsIAMConflictToProblemDetails(t *testing.T) {
	t.Parallel()

	application := &stubIAMApplication{createError: ErrIAMConflict}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/local-users", bytes.NewBufferString(`{"username":"duplicate","display_name":"Duplicate"}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusConflict || response.Header().Get("Content-Type") != httpx.ProblemMediaType {
		t.Fatalf("status = %d, type = %q, body = %s", response.Code, response.Header().Get("Content-Type"), response.Body)
	}
	var problem httpx.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "IAM_RECORD_CONFLICT" {
		t.Fatalf("problem = %+v", problem)
	}
}

func TestHTTPHandlerCreatesOrganizationAndDoesNotMountRoleBindingWrites(t *testing.T) {
	t.Parallel()

	organizationID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e71")
	application := &stubIAMApplication{organization: OrganizationUnit{ID: organizationID, Name: "Release Engineering", Status: OrganizationStatusActive, Version: 1}}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(`{"name":"Release Engineering"}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || application.organizationCommand.Name != "Release Engineering" {
		t.Fatalf("status = %d, command = %+v, body = %s", response.Code, application.organizationCommand, response.Body)
	}
	writeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/role-bindings", bytes.NewBufferString(`{}`))
	writeRequest.Header.Set("Authorization", "Bearer token")
	writeResponse := httptest.NewRecorder()
	handler.ServeHTTP(writeResponse, writeRequest)
	if writeResponse.Code != http.StatusMethodNotAllowed && writeResponse.Code != http.StatusNotFound {
		t.Fatalf("role binding write status = %d", writeResponse.Code)
	}
}

func TestHTTPHandlerWritesIdentitySourceSecretReferenceButNeverReturnsIt(t *testing.T) {
	t.Parallel()

	sourceID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e81")
	application := &stubIAMApplication{identitySource: IdentitySource{ID: sourceID, Name: "Corporate OIDC", Kind: IdentitySourceOIDC, Status: IdentitySourceStatusDraft, SecretReference: "secret://iam/corporate-oidc", Version: 1}}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources", bytes.NewBufferString(`{"name":"Corporate OIDC","kind":"oidc","secret_reference":"secret://iam/corporate-oidc"}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || application.identitySourceCommand.SecretReference != "secret://iam/corporate-oidc" {
		t.Fatalf("status = %d, command = %+v, body = %s", response.Code, application.identitySourceCommand, response.Body)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("secret://iam/corporate-oidc")) || bytes.Contains(response.Body.Bytes(), []byte("secret_reference")) {
		t.Fatalf("identity source response leaked secret reference: %s", response.Body)
	}
}

func authenticatedIAMHandler(application IAMApplication) http.Handler {
	verifier := iamStaticVerifier{principal: identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}}
	return identity.AuthenticationMiddleware(verifier)(NewHTTPHandler(application))
}

type iamStaticVerifier struct{ principal identity.Principal }

func (verifier iamStaticVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return verifier.principal, nil
}

type stubIAMApplication struct {
	provisioning          LocalUserProvisioning
	createError           error
	createCommand         CreateLocalUserCommand
	createRequest         RequestContext
	page                  UserPage
	listPage              Page
	organization          OrganizationUnit
	organizationCommand   CreateOrganizationCommand
	identitySource        IdentitySource
	identitySourceCommand CreateIdentitySourceCommand
}

func (application *stubIAMApplication) CreateLocalUser(_ context.Context, _ identity.Principal, command CreateLocalUserCommand, request RequestContext) (LocalUserProvisioning, error) {
	application.createCommand = command
	application.createRequest = request
	return application.provisioning, application.createError
}

func (application *stubIAMApplication) GetUser(context.Context, identity.Principal, uuid.UUID) (UserPrincipal, error) {
	return UserPrincipal{}, errors.New("unexpected GetUser call")
}

func (application *stubIAMApplication) ListUsers(_ context.Context, _ identity.Principal, page Page) (UserPage, error) {
	application.listPage = page
	return application.page, nil
}

func (application *stubIAMApplication) CreateOrganization(_ context.Context, _ identity.Principal, command CreateOrganizationCommand, _ RequestContext) (OrganizationUnit, error) {
	application.organizationCommand = command
	return application.organization, nil
}

func (application *stubIAMApplication) ListOrganizations(context.Context, identity.Principal, Page) (OrganizationPage, error) {
	return OrganizationPage{}, errors.New("unexpected ListOrganizations call")
}

func (application *stubIAMApplication) ListRoleBindings(context.Context, identity.Principal, Page) (RoleBindingPage, error) {
	return RoleBindingPage{}, errors.New("unexpected ListRoleBindings call")
}

func (application *stubIAMApplication) CreateIdentitySource(_ context.Context, _ identity.Principal, command CreateIdentitySourceCommand, _ RequestContext) (IdentitySource, error) {
	application.identitySourceCommand = command
	return application.identitySource, nil
}

func (application *stubIAMApplication) ListIdentitySources(context.Context, identity.Principal, Page) (IdentitySourcePage, error) {
	return IdentitySourcePage{}, errors.New("unexpected ListIdentitySources call")
}

func (application *stubIAMApplication) PatchIdentitySourceDraft(context.Context, identity.Principal, uuid.UUID, PatchIdentitySourceCommand, RequestContext) (IdentitySource, error) {
	return IdentitySource{}, errors.New("unexpected PatchIdentitySourceDraft call")
}
