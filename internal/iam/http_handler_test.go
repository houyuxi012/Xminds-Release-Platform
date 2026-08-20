package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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

func TestHTTPHandlerMapsGovernedStatePreconditionsToConflict(t *testing.T) {
	t.Parallel()
	for name, applicationError := range map[string]error{
		"sso precondition":      ErrSSOPreconditionFailed,
		"login mode transition": ErrLoginModeTransitionInvalid,
		"last emergency admin":  ErrLastEmergencyAdministrator,
		"already disabled":      ErrUserAlreadyDisabled,
		"already enabled":       ErrUserAlreadyEnabled,
		"source unusable":       ErrUserCannotBeEnabled,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
			response := httptest.NewRecorder()
			writeIAMApplicationError(response, request, applicationError)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body)
			}
		})
	}
}

func TestHTTPHandlerCreatesOrganizationAndMountsGovernedRoleBindingWrites(t *testing.T) {
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
	writeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/role-bindings", bytes.NewBufferString(`{
        "subject_type":"user","subject_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e73","subject_version":4,
        "role":"auditor","scope_type":"platform","effect":"allow",
        "reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}
    }`))
	writeRequest.Header.Set("Authorization", "Bearer token")
	writeRequest.Header.Set("Content-Type", "application/json")
	writeResponse := httptest.NewRecorder()
	handler.ServeHTTP(writeResponse, writeRequest)
	if writeResponse.Code != http.StatusCreated || application.highRiskAction != "role_binding.create" || application.roleBindingCommand.SubjectVersion != 4 || !application.highRiskProof.Confirmed {
		t.Fatalf("role binding write status = %d action=%q command=%+v proof=%+v body=%s", writeResponse.Code, application.highRiskAction, application.roleBindingCommand, application.highRiskProof, writeResponse.Body)
	}
}

func TestHTTPHandlerMountsAllGovernedIAMWritesWithStrictVersionsAndProofs(t *testing.T) {
	application := &stubIAMApplication{}
	handler := authenticatedIAMHandler(application)
	for _, testCase := range []struct {
		name, method, path, body, action string
		status                           int
	}{
		{name: "delete binding", method: http.MethodDelete, path: "/api/v1/role-bindings/018f835d-7e4b-7abc-9f42-67a2f5f48e75", body: `{"version":7,"reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}}`, action: "role_binding.delete", status: http.StatusNoContent},
		{name: "disable user", method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e76/disable", body: `{"version":8,"reason":"incident","reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}}`, action: "user.disable", status: http.StatusNoContent},
		{name: "enable user", method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e76/enable", body: `{"version":9,"reason":"incident closed","reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}}`, action: "user.enable", status: http.StatusNoContent},
		{name: "revoke sessions", method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e76/revoke-sessions", body: `{"version":10,"reason":"rotation","reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}}`, action: "user.revoke_sessions", status: http.StatusNoContent},
		{name: "enable sso", method: http.MethodPost, path: "/api/v1/identity-sources/018f835d-7e4b-7abc-9f42-67a2f5f48e77/enable", body: `{"version":11,"reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}}`, action: "sso.enable", status: http.StatusNoContent},
		{name: "disable sso", method: http.MethodPost, path: "/api/v1/identity-sources/018f835d-7e4b-7abc-9f42-67a2f5f48e77/disable", body: `{"version":12,"reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"opaque-once","confirmed":true}}`, action: "sso.disable", status: http.StatusNoContent},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			application.highRiskAction = ""
			request := httptest.NewRequest(testCase.method, testCase.path, bytes.NewBufferString(testCase.body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.status || application.highRiskAction != testCase.action || application.highRiskVersion < 1 || !application.highRiskProof.Confirmed {
				t.Fatalf("status=%d action=%q version=%d proof=%+v body=%s", response.Code, application.highRiskAction, application.highRiskVersion, application.highRiskProof, response.Body)
			}
		})
	}
}

func TestReauthenticationHTTPReturnsEvidenceOnlyFromSuccessfulCompletion(t *testing.T) {
	challengeID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e90")
	application := &stubReauthenticationApplication{
		created:   ReauthenticationChallengeResult{ID: challengeID, Operation: ReauthenticationOperationUserDisable, Status: ReauthenticationStatusPending, ExpiresAt: time.Date(2026, 8, 20, 12, 5, 0, 0, time.UTC)},
		completed: ReauthenticationEvidence{ChallengeID: challengeID, Evidence: "returned-exactly-once", ExpiresAt: time.Date(2026, 8, 20, 12, 2, 0, 0, time.UTC)},
	}
	router := chi.NewRouter()
	RegisterReauthenticationRoutes(router, application)
	handler := identity.AuthenticationMiddleware(iamStaticVerifier{principal: identity.Principal{Subject: "admin", Kind: identity.PrincipalKindLocal, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "018f835d-7e4b-7abc-9f42-67a2f5f48e93"}})(router)

	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth-challenges", bytes.NewBufferString(`{"operation":"identity.user.disable"}`))
	createRequest.Header.Set("Authorization", "Bearer bearer-value")
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated || bytes.Contains(createResponse.Body.Bytes(), []byte("evidence")) || createResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create response status=%d headers=%v body=%s", createResponse.Code, createResponse.Header(), createResponse.Body)
	}

	completeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth-challenges/"+challengeID.String()+"/complete", bytes.NewBufferString(`{"password":"not-logged","mfa_proof":"834129"}`))
	completeRequest.Header.Set("Authorization", "Bearer bearer-value")
	completeRequest.Header.Set("Content-Type", "application/json")
	completeResponse := httptest.NewRecorder()
	handler.ServeHTTP(completeResponse, completeRequest)
	if completeResponse.Code != http.StatusOK || !bytes.Contains(completeResponse.Body.Bytes(), []byte("returned-exactly-once")) || completeResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("complete response status=%d headers=%v body=%s", completeResponse.Code, completeResponse.Header(), completeResponse.Body)
	}
	if application.completeCommand.Password != "not-logged" || application.completeCommand.MFAProof != "834129" {
		t.Fatalf("complete command = %+v", application.completeCommand)
	}
}

func TestReauthenticationHTTPFailureNeverReflectsSensitiveMaterial(t *testing.T) {
	challengeID := "018f835d-7e4b-7abc-9f42-67a2f5f48e91"
	password, mfaProof := "DoNotReflect-Password", "834129"
	application := &stubReauthenticationApplication{completeError: ErrHighRiskConfirmationRequired}
	router := chi.NewRouter()
	RegisterReauthenticationRoutes(router, application)
	handler := identity.AuthenticationMiddleware(iamStaticVerifier{principal: identity.Principal{Subject: "admin", Kind: identity.PrincipalKindLocal, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "bearer-token-id"}})(router)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth-challenges/"+challengeID+"/complete", bytes.NewBufferString(`{"password":"`+password+`","mfa_proof":"`+mfaProof+`"}`))
	request.Header.Set("Authorization", "Bearer bearer-secret")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	for _, sensitive := range []string{challengeID, password, mfaProof, "bearer-secret", "bearer-token-id"} {
		if bytes.Contains(response.Body.Bytes(), []byte(sensitive)) {
			t.Fatalf("problem response reflected sensitive material %q: %s", sensitive, response.Body)
		}
	}
}

func TestReauthenticationHTTPRejectsOutOfContractLocalFactors(t *testing.T) {
	challengeID := "018f835d-7e4b-7abc-9f42-67a2f5f48e92"
	for name, body := range map[string]string{
		"oversized password": `{"password":"` + strings.Repeat("p", 1025) + `"}`,
		"malformed mfa":      `{"password":"valid","mfa_proof":"12ab56"}`,
	} {
		t.Run(name, func(t *testing.T) {
			application := &stubReauthenticationApplication{}
			router := chi.NewRouter()
			RegisterReauthenticationRoutes(router, application)
			handler := identity.AuthenticationMiddleware(iamStaticVerifier{principal: identity.Principal{Subject: "admin", Kind: identity.PrincipalKindLocal, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "018f835d-7e4b-7abc-9f42-67a2f5f48e93"}})(router)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth-challenges/"+challengeID+"/complete", bytes.NewBufferString(body))
			request.Header.Set("Authorization", "Bearer bearer-value")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || application.completeCommand.Password != "" || application.completeCommand.MFAProof != "" {
				t.Fatalf("status=%d command=%+v body=%s", response.Code, application.completeCommand, response.Body)
			}
		})
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
	roleBindingCommand    CreateRoleBindingCommand
	highRiskProof         HighRiskProof
	highRiskAction        string
	highRiskVersion       int64
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

func (application *stubIAMApplication) CreateRoleBinding(_ context.Context, _ identity.Principal, command CreateRoleBindingCommand, proof HighRiskProof, _ RequestContext) (RoleBinding, error) {
	application.roleBindingCommand, application.highRiskProof, application.highRiskAction, application.highRiskVersion = command, proof, "role_binding.create", command.SubjectVersion
	return RoleBinding{ID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e72"), Version: 1}, nil
}

func (application *stubIAMApplication) DeleteRoleBinding(_ context.Context, _ identity.Principal, _ uuid.UUID, version int64, proof HighRiskProof, _ RequestContext) error {
	application.highRiskProof, application.highRiskAction, application.highRiskVersion = proof, "role_binding.delete", version
	return nil
}

func (application *stubIAMApplication) DisableUser(_ context.Context, _ identity.Principal, _ uuid.UUID, version int64, _ string, proof HighRiskProof, _ RequestContext) error {
	application.highRiskProof, application.highRiskAction, application.highRiskVersion = proof, "user.disable", version
	return nil
}

func (application *stubIAMApplication) EnableUser(_ context.Context, _ identity.Principal, _ uuid.UUID, version int64, _ string, proof HighRiskProof, _ RequestContext) error {
	application.highRiskProof, application.highRiskAction, application.highRiskVersion = proof, "user.enable", version
	return nil
}

func (application *stubIAMApplication) RevokeUserSessions(_ context.Context, _ identity.Principal, _ uuid.UUID, version int64, _ string, proof HighRiskProof, _ RequestContext) error {
	application.highRiskProof, application.highRiskAction, application.highRiskVersion = proof, "user.revoke_sessions", version
	return nil
}

func (application *stubIAMApplication) EnableSSO(_ context.Context, _ identity.Principal, _ uuid.UUID, version int64, proof HighRiskProof, _ RequestContext) error {
	application.highRiskProof, application.highRiskAction, application.highRiskVersion = proof, "sso.enable", version
	return nil
}

func (application *stubIAMApplication) DisableSSO(_ context.Context, _ identity.Principal, _ uuid.UUID, version int64, proof HighRiskProof, _ RequestContext) error {
	application.highRiskProof, application.highRiskAction, application.highRiskVersion = proof, "sso.disable", version
	return nil
}

func (application *stubIAMApplication) CreateIdentitySource(_ context.Context, _ identity.Principal, command CreateIdentitySourceCommand, _ RequestContext) (IdentitySource, error) {
	application.identitySourceCommand = command
	return application.identitySource, nil
}

type stubReauthenticationApplication struct {
	created         ReauthenticationChallengeResult
	completed       ReauthenticationEvidence
	completeCommand CompleteReauthenticationCommand
	completeError   error
}

func (application *stubReauthenticationApplication) CreateChallenge(context.Context, identity.Principal, ReauthenticationOperation, RequestContext) (ReauthenticationChallengeResult, error) {
	return application.created, nil
}

func (application *stubReauthenticationApplication) CompleteChallenge(_ context.Context, _ identity.Principal, _ uuid.UUID, command CompleteReauthenticationCommand, _ RequestContext) (ReauthenticationEvidence, error) {
	application.completeCommand = command
	return application.completed, application.completeError
}

func (application *stubIAMApplication) ListIdentitySources(context.Context, identity.Principal, Page) (IdentitySourcePage, error) {
	return IdentitySourcePage{}, errors.New("unexpected ListIdentitySources call")
}

func (application *stubIAMApplication) PatchIdentitySourceDraft(context.Context, identity.Principal, uuid.UUID, PatchIdentitySourceCommand, RequestContext) (IdentitySource, error) {
	return IdentitySource{}, errors.New("unexpected PatchIdentitySourceDraft call")
}
