package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestIAMHTTPJSONRejectsBodyWhoseActualBytesExceedLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/local-users", bytes.NewBufferString(`{"username":"alice","display_name":"Alice"}`+strings.Repeat(" ", maximumIAMRequestBytes)))
	request.Header.Set("Content-Type", "application/json")
	var target struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := decodeIAMJSON(request, &target); err == nil {
		t.Fatal("decodeIAMJSON() error=nil, want actual byte limit rejection")
	}
}

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
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode creation response: %v", err)
	}
	var activationToken string
	if err := json.Unmarshal(body["activation_token"], &activationToken); err != nil || activationToken != "returned-once" {
		t.Fatalf("activation_token = %q, %v", activationToken, err)
	}
	if application.createCommand.Username != "release.operator" || application.createRequest.RequestID == "" {
		t.Fatalf("create call = %+v, %+v", application.createCommand, application.createRequest)
	}
}

func TestHTTPHandlerAndServiceShareStrictLocalUserInputContract(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name    string
		command CreateLocalUserCommand
	}{
		{name: "username leading whitespace", command: CreateLocalUserCommand{Username: " release.operator", DisplayName: "Release Operator", Email: "operator@example.com"}},
		{name: "username uppercase", command: CreateLocalUserCommand{Username: "Release.Operator", DisplayName: "Release Operator", Email: "operator@example.com"}},
		{name: "display whitespace only", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: "  ", Email: "operator@example.com"}},
		{name: "display leading whitespace", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: " Release Operator", Email: "operator@example.com"}},
		{name: "display trailing whitespace", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: "Release Operator ", Email: "operator@example.com"}},
		{name: "email leading whitespace", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: "Release Operator", Email: " operator@example.com"}},
		{name: "email trailing whitespace", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: "Release Operator", Email: "operator@example.com "}},
		{name: "email uppercase", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: "Release Operator", Email: "OPERATOR@example.com"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			serviceHarness := newIAMHarness(t)
			if _, err := serviceHarness.service.CreateLocalUser(context.Background(), serviceHarness.admin, testCase.command, serviceHarness.request); !errors.Is(err, ErrUserInputInvalid) {
				t.Fatalf("service CreateLocalUser() error = %v, want ErrUserInputInvalid", err)
			}
			if serviceHarness.repository.withinTransactionCalls != 0 {
				t.Fatalf("invalid service input reached repository transaction %d times", serviceHarness.repository.withinTransactionCalls)
			}

			application := &stubIAMApplication{}
			body, err := json.Marshal(map[string]string{
				"username":     testCase.command.Username,
				"display_name": testCase.command.DisplayName,
				"email":        testCase.command.Email,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/local-users", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			authenticatedIAMHandler(application).ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("HTTP status = %d, body = %s", response.Code, response.Body)
			}
			if application.createCalls != 0 {
				t.Fatalf("invalid HTTP input invoked application %d times", application.createCalls)
			}
		})
	}
}

func TestHTTPHandlerAcceptsCanonicalUsernamesThrough128Characters(t *testing.T) {
	t.Parallel()

	for _, username := range []string{strings.Repeat("a", 65), strings.Repeat("a", 128)} {
		t.Run(strconv.Itoa(len(username)), func(t *testing.T) {
			application := &stubIAMApplication{provisioning: LocalUserProvisioning{User: UserPrincipal{ID: uuid.New()}}}
			body, err := json.Marshal(map[string]string{"username": username, "display_name": "Release Operator", "email": "operator@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/local-users", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			authenticatedIAMHandler(application).ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				t.Fatalf("HTTP status = %d, body = %s", response.Code, response.Body)
			}
			if application.createCalls != 1 || application.createCommand.Username != username {
				t.Fatalf("application calls = %d, command = %+v", application.createCalls, application.createCommand)
			}
		})
	}
}

func TestHTTPHandlerNeverReturnsProvisioningSecretFromUserReads(t *testing.T) {
	t.Parallel()

	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e54")
	secret := "activation-token-that-is-returned-once-and-never-through-user-read-routes"
	user := UserPrincipal{ID: userID, Username: "release.reader", DisplayName: "Release Reader", Kind: UserKindLocal, Status: UserStatusPending, Version: 1, CreatedAt: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)}
	application := &stubIAMApplication{
		provisioning: LocalUserProvisioning{User: user, ActivationToken: secret, ActivationExpires: time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)},
		page:         UserPage{Items: []UserPrincipal{user}},
		user:         user,
	}
	handler := authenticatedIAMHandler(application)

	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/local-users", bytes.NewBufferString(`{"username":"release.reader","display_name":"Release Reader"}`))
	createRequest.Header.Set("Authorization", "Bearer token")
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated || !bytes.Contains(createResponse.Body.Bytes(), []byte(secret)) {
		t.Fatalf("creation response must be the sole secret delivery: status=%d body=%s", createResponse.Code, createResponse.Body)
	}

	for _, testCase := range []struct {
		name string
		path string
	}{
		{name: "list", path: "/api/v1/users"},
		{name: "detail", path: "/api/v1/users/" + userID.String()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body)
			}
			if bytes.Contains(response.Body.Bytes(), []byte(secret)) || bytes.Contains(response.Body.Bytes(), []byte(`"activation_token"`)) {
				t.Fatalf("user read leaked activation secret: %s", response.Body)
			}
		})
	}
}

// Mutation caught: omitting any organization governance route leaves the
// backend contract incomplete even if list/create still work.
func TestHTTPHandlerExposesOrganizationDetailChildrenAndMembershipLifecycle(t *testing.T) {
	t.Parallel()
	organizationID, userID := uuid.New(), uuid.New()
	now := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)
	application := &stubIAMApplication{
		organization:               OrganizationUnit{ID: organizationID, Name: "Engineering", Status: OrganizationStatusActive, Version: 4, CreatedAt: now, UpdatedAt: now},
		organizationPage:           OrganizationPage{Items: []OrganizationUnit{{ID: uuid.New(), ParentID: organizationID, Name: "Release", Status: OrganizationStatusActive, Version: 1, CreatedAt: now, UpdatedAt: now}}},
		organizationMembershipPage: OrganizationMembershipPage{Items: []OrganizationMembership{{OrganizationID: organizationID, UserID: userID, SourceOwned: true, Status: OrganizationMembershipStatusActive, Version: 2, CreatedAt: now, UpdatedAt: now}}},
		organizationMembership:     OrganizationMembership{OrganizationID: organizationID, UserID: userID, Status: OrganizationMembershipStatusActive, Version: 1, CreatedAt: now, UpdatedAt: now},
	}
	handler := authenticatedIAMHandler(application)
	for _, path := range []string{
		"/api/v1/organizations/" + organizationID.String(),
		"/api/v1/organizations/" + organizationID.String() + "/children?limit=10",
		"/api/v1/organizations/" + organizationID.String() + "/memberships?limit=10",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET %s status=%d headers=%v body=%s", path, response.Code, response.Header(), response.Body)
		}
	}

	postBody := `{"organization_version":4,"user_id":"` + userID.String() + `","user_version":3,"reason":"approved supplemental access","reauthentication":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`
	postRequest := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+organizationID.String()+"/memberships", strings.NewReader(postBody))
	postRequest.Header.Set("Authorization", "Bearer token")
	postRequest.Header.Set("Content-Type", "application/json")
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, postRequest)
	if postResponse.Code != http.StatusCreated || postResponse.Header().Get("Location") != "/api/v1/organizations/"+organizationID.String()+"/memberships/"+userID.String() || application.membershipCreateCommand.Reason != "approved supplemental access" {
		t.Fatalf("POST membership status=%d location=%q command=%+v body=%s", postResponse.Code, postResponse.Header().Get("Location"), application.membershipCreateCommand, postResponse.Body)
	}

	deleteBody := `{"organization_version":5,"user_version":3,"membership_version":1,"reason":"remove obsolete supplemental access","reauthentication":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/organizations/"+organizationID.String()+"/memberships/"+userID.String(), strings.NewReader(deleteBody))
	deleteRequest.Header.Set("Authorization", "Bearer token")
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent || deleteResponse.Header().Get("Cache-Control") != "no-store" || application.membershipDeleteCommand.MembershipVersion != 1 {
		t.Fatalf("DELETE membership status=%d command=%+v body=%s", deleteResponse.Code, application.membershipDeleteCommand, deleteResponse.Body)
	}
}

func TestOrganizationMembershipHTTPRejectsUnknownFieldsAndTemplatesProblemInstance(t *testing.T) {
	t.Parallel()
	organizationID, userID := uuid.New(), uuid.New()
	application := &stubIAMApplication{membershipError: ErrOrganizationMembershipNotFound}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+organizationID.String()+"/memberships", strings.NewReader(`{"organization_version":1,"user_id":"`+userID.String()+`","user_version":1,"reason":"approved supplemental access","reauthentication":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true},"unexpected":true}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || application.membershipCreateCalls != 0 {
		t.Fatalf("unknown field status=%d calls=%d body=%s", response.Code, application.membershipCreateCalls, response.Body)
	}
	whitespaceRequest := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+organizationID.String()+"/memberships", strings.NewReader(`{"organization_version":1,"user_id":"`+userID.String()+`","user_version":1,"reason":" approved supplemental access ","reauthentication":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`))
	whitespaceRequest.Header.Set("Authorization", "Bearer token")
	whitespaceRequest.Header.Set("Content-Type", "application/json")
	whitespaceResponse := httptest.NewRecorder()
	handler.ServeHTTP(whitespaceResponse, whitespaceRequest)
	if whitespaceResponse.Code != http.StatusBadRequest || application.membershipCreateCalls != 0 {
		t.Fatalf("non-canonical reason status=%d calls=%d body=%s", whitespaceResponse.Code, application.membershipCreateCalls, whitespaceResponse.Body)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/organizations/"+organizationID.String()+"/memberships/"+userID.String(), strings.NewReader(`{"organization_version":1,"user_version":1,"membership_version":1,"reason":"remove obsolete supplemental access","reauthentication":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`))
	deleteRequest.Header.Set("Authorization", "Bearer token")
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNotFound || !strings.Contains(deleteResponse.Body.String(), `"instance":"/api/v1/organizations/{organization_id}/memberships/{user_id}"`) || strings.Contains(deleteResponse.Body.String(), organizationID.String()) || strings.Contains(deleteResponse.Body.String(), userID.String()) {
		t.Fatalf("templated problem status=%d body=%s", deleteResponse.Code, deleteResponse.Body)
	}
}

func TestOrganizationMembershipHTTPParsesOwnershipAwareCursor(t *testing.T) {
	t.Parallel()
	organizationID, userID := uuid.New(), uuid.New()
	createdAt := time.Date(2026, 8, 21, 17, 30, 0, 0, time.UTC)
	application := &stubIAMApplication{}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+organizationID.String()+"/memberships?limit=1&cursor="+encodeOrganizationMembershipCursor(createdAt, userID, true), nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || application.membershipPageRequest.BeforeSourceOwned == nil || !*application.membershipPageRequest.BeforeSourceOwned || application.membershipPageRequest.BeforeID != userID || !application.membershipPageRequest.BeforeTime.Equal(createdAt) {
		t.Fatalf("ownership cursor status=%d page=%+v body=%s", response.Code, application.membershipPageRequest, response.Body)
	}
}

// Mutation caught: trimming or decoding before validating the public cursor
// envelope lets oversized/non-canonical values reach the application.
func TestOrganizationMembershipHTTPRejectsOversizedAndNonCanonicalCursorBeforeApplication(t *testing.T) {
	organizationID := uuid.New()
	for _, cursor := range []string{
		canonicalOrganizationMembershipCursor + strings.Repeat(" ", 513-len(canonicalOrganizationMembershipCursor)),
		canonicalOrganizationMembershipCursor + strings.Repeat(" ", 4096-len(canonicalOrganizationMembershipCursor)),
		canonicalOrganizationMembershipCursor[:len(canonicalOrganizationMembershipCursor)-1] + "R",
	} {
		application := &stubIAMApplication{}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+organizationID.String()+"/memberships?cursor="+url.QueryEscape(cursor), nil)
		request.Header.Set("Authorization", "Bearer token")
		response := httptest.NewRecorder()

		authenticatedIAMHandler(application).ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest || application.membershipListCalls != 0 {
			t.Fatalf("cursor_length=%d status=%d application_calls=%d body=%s", len(cursor), response.Code, application.membershipListCalls, response.Body)
		}
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
        "reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}
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
		{name: "delete binding", method: http.MethodDelete, path: "/api/v1/role-bindings/018f835d-7e4b-7abc-9f42-67a2f5f48e75", body: `{"version":7,"reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`, action: "role_binding.delete", status: http.StatusNoContent},
		{name: "disable user", method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e76/disable", body: `{"version":8,"reason":"incident","reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`, action: "user.disable", status: http.StatusNoContent},
		{name: "enable user", method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e76/enable", body: `{"version":9,"reason":"incident closed","reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`, action: "user.enable", status: http.StatusNoContent},
		{name: "revoke sessions", method: http.MethodPost, path: "/api/v1/users/018f835d-7e4b-7abc-9f42-67a2f5f48e76/revoke-sessions", body: `{"version":10,"reason":"rotation","reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`, action: "user.revoke_sessions", status: http.StatusNoContent},
		{name: "enable sso", method: http.MethodPost, path: "/api/v1/identity-sources/018f835d-7e4b-7abc-9f42-67a2f5f48e77/enable", body: `{"version":11,"reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`, action: "sso.enable", status: http.StatusNoContent},
		{name: "disable sso", method: http.MethodPost, path: "/api/v1/identity-sources/018f835d-7e4b-7abc-9f42-67a2f5f48e77/disable", body: `{"version":12,"reauth":{"challenge_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e74","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`, action: "sso.disable", status: http.StatusNoContent},
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

// Mutation caught: forwarding a malformed proof to any high-risk IAM
// application method would let transport-invalid input reach resource and
// version lookups before returning a stable 400 response.
func TestIAMHighRiskHTTPRejectsMalformedProofBeforeApplication(t *testing.T) {
	organizationID, userID := uuid.New(), uuid.New()
	validEvidence := "xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	for _, endpoint := range []struct {
		name, method, path, body string
		calls                    func(*stubIAMApplication) int
	}{
		{name: "create membership", method: http.MethodPost, path: "/api/v1/organizations/" + organizationID.String() + "/memberships", body: `{"organization_version":1,"user_id":"` + userID.String() + `","user_version":1,"reason":"approved supplemental access","reauthentication":PROOF}`, calls: func(application *stubIAMApplication) int { return application.membershipCreateCalls }},
		{name: "delete membership", method: http.MethodDelete, path: "/api/v1/organizations/" + organizationID.String() + "/memberships/" + userID.String(), body: `{"organization_version":1,"user_version":1,"membership_version":1,"reason":"remove obsolete supplemental access","reauthentication":PROOF}`, calls: func(application *stubIAMApplication) int { return application.membershipDeleteCalls }},
		{name: "create role binding", method: http.MethodPost, path: "/api/v1/role-bindings", body: `{"subject_type":"user","subject_id":"` + userID.String() + `","subject_version":1,"role":"viewer","scope_type":"platform","effect":"allow","reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
		{name: "delete role binding", method: http.MethodDelete, path: "/api/v1/role-bindings/" + uuid.NewString(), body: `{"version":1,"reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
		{name: "disable user", method: http.MethodPost, path: "/api/v1/users/" + userID.String() + "/disable", body: `{"version":1,"reason":"incident response","reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
		{name: "enable user", method: http.MethodPost, path: "/api/v1/users/" + userID.String() + "/enable", body: `{"version":1,"reason":"incident resolved","reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
		{name: "revoke sessions", method: http.MethodPost, path: "/api/v1/users/" + userID.String() + "/revoke-sessions", body: `{"version":1,"reason":"credential rotation","reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
		{name: "enable sso", method: http.MethodPost, path: "/api/v1/identity-sources/" + uuid.NewString() + "/enable", body: `{"version":1,"reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
		{name: "disable sso", method: http.MethodPost, path: "/api/v1/identity-sources/" + uuid.NewString() + "/disable", body: `{"version":1,"reauth":PROOF}`, calls: func(application *stubIAMApplication) int { return boolCount(application.highRiskAction != "") }},
	} {
		for _, proof := range []struct {
			name, json string
		}{
			{name: "missing", json: `{}`},
			{name: "invalid challenge", json: `{"challenge_id":"not-a-uuid","evidence":"` + validEvidence + `","confirmed":true}`},
			{name: "invalid evidence", json: `{"challenge_id":"` + uuid.NewString() + `","evidence":"xmr_too-short","confirmed":true}`},
			{name: "unconfirmed", json: `{"challenge_id":"` + uuid.NewString() + `","evidence":"` + validEvidence + `","confirmed":false}`},
		} {
			t.Run(endpoint.name+"/"+proof.name, func(t *testing.T) {
				application := &stubIAMApplication{}
				request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(strings.Replace(endpoint.body, "PROOF", proof.json, 1)))
				request.Header.Set("Authorization", "Bearer token")
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()

				authenticatedIAMHandler(application).ServeHTTP(response, request)

				if response.Code != http.StatusBadRequest || endpoint.calls(application) != 0 {
					t.Fatalf("status=%d application_calls=%d body=%s", response.Code, endpoint.calls(application), response.Body)
				}
			})
		}
	}
}

// Mutation caught: treating OpenAPI format:uuid as lowercase-only rejects a
// standards-compliant uppercase UUID before the application can consume it.
func TestIAMHighRiskHTTPAcceptsUppercaseUUIDAndCanonicalizesProof(t *testing.T) {
	organizationID, userID := uuid.New(), uuid.New()
	challengeID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e74")
	body := `{"organization_version":1,"user_id":"` + userID.String() + `","user_version":1,"reason":"approved supplemental access","reauthentication":{"challenge_id":"` + strings.ToUpper(challengeID.String()) + `","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`
	application := &stubIAMApplication{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+organizationID.String()+"/memberships", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	authenticatedIAMHandler(application).ServeHTTP(response, request)

	if response.Code != http.StatusCreated || application.membershipCreateCalls != 1 || application.highRiskProof.ChallengeID != challengeID.String() {
		t.Fatalf("status=%d calls=%d proof=%+v body=%s", response.Code, application.membershipCreateCalls, application.highRiskProof, response.Body)
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
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
	provisioning               LocalUserProvisioning
	createError                error
	createCalls                int
	createCommand              CreateLocalUserCommand
	createRequest              RequestContext
	page                       UserPage
	user                       UserPrincipal
	listPage                   Page
	organization               OrganizationUnit
	organizationPage           OrganizationPage
	organizationMembershipPage OrganizationMembershipPage
	organizationMembership     OrganizationMembership
	membershipCreateCommand    CreateOrganizationMembershipCommand
	membershipDeleteCommand    DeleteOrganizationMembershipCommand
	membershipPageRequest      Page
	membershipListCalls        int
	membershipCreateCalls      int
	membershipDeleteCalls      int
	membershipError            error
	organizationCommand        CreateOrganizationCommand
	identitySource             IdentitySource
	identitySourceCommand      CreateIdentitySourceCommand
	roleBindingCommand         CreateRoleBindingCommand
	highRiskProof              HighRiskProof
	highRiskAction             string
	highRiskVersion            int64
}

func (application *stubIAMApplication) GetOrganization(context.Context, identity.Principal, uuid.UUID) (OrganizationUnit, error) {
	return application.organization, application.membershipError
}

func (application *stubIAMApplication) ListOrganizationChildren(context.Context, identity.Principal, uuid.UUID, Page) (OrganizationPage, error) {
	return application.organizationPage, application.membershipError
}

func (application *stubIAMApplication) ListOrganizationMemberships(_ context.Context, _ identity.Principal, _ uuid.UUID, page Page) (OrganizationMembershipPage, error) {
	application.membershipListCalls++
	application.membershipPageRequest = page
	return application.organizationMembershipPage, application.membershipError
}

func (application *stubIAMApplication) CreateOrganizationMembership(_ context.Context, _ identity.Principal, _ uuid.UUID, command CreateOrganizationMembershipCommand, proof HighRiskProof, _ RequestContext) (OrganizationMembership, error) {
	application.membershipCreateCalls++
	application.membershipCreateCommand = command
	application.highRiskProof = proof
	return application.organizationMembership, application.membershipError
}

func (application *stubIAMApplication) DeleteOrganizationMembership(_ context.Context, _ identity.Principal, _, _ uuid.UUID, command DeleteOrganizationMembershipCommand, proof HighRiskProof, _ RequestContext) error {
	application.membershipDeleteCalls++
	application.membershipDeleteCommand = command
	application.highRiskProof = proof
	return application.membershipError
}

func (application *stubIAMApplication) CreateLocalUser(_ context.Context, _ identity.Principal, command CreateLocalUserCommand, request RequestContext) (LocalUserProvisioning, error) {
	application.createCalls++
	application.createCommand = command
	application.createRequest = request
	return application.provisioning, application.createError
}

func (application *stubIAMApplication) GetUser(context.Context, identity.Principal, uuid.UUID) (UserPrincipal, error) {
	if application.user.ID != uuid.Nil {
		return application.user, nil
	}
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
