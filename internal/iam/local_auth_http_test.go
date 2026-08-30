package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/httpserver"
	"xminds-release-platform/internal/platform/httpx"
)

func TestPublicLocalAuthenticationHTTPContractReturnsOnlyOpaqueSession(t *testing.T) {
	t.Parallel()
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	handler := localAuthManagementHandler(harness.service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/login", bytes.NewBufferString(`{"username":"release.operator","password":"Current-Strong-Password!"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["token_type"] != "Bearer" || !strings.HasPrefix(payload["access_token"].(string), "xms_") || payload["expires_at"] == nil || payload["subject"] == nil {
		t.Fatalf("login payload = %#v", payload)
	}
	for _, forbidden := range []string{"password", "activation_digest", "mfa_secret", "token_digest"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("login response exposed %q: %s", forbidden, response.Body)
		}
	}
}

func TestPublicLoginStateHTTPContractExposesOnlySafeMode(t *testing.T) {
	t.Parallel()
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	handler := localAuthManagementHandler(harness.service)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-state", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	if strings.TrimSpace(response.Body.String()) != `{"mode":"local"}` {
		t.Fatalf("login state exposed an unstable or sensitive contract: %s", response.Body)
	}
}

func TestPublicActivationHTTPContractConsumesTokenAndReturnsNoRecoveryCodesWithoutMFA(t *testing.T) {
	t.Parallel()
	harness := newLocalAuthHarness(t, UserKindLocal, false)
	handler := localAuthManagementHandler(harness.service)
	body := `{"activation_token":"` + harness.activationToken + `","new_password":"A-Strong-Local-Password!"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/activate", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"recovery_codes":[]}` || response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
}

func TestPublicActivationHTTPRejectsClientAuthoredMFASecretReferenceBeforeApplication(t *testing.T) {
	t.Parallel()
	application := &countingLocalAuthApplication{}
	handler := localAuthManagementHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/activate", bytes.NewBufferString(`{
        "activation_token":"never-log-this-token",
        "new_password":"A-Strong-Local-Password!",
        "mfa_secret_reference":"secret://iam/client-authored",
        "mfa_proof":"123456"
    }`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || application.activationCalls != 0 {
		t.Fatalf("response=%d calls=%d body=%s", response.Code, application.activationCalls, response.Body)
	}
	if strings.Contains(response.Body.String(), "never-log-this-token") || strings.Contains(response.Body.String(), "client-authored") {
		t.Fatalf("sensitive activation input leaked: %s", response.Body)
	}
}

func TestPublicActivationMFAEnrollmentHTTPReturnsOneTimeSecretNoStore(t *testing.T) {
	t.Parallel()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	application := &mfaActivationHTTPApplication{result: MFAEnrollmentStart{
		ID: id, Secret: testMFASeed(), OTPAuthURI: "otpauth://totp/Xminds%20Release%20Platform:operator?secret=" + testMFASeed(),
		ExpiresAt: time.Date(2026, 8, 21, 18, 10, 0, 0, time.UTC),
	}}
	handler := mfaActivationEnrollmentHTTPHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/mfa-enrollments", bytes.NewBufferString(`{"activation_token":"one-time-activation-token-with-entropy"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" || application.calls != 1 {
		t.Fatalf("response=%d headers=%v calls=%d body=%s", response.Code, response.Header(), application.calls, response.Body)
	}
	if !strings.Contains(response.Body.String(), `"secret":"`+testMFASeed()+`"`) || !strings.Contains(response.Body.String(), `"otpauth_uri":"otpauth://`) || strings.Contains(response.Body.String(), "one-time-activation-token-with-entropy") {
		t.Fatalf("enrollment response=%s", response.Body)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/mfa-enrollments", bytes.NewBufferString(`{"activation_token":"one-time-activation-token-with-entropy","secret":"client-seed"}`))
	invalid.Header.Set("Content-Type", "application/json")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest || application.calls != 1 || strings.Contains(invalidResponse.Body.String(), "client-seed") {
		t.Fatalf("invalid response=%d calls=%d body=%s", invalidResponse.Code, application.calls, invalidResponse.Body)
	}
}

func TestPublicAuthenticationHTTPUsesUniformProblemAndStableRateLimitCode(t *testing.T) {
	t.Parallel()
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	handler := localAuthManagementHandler(harness.service)
	post := func(username string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/login", bytes.NewBufferString(`{"username":"`+username+`","password":"Wrong-Password-Value!"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	wrong := post("release.operator")
	unknown := post("unknown.operator")
	for name, response := range map[string]*httptest.ResponseRecorder{"wrong": wrong, "unknown": unknown} {
		if response.Code != http.StatusUnauthorized || response.Header().Get("Content-Type") != httpx.ProblemMediaType || !strings.Contains(response.Body.String(), `"code":"AUTHENTICATION_FAILED"`) {
			t.Fatalf("%s response = %d %s", name, response.Code, response.Body)
		}
		if strings.Contains(response.Body.String(), "operator") {
			t.Fatalf("%s response enumerates account: %s", name, response.Body)
		}
	}
	for attempt := 3; attempt <= 17; attempt++ {
		response := post("release.operator")
		if attempt == 17 && (response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), `"code":"AUTHENTICATION_RATE_LIMITED"`)) {
			t.Fatalf("rate limit response = %d %s", response.Code, response.Body)
		}
	}
}

func localAuthManagementHandler(application LocalAuthApplication) http.Handler {
	return httpserver.NewManagementHandler(
		nil,
		buildinfo.Current(),
		identity.AuthenticationMiddleware(localAuthHTTPVerifier{}),
		nil,
		func(router chi.Router) { RegisterPublicAuthRoutes(router, application) },
	)
}

type localAuthHTTPVerifier struct{}

func (localAuthHTTPVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return identity.Principal{}, identity.ErrAuthenticationFailed
}

type countingLocalAuthApplication struct {
	activationCalls int
}

type mfaActivationHTTPApplication struct {
	result MFAEnrollmentStart
	calls  int
}

func (application *mfaActivationHTTPApplication) BeginActivationEnrollment(context.Context, string, RequestContext) (MFAEnrollmentStart, error) {
	application.calls++
	return application.result, nil
}

func mfaActivationEnrollmentHTTPHandler(application MFAActivationEnrollmentApplication) http.Handler {
	return httpserver.NewManagementHandler(
		nil,
		buildinfo.Current(),
		identity.AuthenticationMiddleware(localAuthHTTPVerifier{}),
		nil,
		func(router chi.Router) { RegisterPublicMFAEnrollmentRoutes(router, application) },
	)
}

func (application *countingLocalAuthApplication) ActivateWithResult(context.Context, ActivateLocalAccountCommand, RequestContext) (LocalActivationResult, error) {
	application.activationCalls++
	return LocalActivationResult{}, nil
}

func (*countingLocalAuthApplication) LoginLocal(context.Context, LocalLoginCommand, RequestContext) (LoginResult, error) {
	return LoginResult{}, nil
}

func (*countingLocalAuthApplication) LoginEmergency(context.Context, LocalLoginCommand, RequestContext) (LoginResult, error) {
	return LoginResult{}, nil
}
