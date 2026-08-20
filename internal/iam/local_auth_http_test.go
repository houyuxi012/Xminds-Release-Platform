package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

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

func TestPublicActivationHTTPContractConsumesTokenAndReturnsNoContent(t *testing.T) {
	t.Parallel()
	harness := newLocalAuthHarness(t, UserKindLocal, false)
	handler := localAuthManagementHandler(harness.service)
	body := `{"activation_token":"` + harness.activationToken + `","new_password":"A-Strong-Local-Password!"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/activate", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
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
