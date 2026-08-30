package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/buildinfo"
)

type healthCheckerFunc func(context.Context) error

func (function healthCheckerFunc) Ping(ctx context.Context) error {
	return function(ctx)
}

func TestHandlerPublishesHealthAndVersion(t *testing.T) {
	t.Parallel()

	handler := NewHandler(healthCheckerFunc(func(context.Context) error { return nil }), buildinfo.Info{
		Product: "xminds-release-platform",
		Version: "test-version",
		Commit:  "test-commit",
	})

	for _, testCase := range []struct {
		path       string
		bodyMarker string
	}{
		{path: "/health/live", bodyMarker: `"status":"ok"`},
		{path: "/health/ready", bodyMarker: `"status":"ready"`},
		{path: "/version", bodyMarker: `"version":"test-version"`},
	} {
		testCase := testCase
		t.Run(testCase.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), testCase.bodyMarker) {
				t.Fatalf("body = %s, want marker %s", response.Body.String(), testCase.bodyMarker)
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("security response headers are missing")
			}
		})
	}
}

func TestReadinessUsesSafeProblemDetails(t *testing.T) {
	t.Parallel()

	handler := NewHandler(healthCheckerFunc(func(context.Context) error {
		return errors.New("password=must-not-leak")
	}), buildinfo.Current())
	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatalf("internal error leaked: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"DATABASE_UNAVAILABLE"`) {
		t.Fatalf("problem code missing: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"request_id":`) {
		t.Fatalf("request ID missing: %s", response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
}

func TestManagementHandlerProtectsBusinessRoutesButNotHealth(t *testing.T) {
	t.Parallel()

	principal := identity.Principal{
		Subject:    "alice",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAdmin},
		ProductIDs: []string{"ngep"},
		TokenID:    "token-1",
	}
	verifier := identityVerifierFunc(func(_ context.Context, rawToken string) (identity.Principal, error) {
		if rawToken != "signed-token" {
			return identity.Principal{}, identity.ErrAuthenticationFailed
		}
		return principal, nil
	})
	handler := NewManagementHandler(
		healthCheckerFunc(func(context.Context) error { return nil }),
		buildinfo.Current(),
		identity.AuthenticationMiddleware(verifier),
		func(router chi.Router) {
			router.Get("/api/v1/products", func(writer http.ResponseWriter, request *http.Request) {
				verified, ok := identity.PrincipalFromContext(request.Context())
				if !ok || verified.Subject != "alice" {
					t.Fatalf("PrincipalFromContext() = %#v, %v", verified, ok)
				}
				writer.WriteHeader(http.StatusNoContent)
			})
		},
	)

	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health status = %d, body = %s", healthResponse.Code, healthResponse.Body.String())
	}

	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, httptest.NewRequest(http.MethodGet, "/api/v1/products", nil))
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, body = %s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer signed-token")
	authorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResponse, authorizedRequest)
	if authorizedResponse.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d, body = %s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
}

func TestManagementHandlerFailsClosedWithoutAuthenticationMiddleware(t *testing.T) {
	t.Parallel()

	handler := NewManagementHandler(
		healthCheckerFunc(func(context.Context) error { return nil }),
		buildinfo.Current(),
		nil,
		func(router chi.Router) {
			router.Get("/api/v1/products", func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusNoContent)
			})
		},
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/products", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestManagementHandlerKeepsPublicAuthenticationOutsideProtectedRoutes(t *testing.T) {
	t.Parallel()
	handler := NewManagementHandler(
		healthCheckerFunc(func(context.Context) error { return nil }),
		buildinfo.Current(),
		identity.AuthenticationMiddleware(identityVerifierFunc(func(context.Context, string) (identity.Principal, error) {
			return identity.Principal{}, identity.ErrAuthenticationFailed
		})),
		func(router chi.Router) {
			router.Get("/api/v1/users", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
		},
		func(router chi.Router) {
			router.Post("/api/v1/auth/local/login", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
		},
	)
	publicResponse := httptest.NewRecorder()
	handler.ServeHTTP(publicResponse, httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/login", nil))
	if publicResponse.Code != http.StatusNoContent || publicResponse.Header().Get("X-Request-ID") == "" {
		t.Fatalf("public auth response = %d, request ID = %q", publicResponse.Code, publicResponse.Header().Get("X-Request-ID"))
	}
	protectedResponse := httptest.NewRecorder()
	handler.ServeHTTP(protectedResponse, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	if protectedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("protected IAM status = %d", protectedResponse.Code)
	}
}

type identityVerifierFunc func(context.Context, string) (identity.Principal, error)

func (function identityVerifierFunc) Verify(ctx context.Context, token string) (identity.Principal, error) {
	return function(ctx, token)
}
