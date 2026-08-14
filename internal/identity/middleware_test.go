package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xminds-release-platform/internal/platform/httpx"
)

type verifierFunc func(context.Context, string) (Principal, error)

func (function verifierFunc) Verify(ctx context.Context, rawToken string) (Principal, error) {
	return function(ctx, rawToken)
}

func TestAuthenticationMiddlewareInjectsVerifiedPrincipal(t *testing.T) {
	t.Parallel()

	wanted := Principal{
		Subject:    "alice",
		Kind:       PrincipalKindHuman,
		Roles:      []Role{RoleApprover},
		ProductIDs: []string{"product-a"},
		TokenID:    "token-1",
	}
	verifier := verifierFunc(func(_ context.Context, rawToken string) (Principal, error) {
		if rawToken != "signed-token" {
			return Principal{}, errors.New("unexpected token")
		}
		return wanted, nil
	})
	handler := AuthenticationMiddleware(verifier)(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := PrincipalFromContext(request.Context())
		if !ok || principal.Subject != wanted.Subject || principal.TokenID != wanted.TokenID {
			t.Fatalf("PrincipalFromContext() = %#v, %v", principal, ok)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/products/product-a", nil)
	request.Header.Set("Authorization", "Bearer signed-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestAuthenticationMiddlewareRejectsQueryToken(t *testing.T) {
	t.Parallel()

	handler := AuthenticationMiddleware(verifierFunc(func(context.Context, string) (Principal, error) {
		return Principal{Subject: "unexpected", Kind: PrincipalKindHuman}, nil
	}))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was invoked")
	}))
	request := httptest.NewRequest(http.MethodGet, "/products?access_token=signed-token", nil)
	request = request.WithContext(httpx.WithRequestID(request.Context(), "018f835d-7e4b-7abc-9f42-67a2f5f48e01"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"AUTHENTICATION_REQUIRED"`) {
		t.Fatalf("problem code missing: %s", response.Body.String())
	}
}

func TestAuthenticationMiddlewareDoesNotLeakVerifierError(t *testing.T) {
	t.Parallel()

	handler := AuthenticationMiddleware(verifierFunc(func(context.Context, string) (Principal, error) {
		return Principal{}, errors.New("client_secret=must-not-leak")
	}))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was invoked")
	}))
	request := httptest.NewRequest(http.MethodGet, "/products", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")
	request = request.WithContext(httpx.WithRequestID(request.Context(), "018f835d-7e4b-7abc-9f42-67a2f5f48e01"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatalf("verifier error leaked: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"request_id":"018f835d-7e4b-7abc-9f42-67a2f5f48e01"`) {
		t.Fatalf("request ID missing: %s", response.Body.String())
	}
}
