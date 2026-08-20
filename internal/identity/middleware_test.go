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

func TestManagementVerifierRoutesAPITokensWithoutOIDCFallback(t *testing.T) {
	t.Parallel()

	humanCalls := 0
	workloadCalls := 0
	verifier, err := NewManagementVerifier(
		verifierFunc(func(context.Context, string) (Principal, error) {
			humanCalls++
			return Principal{}, errors.New("human verifier must not receive API tokens")
		}),
		verifierFunc(func(context.Context, string) (Principal, error) {
			workloadCalls++
			return Principal{}, errors.New("workload verifier must not receive API tokens")
		}),
		verifierFunc(func(_ context.Context, rawToken string) (Principal, error) {
			if rawToken != "xrp.018f835d-7e4b-7abc-9f42-67a2f5f48e01.c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA" {
				return Principal{}, ErrAPITokenInvalid
			}
			return Principal{Subject: "automation", Kind: PrincipalKindWorkload}, nil
		}),
		verifierFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrAuthenticationFailed }),
	)
	if err != nil {
		t.Fatalf("NewManagementVerifier() error = %v", err)
	}

	principal, err := verifier.Verify(context.Background(), "xrp.018f835d-7e4b-7abc-9f42-67a2f5f48e01.c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Subject != "automation" || humanCalls != 0 || workloadCalls != 0 {
		t.Fatalf("principal = %#v, human calls = %d, workload calls = %d", principal, humanCalls, workloadCalls)
	}
}

func TestManagementVerifierRoutesLocalSessionsWithoutAnyFallback(t *testing.T) {
	t.Parallel()
	fallbackCalls := 0
	fallback := verifierFunc(func(context.Context, string) (Principal, error) {
		fallbackCalls++
		return Principal{}, errors.New("fallback must not receive local session tokens")
	})
	localFailure := errors.New("local session revoked")
	verifier, err := NewManagementVerifier(fallback, fallback, fallback, verifierFunc(func(_ context.Context, rawToken string) (Principal, error) {
		if !strings.HasPrefix(rawToken, "xms_") {
			return Principal{}, ErrTokenUseInvalid
		}
		return Principal{}, localFailure
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), "xms_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, localFailure) {
		t.Fatalf("Verify(local) error = %v", err)
	}
	if fallbackCalls != 0 {
		t.Fatalf("local failure used %d fallback verifiers", fallbackCalls)
	}
}

func TestManagementVerifierFallsBackOnlyForWorkloadTokenUse(t *testing.T) {
	t.Parallel()

	workload := Principal{Subject: "github-runner", Kind: PrincipalKindWorkload}
	verifier, err := NewManagementVerifier(
		verifierFunc(func(context.Context, string) (Principal, error) {
			return Principal{}, ErrTokenUseInvalid
		}),
		verifierFunc(func(context.Context, string) (Principal, error) {
			return workload, nil
		}),
		verifierFunc(func(context.Context, string) (Principal, error) {
			return Principal{}, ErrAPITokenInvalid
		}),
		verifierFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrAuthenticationFailed }),
	)
	if err != nil {
		t.Fatalf("NewManagementVerifier() error = %v", err)
	}

	principal, err := verifier.Verify(context.Background(), "signed-workload-token")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Subject != workload.Subject || principal.Kind != PrincipalKindWorkload {
		t.Fatalf("principal = %#v", principal)
	}

	verificationFailure := errors.New("signature verification failed")
	workloadCalled := false
	strictVerifier, err := NewManagementVerifier(
		verifierFunc(func(context.Context, string) (Principal, error) {
			return Principal{}, verificationFailure
		}),
		verifierFunc(func(context.Context, string) (Principal, error) {
			workloadCalled = true
			return workload, nil
		}),
		verifierFunc(func(context.Context, string) (Principal, error) {
			return Principal{}, ErrAPITokenInvalid
		}),
		verifierFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrAuthenticationFailed }),
	)
	if err != nil {
		t.Fatalf("NewManagementVerifier() error = %v", err)
	}
	if _, err := strictVerifier.Verify(context.Background(), "invalid-token"); !errors.Is(err, verificationFailure) {
		t.Fatalf("Verify() error = %v, want %v", err, verificationFailure)
	}
	if workloadCalled {
		t.Fatal("workload verifier accepted fallback after a signature failure")
	}
}

func TestManagementVerifierRejectsIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	valid := verifierFunc(func(context.Context, string) (Principal, error) {
		return Principal{}, ErrAuthenticationFailed
	})
	for name, verifiers := range map[string][]Verifier{
		"human":         {nil, valid, valid, valid},
		"workload":      {valid, nil, valid, valid},
		"api token":     {valid, valid, nil, valid},
		"local session": {valid, valid, valid, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewManagementVerifier(verifiers[0], verifiers[1], verifiers[2], verifiers[3]); !errors.Is(err, ErrManagementVerifierConfiguration) {
				t.Fatalf("NewManagementVerifier() error = %v", err)
			}
		})
	}
}
