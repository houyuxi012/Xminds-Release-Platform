package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCVerifierValidatesAndMapsHumanPrincipal(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	token := issuer.sign(t, map[string]any{
		"sub":         "alice",
		"aud":         "xminds-console",
		"jti":         "token-human-1",
		"token_use":   "human",
		"roles":       []string{"approver", "auditor"},
		"product_ids": []string{"product-a", "product-b"},
	})

	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Subject != "alice" || principal.Kind != PrincipalKindHuman || principal.TokenID != "token-human-1" {
		t.Fatalf("principal identity = %#v", principal)
	}
	if len(principal.Roles) != 2 || principal.Roles[0] != RoleApprover || principal.Roles[1] != RoleAuditor {
		t.Fatalf("principal roles = %#v", principal.Roles)
	}
	if len(principal.ProductIDs) != 2 || principal.ProductIDs[1] != "product-b" {
		t.Fatalf("principal product IDs = %#v", principal.ProductIDs)
	}
}

func TestOIDCVerifierMapsFreshAuthenticationTimeAndIndependentMFAFactors(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	authenticatedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	for _, testCase := range []struct {
		name string
		amr  []string
	}{
		{name: "explicit mfa", amr: []string{"mfa"}},
		{name: "knowledge and possession", amr: []string{"pwd", "otp"}},
		{name: "possession and inherence", amr: []string{"hwk", "face"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := issuer.sign(t, map[string]any{
				"sub": "alice", "aud": "xminds-console", "jti": "token-" + testCase.name,
				"token_use": "human", "roles": []string{"auditor"}, "product_ids": []string{"product-a"},
				"auth_time": authenticatedAt.Unix(), "amr": testCase.amr,
			})
			principal, verifyErr := verifier.Verify(context.Background(), token)
			if verifyErr != nil {
				t.Fatalf("Verify() error = %v", verifyErr)
			}
			if !principal.AuthenticatedAt.Equal(authenticatedAt) || principal.AuthenticationAssurance != 1 {
				t.Fatalf("principal authentication = %#v", principal)
			}
		})
	}
}

func TestOIDCVerifierKeepsOrdinaryAuthenticationCompatibleWithoutFreshMFAClaims(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	for _, testCase := range []struct {
		name   string
		claims map[string]any
	}{
		{name: "claims absent", claims: nil},
		{name: "one factor plus unknown", claims: map[string]any{"auth_time": time.Now().Add(-time.Minute).Unix(), "amr": []string{"pwd", "vendor_unknown"}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			claims := map[string]any{
				"sub": "alice", "aud": "xminds-console", "jti": "token-" + testCase.name,
				"token_use": "human", "roles": []string{"auditor"}, "product_ids": []string{"product-a"},
			}
			for key, value := range testCase.claims {
				claims[key] = value
			}
			principal, verifyErr := verifier.Verify(context.Background(), issuer.sign(t, claims))
			if verifyErr != nil {
				t.Fatalf("Verify() error = %v", verifyErr)
			}
			if principal.AuthenticationAssurance != 0 {
				t.Fatalf("AuthenticationAssurance = %d, want 0", principal.AuthenticationAssurance)
			}
		})
	}
}

func TestWorkloadVerifierCannotAcquireHumanReauthenticationAssurance(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewWorkloadVerifier(context.Background(), OIDCVerifierConfig{
		Issuer: issuer.server.URL, Audience: "xminds-workloads",
	})
	if err != nil {
		t.Fatalf("NewWorkloadVerifier() error = %v", err)
	}
	principal, err := verifier.Verify(context.Background(), issuer.sign(t, map[string]any{
		"sub": "ci-release", "aud": "xminds-workloads", "jti": "token-workload-assurance",
		"token_use": "workload", "workload_provider": "github-actions", "roles": []string{"publisher"}, "product_ids": []string{"product-a"},
		"auth_time": time.Now().Add(-time.Minute).Unix(), "amr": []string{"mfa"},
	}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !principal.AuthenticatedAt.IsZero() || principal.AuthenticationAssurance != 0 {
		t.Fatalf("workload authentication = %#v", principal)
	}
}

func TestOIDCVerifierRejectsWorkloadToken(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	token := issuer.sign(t, map[string]any{
		"sub":         "ci-release",
		"aud":         "xminds-console",
		"token_use":   "workload",
		"roles":       []string{"publisher"},
		"product_ids": []string{"product-a"},
	})

	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify() error = nil, want token_use rejection")
	}
}

func TestWorkloadVerifierAcceptsOnlyWorkloadToken(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewWorkloadVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-workloads",
	})
	if err != nil {
		t.Fatalf("NewWorkloadVerifier() error = %v", err)
	}
	token := issuer.sign(t, map[string]any{
		"sub":               "ci-release",
		"aud":               "xminds-workloads",
		"jti":               "token-workload-1",
		"token_use":         "workload",
		"workload_provider": "github-actions",
		"roles":             []string{"publisher"},
		"product_ids":       []string{"product-a"},
	})

	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Kind != PrincipalKindWorkload || principal.Subject != "ci-release" || principal.Provider != WorkloadProviderGitHubActions {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestOIDCVerifierRejectsTokenWithoutTokenID(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	token := issuer.sign(t, map[string]any{
		"sub":         "alice",
		"aud":         "xminds-console",
		"token_use":   "human",
		"roles":       []string{"auditor"},
		"product_ids": []string{"product-a"},
	})

	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrTokenIDRequired) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrTokenIDRequired)
	}
}

func TestWorkloadVerifierRejectsUnknownProvider(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewWorkloadVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-workloads",
	})
	if err != nil {
		t.Fatalf("NewWorkloadVerifier() error = %v", err)
	}
	token := issuer.sign(t, map[string]any{
		"sub":               "ci-release",
		"aud":               "xminds-workloads",
		"jti":               "token-workload-2",
		"token_use":         "workload",
		"workload_provider": "unknown-ci",
		"roles":             []string{"publisher"},
		"product_ids":       []string{"product-a"},
	})

	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrWorkloadProviderInvalid) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrWorkloadProviderInvalid)
	}
}

func TestOIDCVerifierRejectsUnknownRole(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	token := issuer.sign(t, map[string]any{
		"sub":         "alice",
		"aud":         "xminds-console",
		"token_use":   "human",
		"roles":       []string{"superuser"},
		"product_ids": []string{"product-a"},
	})

	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify() error = nil, want unknown role rejection")
	}
}

func TestOIDCVerifierRejectsWrongAudienceExpiredAndFutureTokens(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:   issuer.server.URL,
		Audience: "xminds-console",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	now := time.Now().UTC()
	for _, testCase := range []struct {
		name     string
		override map[string]any
	}{
		{name: "wrong audience", override: map[string]any{"aud": "other-service"}},
		{name: "expired", override: map[string]any{"exp": now.Add(-time.Minute).Unix()}},
		{name: "not before", override: map[string]any{"nbf": now.Add(10 * time.Minute).Unix()}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			claims := map[string]any{
				"sub":         "alice",
				"aud":         "xminds-console",
				"jti":         "token-invalid-" + testCase.name,
				"token_use":   "human",
				"roles":       []string{"auditor"},
				"product_ids": []string{"product-a"},
			}
			for key, value := range testCase.override {
				claims[key] = value
			}
			if _, err := verifier.Verify(context.Background(), issuer.sign(t, claims)); err == nil {
				t.Fatal("Verify() error = nil, want claim validation failure")
			}
		})
	}
}

func TestOIDCConfigurationRejectsSymmetricSigningAlgorithm(t *testing.T) {
	t.Parallel()

	_, err := normalizeOIDCConfig(OIDCVerifierConfig{
		Issuer:            "https://identity.internal",
		Audience:          "xminds-console",
		SigningAlgorithms: []string{"HS256"},
	})
	if !errors.Is(err, ErrOIDCConfigurationInvalid) {
		t.Fatalf("normalizeOIDCConfig() error = %v, want %v", err, ErrOIDCConfigurationInvalid)
	}
}

type oidcTestIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newOIDCTestIssuer(t *testing.T) *oidcTestIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	fixture := &oidcTestIssuer{key: key}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"issuer":                                fixture.server.URL,
				"authorization_endpoint":                fixture.server.URL + "/authorize",
				"token_endpoint":                        fixture.server.URL + "/token",
				"jwks_uri":                              fixture.server.URL + "/jwks",
				"response_types_supported":              []string{"id_token"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty": "RSA",
					"use": "sig",
					"kid": "test-key-1",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				}},
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (issuer *oidcTestIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	now := time.Now().UTC()
	claims["iss"] = issuer.server.URL
	claims["iat"] = now.Unix()
	if _, exists := claims["exp"]; !exists {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	header := map[string]any{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"}
	encodedHeader := encodeJWTPart(t, header)
	encodedClaims := encodeJWTPart(t, claims)
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, issuer.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(signature))
}

func encodeJWTPart(t *testing.T, value any) string {
	t.Helper()

	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JWT part: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
