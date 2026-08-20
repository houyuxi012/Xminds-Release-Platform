package authorizationcontext

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestUnsignedClientFieldsCannotBecomeAuthorizationFacts(t *testing.T) {
	t.Parallel()

	resolver, _, binding := newResolverHarness(t)
	_, err := resolver.Resolve(context.Background(), SignedEnvelope{Compact: `{"license_id":"forged"}`}, binding)
	if !errors.Is(err, ErrUntrustedContext) {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestResolverBindsSignedContextToRequestAndRejectsReplay(t *testing.T) {
	t.Parallel()

	resolver, privateKey, binding := newResolverHarness(t)
	envelope := signClaims(t, privateKey, validClaims(binding))
	snapshot, err := resolver.Resolve(context.Background(), envelope, binding)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if snapshot.LicenseID != "LIC-2026-000184" || snapshot.ClientAppVersion != "3.8.2" || snapshot.ContextDigest == [32]byte{} {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if _, err := resolver.Resolve(context.Background(), envelope, binding); !errors.Is(err, ErrContextReplay) {
		t.Fatalf("replayed Resolve() error = %v", err)
	}
}

func TestResolverRejectsRequestBindingMismatch(t *testing.T) {
	t.Parallel()

	resolver, privateKey, binding := newResolverHarness(t)
	envelope := signClaims(t, privateKey, validClaims(binding))
	binding.Path = "/api/v1/catalog/ngep/beta"
	if _, err := resolver.Resolve(context.Background(), envelope, binding); !errors.Is(err, ErrRequestBindingInvalid) {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestExpiredLicenseProducesImmutableDenySnapshot(t *testing.T) {
	t.Parallel()

	resolver, privateKey, binding := newResolverHarness(t)
	claims := validClaims(binding)
	claims.LicenseStatus = LicenseStatusExpired
	claims.LicenseExpiresAt = time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	claims.Decision = DecisionAllow
	snapshot, err := resolver.Resolve(context.Background(), signClaims(t, privateKey, claims), binding)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if snapshot.Decision != DecisionDeny || snapshot.ReasonCode != "LICENSE_EXPIRED" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func newResolverHarness(t *testing.T) (*JWSResolver, ed25519.PrivateKey, RequestBinding) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	resolver, err := NewJWSResolver(JWSResolverConfig{
		Issuer: "https://license.example.test", Audience: "xminds-release-public", VerificationKey: publicKey,
		Algorithms: []jose.SignatureAlgorithm{jose.EdDSA}, ReplayStore: NewMemoryReplayStore(),
		Clock: func() time.Time { return now }, ClockSkew: 30 * time.Second, MaximumContextAge: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolver, privateKey, RequestBinding{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e71", Method: "GET", Path: "/api/v1/catalog/ngep/stable"}
}

func validClaims(binding RequestBinding) signedClaims {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	return signedClaims{
		Issuer: "https://license.example.test", Audience: []string{"xminds-release-public"},
		ExpiresAt: now.Add(time.Minute).Unix(), NotBefore: now.Add(-time.Minute).Unix(), IssuedAt: now.Add(-time.Minute).Unix(),
		ContextID: "ctx-018f835d-7e4b-7abc-9f42-67a2f5f48e72", RequestID: binding.RequestID, Method: binding.Method, Path: binding.Path,
		CustomerID: "customer-184", CustomerName: "示例设计院", TenantID: "tenant-01",
		AuthorizationName: "Xminds Enterprise", ClientAppVersion: "3.8.2", LicenseID: "LIC-2026-000184",
		LicenseExpiresAt: time.Date(2027, 8, 20, 0, 0, 0, 0, time.UTC), LicenseStatus: LicenseStatusValid,
		Decision: DecisionAllow, ReasonCode: "LICENSE_VALID",
	}
}

func signClaims(t *testing.T, privateKey ed25519.PrivateKey, claims signedClaims) SignedEnvelope {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, new(jose.SignerOptions).WithType("authorization-context+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return SignedEnvelope{Compact: compact}
}
