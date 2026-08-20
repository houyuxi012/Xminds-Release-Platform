package iam

import (
	"bytes"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

func TestOIDCTrustKeySetNegativeCachesUnknownKeyID(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	verifier := fixture.humanVerifier(t)
	token := fixture.sign(t, fixture.rotatedKey, "rotated-key", "unknown-key")

	for range 2 {
		if _, err := verifier.Verify(context.Background(), token); err == nil {
			t.Fatal("Verify(unknown kid) error=nil")
		}
	}
	if calls := fixture.jwksCalls.Load(); calls != 2 {
		t.Fatalf("JWKS requests=%d, want one prefetch and one negatively cached refresh", calls)
	}
}

func TestOIDCTrustKeySetGloballyThrottlesDistinctUnknownKeyIDs(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	verifier := fixture.humanVerifier(t)
	for index := range maximumOIDCNegativeKeyIDs {
		token := fixture.sign(t, fixture.rotatedKey, fmt.Sprintf("unknown-%03d", index), fmt.Sprintf("token-%03d", index))
		if _, err := verifier.Verify(context.Background(), token); err == nil {
			t.Fatalf("Verify(distinct unknown kid %d) error=nil", index)
		}
	}
	if calls := fixture.jwksCalls.Load(); calls != 2 {
		t.Fatalf("JWKS requests=%d, want one prefetch plus one globally throttled refresh", calls)
	}
}

func TestOIDCTrustKeySetFailureBackoffAndJitterAreDeterministic(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	fixture.jwksResponse = func(writer http.ResponseWriter, _ *http.Request, _ int32) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}
	keySet := fixture.directKeySet(t)
	now := time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)
	keySet.now = func() time.Time { return now }
	keySet.refreshJitter = func(maximum time.Duration) time.Duration { return maximum }

	verifyUnknown := func(keyID string) {
		t.Helper()
		if _, err := keySet.VerifySignature(context.Background(), fixture.sign(t, fixture.rotatedKey, keyID, keyID)); err == nil {
			t.Fatalf("VerifySignature(%s) error=nil", keyID)
		}
	}
	verifyUnknown("failure-1")
	firstDelay := oidcRefreshFailureBase + oidcRefreshFailureBase/oidcRefreshJitterDivisor
	keySet.mu.RLock()
	firstAllowed, firstFailures := keySet.nextAllowedRefresh, keySet.refreshFailures
	keySet.mu.RUnlock()
	if firstFailures != 1 || !firstAllowed.Equal(now.Add(firstDelay)) {
		t.Fatalf("first failure count=%d next=%s, want %s", firstFailures, firstAllowed, now.Add(firstDelay))
	}
	verifyUnknown("failure-suppressed")
	if calls := fixture.jwksCalls.Load(); calls != 1 {
		t.Fatalf("JWKS calls during first backoff=%d", calls)
	}

	now = firstAllowed
	verifyUnknown("failure-2")
	secondBase := 2 * oidcRefreshFailureBase
	secondDelay := secondBase + secondBase/oidcRefreshJitterDivisor
	keySet.mu.RLock()
	secondAllowed, secondFailures := keySet.nextAllowedRefresh, keySet.refreshFailures
	keySet.mu.RUnlock()
	if secondFailures != 2 || !secondAllowed.Equal(now.Add(secondDelay)) {
		t.Fatalf("second failure count=%d next=%s, want %s", secondFailures, secondAllowed, now.Add(secondDelay))
	}
	now = now.Add(firstDelay)
	verifyUnknown("failure-still-suppressed")
	if calls := fixture.jwksCalls.Load(); calls != 2 {
		t.Fatalf("JWKS calls during exponential backoff=%d", calls)
	}
}

func TestOIDCTrustKeySetRefreshesLegalRotationAfterGlobalCooldown(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	fixture.jwksResponse = func(writer http.ResponseWriter, _ *http.Request, call int32) {
		if call == 1 {
			fixture.writeKeys(t, writer, fixture.initialKey, "initial-key")
			return
		}
		fixture.writeKeys(t, writer, fixture.rotatedKey, "rotated-key")
	}
	keySet := fixture.directKeySet(t)
	now := time.Date(2026, 8, 21, 20, 30, 0, 0, time.UTC)
	keySet.now = func() time.Time { return now }
	keySet.refreshJitter = func(time.Duration) time.Duration { return 0 }

	missing := fixture.sign(t, fixture.rotatedKey, "unknown-before-rotation", "missing")
	if _, err := keySet.VerifySignature(context.Background(), missing); err == nil {
		t.Fatal("VerifySignature(missing key) error=nil")
	}
	rotated := fixture.sign(t, fixture.rotatedKey, "rotated-key", "rotated")
	if _, err := keySet.VerifySignature(context.Background(), rotated); err == nil {
		t.Fatal("VerifySignature(rotation during cooldown) error=nil")
	}
	if calls := fixture.jwksCalls.Load(); calls != 1 {
		t.Fatalf("JWKS calls during successful-missing cooldown=%d", calls)
	}
	now = now.Add(oidcRefreshSuccessCooldown)
	if _, err := keySet.VerifySignature(context.Background(), rotated); err != nil {
		t.Fatalf("VerifySignature(rotation after cooldown) error=%v", err)
	}
	if calls := fixture.jwksCalls.Load(); calls != 2 {
		t.Fatalf("JWKS calls after legal rotation=%d", calls)
	}
}

func TestOIDCTrustKeySetNegativeCacheRemainsBoundedAcrossExpiryCycles(t *testing.T) {
	now := time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)
	keySet := &boundedOIDCKeySet{now: func() time.Time { return now }, negative: make(map[string]time.Time)}
	for index := range maximumOIDCNegativeKeyIDs {
		keySet.rememberNegative(fmt.Sprintf("expired-%03d", index))
	}
	now = now.Add(oidcNegativeKeyIDTTL + time.Second)
	for index := range maximumOIDCNegativeKeyIDs {
		keySet.negativeCached(fmt.Sprintf("expired-%03d", index))
	}
	for index := range maximumOIDCNegativeKeyIDs + 1 {
		keySet.rememberNegative(fmt.Sprintf("current-%03d", index))
	}
	if len(keySet.negative) != maximumOIDCNegativeKeyIDs || len(keySet.negativeOrder) != maximumOIDCNegativeKeyIDs {
		t.Fatalf("negative cache map=%d order=%d, want hard bound %d", len(keySet.negative), len(keySet.negativeOrder), maximumOIDCNegativeKeyIDs)
	}
}

func TestOIDCTrustKeySetRejectsOversizedKeyIDWithoutRefresh(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	verifier := fixture.humanVerifier(t)
	token := fixture.sign(t, fixture.rotatedKey, strings.Repeat("k", 129), "oversized-kid")

	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify(oversized kid) error=nil")
	}
	if calls := fixture.jwksCalls.Load(); calls != 1 {
		t.Fatalf("JWKS requests=%d, oversized kid must not trigger refresh", calls)
	}
}

func TestOIDCTrustKeySetRejectsOversizedOrAmbiguousPrefetchedKeySet(t *testing.T) {
	key := generateBoundedJWKSKey(t)
	keys := make([]map[string]any, 0, maximumOIDCVerificationKeys+1)
	for index := range maximumOIDCVerificationKeys + 1 {
		keys = append(keys, boundedJWKSMap(key, fmt.Sprintf("key-%03d", index)))
	}
	contents, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	var keySet oidcJWKSet
	if err := json.Unmarshal(contents, &keySet); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]struct{}{"RS256": {}}
	if _, err := parseOIDCVerificationKeys(keySet, allowed); !errors.Is(err, errOIDCKeySetRejected) {
		t.Fatalf("parseOIDCVerificationKeys(129 keys) error=%v", err)
	}

	contents, err = json.Marshal(map[string]any{"keys": []map[string]any{boundedJWKSMap(key, " key-with-space")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &keySet); err != nil {
		t.Fatal(err)
	}
	if _, err := parseOIDCVerificationKeys(keySet, allowed); !errors.Is(err, errOIDCKeySetRejected) {
		t.Fatalf("parseOIDCVerificationKeys(ambiguous kid) error=%v", err)
	}
}

func TestOIDCTrustKeySetRefreshUsesCallerDeadline(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fixture.jwksResponse = func(writer http.ResponseWriter, request *http.Request, call int32) {
		if call == 1 {
			fixture.writeKeys(t, writer, fixture.initialKey, "initial-key")
			return
		}
		once.Do(func() { close(started) })
		select {
		case <-request.Context().Done():
			close(canceled)
		case <-release:
		}
	}
	verifier := fixture.humanVerifier(t)
	token := fixture.sign(t, fixture.rotatedKey, "rotated-key", "deadline")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(ctx, token)
		result <- err
	}()
	<-started
	verifyErr := <-result
	if verifyErr == nil {
		t.Fatalf("Verify(slow refresh) error=%v", verifyErr)
	}
	select {
	case <-canceled:
		close(release)
	case <-time.After(400 * time.Millisecond):
		close(release)
		t.Fatal("JWKS refresh continued after caller operation deadline")
	}
}

func TestOIDCTrustKeySetStopsReadingOversizedJWKSBody(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	wroteBound := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	fixture.jwksResponse = func(writer http.ResponseWriter, request *http.Request, call int32) {
		if call == 1 {
			fixture.writeKeys(t, writer, fixture.initialKey, "initial-key")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(bytes.Repeat([]byte(" "), maximumDirectoryResponseBytes+1))
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(wroteBound)
		select {
		case <-request.Context().Done():
			close(canceled)
		case <-release:
		}
	}
	verifier := fixture.humanVerifier(t)
	token := fixture.sign(t, fixture.rotatedKey, "rotated-key", "oversized-body")
	result := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(context.Background(), token)
		result <- err
	}()
	<-wroteBound
	select {
	case <-canceled:
		close(release)
	case <-time.After(500 * time.Millisecond):
		close(release)
		<-result
		t.Fatal("JWKS refresh kept reading after the 2 MiB response boundary")
	}
	if err := <-result; err == nil {
		t.Fatal("Verify(oversized JWKS) error=nil")
	}
}

func TestOIDCTrustKeySetRefreshesRotatedKeyOnceForConcurrentTokens(t *testing.T) {
	fixture := newBoundedJWKSFixture(t)
	fixture.jwksResponse = func(writer http.ResponseWriter, _ *http.Request, call int32) {
		if call == 1 {
			fixture.writeKeys(t, writer, fixture.initialKey, "initial-key")
			return
		}
		time.Sleep(50 * time.Millisecond)
		fixture.writeKeys(t, writer, fixture.rotatedKey, "rotated-key")
	}
	verifier := fixture.humanVerifier(t)
	token := fixture.sign(t, fixture.rotatedKey, "rotated-key", "rotated")
	const callers = 12
	errorsFound := make(chan error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			principal, err := verifier.Verify(context.Background(), token)
			if err == nil && principal.TokenID != "rotated" {
				err = errors.New("wrong rotated principal")
			}
			errorsFound <- err
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("Verify(rotated token) error=%v", err)
		}
	}
	if calls := fixture.jwksCalls.Load(); calls != 2 {
		t.Fatalf("JWKS requests=%d, want one prefetch and one shared rotation refresh", calls)
	}
}

type boundedJWKSFixture struct {
	server       *httptest.Server
	initialKey   *rsa.PrivateKey
	rotatedKey   *rsa.PrivateKey
	jwksCalls    atomic.Int32
	jwksResponse func(http.ResponseWriter, *http.Request, int32)
}

func newBoundedJWKSFixture(t *testing.T) *boundedJWKSFixture {
	t.Helper()
	fixture := &boundedJWKSFixture{initialKey: generateBoundedJWKSKey(t), rotatedKey: generateBoundedJWKSKey(t)}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeDirectoryTestJSON(t, writer, map[string]any{"issuer": fixture.server.URL, "jwks_uri": fixture.server.URL + "/jwks"})
		case "/jwks":
			call := fixture.jwksCalls.Add(1)
			if fixture.jwksResponse != nil {
				fixture.jwksResponse(writer, request, call)
				return
			}
			fixture.writeKeys(t, writer, fixture.initialKey, "initial-key")
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *boundedJWKSFixture) humanVerifier(t *testing.T) identity.Verifier {
	t.Helper()
	secret, err := json.Marshal(map[string]any{
		"issuer": fixture.server.URL, "audience": "console", "roles_claim": "roles",
		"product_ids_claim": "product_ids", "token_use_claim": "token_use",
		"signing_algorithms": []string{"RS256"}, "ca_reference": "secret://iam/ca",
	})
	if err != nil {
		t.Fatal(err)
	}
	secrets := directorySecretMap{
		"secret://iam/oidc": secret,
		"secret://iam/ca":   directoryTestServerCA(t, fixture.server),
	}
	factory, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: secrets, RequestTimeout: 3 * time.Second, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/oidc", Version: 1}
	material, err := factory.resolve(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := factory.humanVerifier(context.Background(), material)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func (fixture *boundedJWKSFixture) directKeySet(t *testing.T) *boundedOIDCKeySet {
	t.Helper()
	contents, err := json.Marshal(map[string]any{"keys": []map[string]any{boundedJWKSMap(fixture.initialKey, "initial-key")}})
	if err != nil {
		t.Fatal(err)
	}
	var initial oidcJWKSet
	if err := json.Unmarshal(contents, &initial); err != nil {
		t.Fatal(err)
	}
	client := fixture.server.Client()
	client.Timeout = 3 * time.Second
	keySet, err := newBoundedOIDCKeySet(client, fixture.server.URL+"/jwks", []string{"RS256"}, initial)
	if err != nil {
		t.Fatal(err)
	}
	return keySet
}

func (fixture *boundedJWKSFixture) writeKeys(t *testing.T, writer http.ResponseWriter, key *rsa.PrivateKey, keyID string) {
	t.Helper()
	writeDirectoryTestJSON(t, writer, map[string]any{"keys": []map[string]any{boundedJWKSMap(key, keyID)}})
}

func boundedJWKSMap(key *rsa.PrivateKey, keyID string) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "kid": keyID, "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func (fixture *boundedJWKSFixture) sign(t *testing.T, key *rsa.PrivateKey, keyID, tokenID string) string {
	t.Helper()
	now := time.Now().UTC()
	header := activeOIDCEncodeJWTPart(t, map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	payload := activeOIDCEncodeJWTPart(t, map[string]any{
		"iss": fixture.server.URL, "sub": "alice", "aud": "console", "jti": tokenID, "token_use": "human",
		"roles": []string{string(identity.RoleViewer)}, "product_ids": []string{"product-a"}, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func generateBoundedJWKSKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
