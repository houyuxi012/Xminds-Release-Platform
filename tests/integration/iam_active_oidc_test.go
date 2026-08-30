package integration_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestIAMActiveOIDCVerifierTracksPostgresSourceAndStatusTransitions(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error=%v", err)
	}
	issuerA := newActivePGIssuer(t)
	issuerB := newActivePGIssuer(t)
	sourceA, sourceB := uuid.New(), uuid.New()
	secrets := activePGSecrets{
		"secret://iam/pg-oidc-a": activePGSecret(t, issuerA.server.URL, "pg-audience-a", "secret://iam/pg-ca-a"),
		"secret://iam/pg-ca-a":   activePGServerCA(t, issuerA.server),
		"secret://iam/pg-oidc-b": activePGSecret(t, issuerB.server.URL, "pg-audience-b", "secret://iam/pg-ca-b"),
		"secret://iam/pg-ca-b":   activePGServerCA(t, issuerB.server),
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `TRUNCATE TABLE identity_sources CASCADE`); err != nil {
		t.Fatalf("reset active OIDC state: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_sources (
    id, name, source_kind, status, secret_reference, required_mappings_complete, verified_configuration_version,
    verified_at, previewed_at, version, created_at, updated_at
) VALUES
    ($1, 'Active PG OIDC A', 'oidc', 'enabled', 'secret://iam/pg-oidc-a', TRUE, 1, clock_timestamp(), clock_timestamp(), 3, clock_timestamp(), clock_timestamp()),
	($2, 'Active PG OIDC B', 'oidc', 'enabled', 'secret://iam/pg-oidc-b', TRUE, 1, clock_timestamp(), clock_timestamp(), 5, clock_timestamp(), clock_timestamp())`, sourceA, sourceB); err != nil {
		t.Fatalf("seed active OIDC state: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO iam_login_state (singleton, login_mode, active_source_id, version, updated_by, updated_at)
VALUES (TRUE, 'sso', $1, 1, 'test:active-oidc', clock_timestamp())`, sourceA); err != nil {
		t.Fatalf("seed active login state: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit active OIDC seed: %v", err)
	}
	repository := iam.NewPostgresRepository(pool)
	trusts, err := iam.NewOIDCTrustFactory(iam.OIDCTrustFactoryConfig{Secrets: secrets, RequestTimeout: 3 * time.Second, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := iam.NewActiveOIDCVerifier(iam.ActiveOIDCVerifierConfig{Repository: repository, Trusts: trusts})
	if err != nil {
		t.Fatal(err)
	}
	tokenA := issuerA.sign(t, "same-subject", "pg-audience-a", "pg-token-a")
	tokenB := issuerB.sign(t, "same-subject", "pg-audience-b", "pg-token-b")
	principal, err := verifier.Verify(ctx, tokenA)
	if err != nil || principal.Subject != "same-subject" || principal.TokenID != "pg-token-a" || principal.IdentitySourceID != sourceA.String() {
		t.Fatalf("Verify(source A) principal=%#v error=%v", principal, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE iam_login_state SET active_source_id=$1, version=version+1, updated_at=clock_timestamp() WHERE singleton=TRUE`, sourceB); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, tokenA); !errors.Is(err, iam.ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("old source token after PostgreSQL switch error=%v", err)
	}
	principal, err = verifier.Verify(ctx, tokenB)
	if err != nil || principal.Subject != "same-subject" || principal.TokenID != "pg-token-b" || principal.IdentitySourceID != sourceB.String() {
		t.Fatalf("Verify(source B) principal=%#v error=%v", principal, err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_sources SET status='fault', fault_code='OIDC_UNREACHABLE', version=version+1, updated_at=clock_timestamp() WHERE id=$1`, sourceB); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE iam_login_state SET login_mode='fault', fault_code='OIDC_UNREACHABLE', version=version+1, updated_at=clock_timestamp() WHERE singleton=TRUE`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, tokenB); !errors.Is(err, iam.ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("fault source token error=%v", err)
	}
}

type activePGSecrets map[string][]byte

func (secrets activePGSecrets) Resolve(_ context.Context, reference string) ([]byte, error) {
	value, found := secrets[reference]
	if !found {
		return nil, errors.New("secret not found")
	}
	return append([]byte(nil), value...), nil
}

type activePGIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newActivePGIssuer(t *testing.T) *activePGIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &activePGIssuer{key: key}
	issuer.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"issuer": issuer.server.URL, "authorization_endpoint": issuer.server.URL + "/authorize",
				"token_endpoint": issuer.server.URL + "/token", "jwks_uri": issuer.server.URL + "/jwks",
				"response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			_ = json.NewEncoder(writer).Encode(map[string]any{"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "kid": "pg-key", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (issuer *activePGIssuer) sign(t *testing.T, subject, audience, tokenID string) string {
	t.Helper()
	now := time.Now().UTC()
	header := activePGJWTPart(t, map[string]any{"alg": "RS256", "kid": "pg-key", "typ": "JWT"})
	payload := activePGJWTPart(t, map[string]any{
		"iss": issuer.server.URL, "sub": subject, "aud": audience, "jti": tokenID, "token_use": "human",
		"roles": []string{"viewer"}, "product_ids": []string{"product-a"}, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, issuer.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func activePGJWTPart(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func activePGSecret(t *testing.T, issuer, audience, caReference string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"issuer": issuer, "audience": audience, "roles_claim": "roles", "product_ids_claim": "product_ids",
		"token_use_claim": "token_use", "signing_algorithms": []string{"RS256"}, "ca_reference": caReference,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func activePGServerCA(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}
