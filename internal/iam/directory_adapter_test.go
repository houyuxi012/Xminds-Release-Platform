package iam

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSecretBackedDirectoryAdapterVerifiesOIDCDiscoveryJWKSAndPrivateCA(t *testing.T) {
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeDirectoryTestJSON(t, writer, map[string]any{
				"issuer":   issuer,
				"jwks_uri": issuer + "/jwks",
			})
		case "/jwks":
			writeDirectoryTestJSON(t, writer, map[string]any{
				"keys": []map[string]any{{"kty": "RSA", "kid": "primary", "alg": "RS256", "use": "sig", "n": directoryTestRSAModulus(), "e": "AQAB"}},
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	issuer = server.URL

	resolver := directorySecretMap{
		"secret://iam/corporate-oidc": []byte(fmt.Sprintf(`{"issuer":%q,"audience":"xminds-release-platform","roles_claim":"roles","product_ids_claim":"product_ids","token_use_claim":"token_use","signing_algorithms":["RS256"],"ca_reference":"secret://iam/corporate-ca"}`, issuer)),
		"secret://iam/corporate-ca":   directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{
		Secrets: resolver, RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSecretBackedDirectoryAdapter() error = %v", err)
	}
	report, err := adapter.Verify(context.Background(), IdentitySource{
		ID: uuid.New(), Kind: IdentitySourceOIDC, SecretReference: "secret://iam/corporate-oidc", RequiredMappingsComplete: true,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !report.Reachable || !report.RequiredMappingsComplete || report.SupportsIncremental || report.SupportsPagination {
		t.Fatalf("Verify() report = %#v", report)
	}
	wantMappings := []string{"subject", "display_name", "email", "roles", "product_ids"}
	if fmt.Sprint(report.RequiredAttributes) != fmt.Sprint(wantMappings) {
		t.Fatalf("RequiredAttributes = %v, want %v", report.RequiredAttributes, wantMappings)
	}
}

func TestSecretBackedDirectoryAdapterRejectsJWKSWithoutUsablePublicKeyMaterial(t *testing.T) {
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeDirectoryTestJSON(t, writer, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
		case "/jwks":
			writeDirectoryTestJSON(t, writer, map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "metadata-only", "alg": "RS256", "use": "sig"}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	issuer = server.URL
	resolver := directorySecretMap{
		"secret://iam/oidc": []byte(fmt.Sprintf(`{"issuer":%q,"audience":"xminds-release-platform","roles_claim":"roles","product_ids_claim":"product_ids","token_use_claim":"token_use","signing_algorithms":["RS256"],"ca_reference":"secret://iam/ca"}`, issuer)),
		"secret://iam/ca":   directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Verify(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, SecretReference: "secret://iam/oidc"})
	if !errors.Is(err, ErrDirectoryResponseInvalid) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSecretBackedDirectoryAdapterRejectsOIDCSymmetricAlgorithms(t *testing.T) {
	resolver := directorySecretMap{
		"secret://iam/oidc": []byte(`{"issuer":"https://id.example.com","audience":"xminds-release-platform","roles_claim":"roles","product_ids_claim":"product_ids","token_use_claim":"token_use","signing_algorithms":["HS256"]}`),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver})
	if err != nil {
		t.Fatalf("NewSecretBackedDirectoryAdapter() error = %v", err)
	}
	_, err = adapter.Verify(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, SecretReference: "secret://iam/oidc"})
	if !errors.Is(err, ErrDirectoryConfigurationInvalid) || strings.Contains(err.Error(), "HS256") {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSecretBackedDirectoryAdapterRejectsUnknownSecretFields(t *testing.T) {
	resolver := directorySecretMap{
		"secret://iam/scim": []byte(`{"base_url":"https://id.example.com/scim/v2","bearer_token_reference":"secret://iam/token","page_size":100,"unexpected":"reject"}`),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver})
	if err != nil {
		t.Fatalf("NewSecretBackedDirectoryAdapter() error = %v", err)
	}
	_, err = adapter.Verify(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"})
	if !errors.Is(err, ErrDirectoryConfigurationInvalid) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSCIMNormalizationPreservesDuplicateStableSubjectsForConflictEngine(t *testing.T) {
	users, err := normalizeSCIMUsers([]json.RawMessage{
		json.RawMessage(`{"id":"duplicate","userName":"first.user","displayName":"First"}`),
		json.RawMessage(`{"id":"duplicate","userName":"second.user","displayName":"Second"}`),
	})
	if err != nil || len(users) != 2 {
		t.Fatalf("normalizeSCIMUsers() users=%#v error=%v", users, err)
	}
	organizations, _, _, err := normalizeSCIMGroups([]json.RawMessage{
		json.RawMessage(`{"id":"duplicate-group","displayName":"First Group"}`),
		json.RawMessage(`{"id":"duplicate-group","displayName":"Second Group"}`),
	})
	if err != nil || len(organizations) != 2 {
		t.Fatalf("normalizeSCIMGroups() organizations=%#v error=%v", organizations, err)
	}
}

func TestSecretBackedDirectoryAdapterVerifiesSCIMAndPaginatesNormalizedSnapshot(t *testing.T) {
	const bearerToken = "directory-token-must-never-leak"
	var baseURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+bearerToken {
			t.Fatalf("Authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/scim+json")
		switch request.URL.Path {
		case "/scim/v2/ServiceProviderConfig":
			writeDirectoryTestJSON(t, writer, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}})
		case "/scim/v2/ResourceTypes":
			writeDirectoryTestJSON(t, writer, map[string]any{
				"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
				"totalResults": 2,
				"startIndex":   1,
				"itemsPerPage": 2,
				"Resources": []map[string]any{
					{"id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User"},
					{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"},
				},
			})
		case "/scim/v2/Users":
			startIndex := request.URL.Query().Get("startIndex")
			if request.URL.Query().Get("count") != "1" {
				t.Fatalf("Users count = %q", request.URL.Query().Get("count"))
			}
			if startIndex == "1" {
				writeDirectoryTestJSON(t, writer, directorySCIMList(2, 1, []map[string]any{{
					"id": "user-1", "userName": " Alice ", "displayName": " Alice Example ", "active": true,
					"emails": []map[string]any{{"value": "ALICE@EXAMPLE.COM", "primary": true}},
				}}))
				return
			}
			if startIndex == "2" {
				writeDirectoryTestJSON(t, writer, directorySCIMList(2, 2, []map[string]any{{
					"id": "user-2", "userName": "bob", "displayName": "Bob", "active": false,
				}}))
				return
			}
			t.Fatalf("unexpected Users startIndex = %q", startIndex)
		case "/scim/v2/Groups":
			if request.URL.Query().Get("startIndex") != "1" || request.URL.Query().Get("count") != "1" {
				t.Fatalf("Groups query = %q", request.URL.RawQuery)
			}
			writeDirectoryTestJSON(t, writer, directorySCIMList(1, 1, []map[string]any{{
				"id": "group-1", "displayName": "Engineering",
				"members": []map[string]any{{"value": "user-1", "type": "User"}, {"value": "group-child", "type": "Group"}},
			}}))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	baseURL = server.URL + "/scim/v2"
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":1}`, baseURL)),
		"secret://iam/token": []byte(bearerToken),
		"secret://iam/ca":    directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{
		Secrets: resolver, RequestTimeout: 3 * time.Second, MaximumPages: 10, MaximumObjects: 10,
	})
	if err != nil {
		t.Fatalf("NewSecretBackedDirectoryAdapter() error = %v", err)
	}
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim", RequiredMappingsComplete: true}
	report, err := adapter.Verify(context.Background(), source)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !report.Reachable || !report.SupportsPagination || report.SupportsIncremental {
		t.Fatalf("Verify() report = %#v", report)
	}

	first, err := adapter.Sync(context.Background(), source, "")
	if err != nil {
		t.Fatalf("Sync(first) error = %v", err)
	}
	if len(first.Users) != 1 || first.Users[0].ExternalSubject != "user-1" || first.Users[0].Username != "alice" || first.Users[0].Email != "alice@example.com" || !first.Users[0].Enabled || first.NextCursor == "" || first.Complete {
		t.Fatalf("Sync(first) = %#v", first)
	}
	second, err := adapter.Sync(context.Background(), source, first.NextCursor)
	if err != nil {
		t.Fatalf("Sync(second) error = %v", err)
	}
	if len(second.Users) != 1 || second.Users[0].ExternalSubject != "user-2" || second.Users[0].Enabled || second.NextCursor == "" || second.Complete {
		t.Fatalf("Sync(second) = %#v", second)
	}
	third, err := adapter.Sync(context.Background(), source, second.NextCursor)
	if err != nil {
		t.Fatalf("Sync(third) error = %v", err)
	}
	if len(third.Organizations) != 1 || third.Organizations[0].ExternalID != "group-1" || len(third.Memberships) != 1 || len(third.OrganizationParents) != 1 || !third.Complete || third.NextCursor != "" {
		t.Fatalf("Sync(third) = %#v", third)
	}

	bounded, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{
		Secrets: resolver, RequestTimeout: 3 * time.Second, MaximumPages: 10, MaximumObjects: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	boundedFirst, err := bounded.Sync(context.Background(), source, "")
	if err != nil {
		t.Fatal(err)
	}
	boundedSecond, err := bounded.Sync(context.Background(), source, boundedFirst.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Sync(context.Background(), source, boundedSecond.NextCursor); !errors.Is(err, ErrDirectoryLimitExceeded) {
		t.Fatalf("relationship-inclusive object limit error = %v", err)
	}
}

func TestSecretBackedDirectoryAdapterRejectsSCIMRedirectWithoutLeakingResponseOrBearer(t *testing.T) {
	const bearerToken = "bearer-secret-value"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/unexpected?body="+url.QueryEscape(bearerToken), http.StatusFound)
	}))
	t.Cleanup(server.Close)
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":100}`, server.URL+"/scim/v2")),
		"secret://iam/token": []byte(bearerToken),
		"secret://iam/ca":    directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver})
	if err != nil {
		t.Fatalf("NewSecretBackedDirectoryAdapter() error = %v", err)
	}
	_, err = adapter.Verify(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"})
	if !errors.Is(err, ErrDirectoryUpstreamRejected) {
		t.Fatalf("Verify() error = %v", err)
	}
	if strings.Contains(err.Error(), bearerToken) || strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("Verify() leaked upstream data: %v", err)
	}
}

type directorySecretMap map[string][]byte

func (secrets directorySecretMap) Resolve(_ context.Context, reference string) ([]byte, error) {
	value, found := secrets[reference]
	if !found {
		return nil, ErrSecretReferenceInvalid
	}
	return append([]byte(nil), value...), nil
}

func directoryTestServerCA(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

func directoryTestRSAModulus() string {
	modulus := make([]byte, 256)
	modulus[0] = 0x80
	modulus[len(modulus)-1] = 0x01
	return base64.RawURLEncoding.EncodeToString(modulus)
}

func writeDirectoryTestJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
}

func directorySCIMList(total, start int, resources []map[string]any) map[string]any {
	return map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}
