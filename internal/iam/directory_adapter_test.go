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
		Secrets: resolver, RequestTimeout: 3 * time.Second, AllowLoopbackHTTP: true,
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
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
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
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
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
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("NewSecretBackedDirectoryAdapter() error = %v", err)
	}
	_, _, _, err = adapter.loadSCIM(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"})
	if !errors.Is(err, ErrDirectoryConfigurationInvalid) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSecretBackedDirectoryAdapterRejectsDuplicateSecretMembers(t *testing.T) {
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(`{"base_url":"https://first.example.com/scim/v2","base_url":"https://second.example.com/scim/v2","bearer_token_reference":"secret://iam/token","page_size":100}`),
		"secret://iam/token": []byte("directory-bearer"),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = adapter.loadSCIM(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"})
	if !errors.Is(err, ErrDirectoryConfigurationInvalid) {
		t.Fatalf("Verify() error=%v, want duplicate secret rejection", err)
	}
}

func TestSCIMNormalizationPreservesDuplicateStableSubjectsForConflictEngine(t *testing.T) {
	users, err := normalizeSCIMUsers([]json.RawMessage{
		json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"duplicate","userName":"first.user","displayName":"First"}`),
		json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"duplicate","userName":"second.user","displayName":"Second"}`),
	})
	if err != nil || len(users) != 2 {
		t.Fatalf("normalizeSCIMUsers() users=%#v error=%v", users, err)
	}
	organizations, _, _, err := normalizeSCIMGroups([]json.RawMessage{
		json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"duplicate-group","displayName":"First Group"}`),
		json.RawMessage(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"duplicate-group","displayName":"Second Group"}`),
	})
	if err != nil || len(organizations) != 2 {
		t.Fatalf("normalizeSCIMGroups() organizations=%#v error=%v", organizations, err)
	}
}

func TestSCIMNormalizationRequiresCorrectCoreSchemaAndAllowsExtensions(t *testing.T) {
	userCases := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "missing", raw: `{"id":"user-1","userName":"alice"}`},
		{name: "wrong resource type", raw: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"user-1","userName":"alice"}`},
		{name: "extension", raw: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:example:params:scim:schemas:extension:2.0:User"],"id":"user-1","userName":"alice"}`, want: true},
	}
	for _, testCase := range userCases {
		t.Run("user/"+testCase.name, func(t *testing.T) {
			users, err := normalizeSCIMUsers([]json.RawMessage{json.RawMessage(testCase.raw)})
			if testCase.want && (err != nil || len(users) != 1) {
				t.Fatalf("normalizeSCIMUsers() users=%#v error=%v", users, err)
			}
			if !testCase.want && !errors.Is(err, ErrDirectoryResponseInvalid) {
				t.Fatalf("normalizeSCIMUsers() error=%v, want response invalid", err)
			}
		})
	}
	groupCases := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "missing", raw: `{"id":"group-1","displayName":"Engineering"}`},
		{name: "wrong resource type", raw: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"group-1","displayName":"Engineering"}`},
		{name: "extension", raw: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","urn:example:params:scim:schemas:extension:2.0:Group"],"id":"group-1","displayName":"Engineering"}`, want: true},
	}
	for _, testCase := range groupCases {
		t.Run("group/"+testCase.name, func(t *testing.T) {
			groups, _, _, err := normalizeSCIMGroups([]json.RawMessage{json.RawMessage(testCase.raw)})
			if testCase.want && (err != nil || len(groups) != 1) {
				t.Fatalf("normalizeSCIMGroups() groups=%#v error=%v", groups, err)
			}
			if !testCase.want && !errors.Is(err, ErrDirectoryResponseInvalid) {
				t.Fatalf("normalizeSCIMGroups() error=%v, want response invalid", err)
			}
		})
	}
}

func TestSCIMGroupSelfReferenceIsPreservedForCycleConflictEngine(t *testing.T) {
	organizations, memberships, parents, err := normalizeSCIMGroups([]json.RawMessage{json.RawMessage(`{
  "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id":"self-group","displayName":"Self Group",
  "members":[{"value":"self-group","type":"Group"}]
}`)})
	if err != nil || len(organizations) != 1 || len(memberships) != 0 || len(parents) != 1 ||
		parents[0].OrganizationExternalID != "self-group" || parents[0].ParentExternalID != "self-group" {
		t.Fatalf("normalizeSCIMGroups() organizations=%#v memberships=%#v parents=%#v error=%v", organizations, memberships, parents, err)
	}
}

func TestSecretBackedDirectoryAdapterRejectsIncompleteResourceTypesList(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/scim/v2/ServiceProviderConfig":
			writeDirectoryTestJSON(t, writer, map[string]any{
				"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
				"pagination": map[string]any{"supported": true},
			})
		case "/scim/v2/ResourceTypes":
			writeDirectoryTestJSON(t, writer, map[string]any{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": 3, "startIndex": 1, "itemsPerPage": 2,
				"Resources": []map[string]any{
					{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema},
					{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema},
				},
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":100}`, server.URL+"/scim/v2")),
		"secret://iam/token": []byte("directory-bearer"),
		"secret://iam/ca":    directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Verify(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"})
	if !errors.Is(err, ErrDirectoryResponseInvalid) {
		t.Fatalf("Verify() error=%v, want incomplete ResourceTypes rejection", err)
	}
}

func TestSecretBackedDirectoryAdapterCollectsPaginatedResourceTypesAndRequiresPaginationCapability(t *testing.T) {
	paginationSupported := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/scim/v2/ServiceProviderConfig":
			writeDirectoryTestJSON(t, writer, map[string]any{
				"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
				"pagination": map[string]any{"supported": paginationSupported},
			})
		case "/scim/v2/ResourceTypes":
			start := request.URL.Query().Get("startIndex")
			if request.URL.Query().Get("count") != "200" {
				t.Fatalf("ResourceTypes count=%q", request.URL.Query().Get("count"))
			}
			if start == "1" {
				writeDirectoryTestJSON(t, writer, directorySCIMList(2, 1, []map[string]any{{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema}}))
				return
			}
			if start == "2" {
				writeDirectoryTestJSON(t, writer, directorySCIMList(2, 2, []map[string]any{{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema}}))
				return
			}
			t.Fatalf("ResourceTypes startIndex=%q", start)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":100}`, server.URL+"/scim/v2")),
		"secret://iam/token": []byte("directory-bearer"),
		"secret://iam/ca":    directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"}
	report, err := adapter.Verify(context.Background(), source)
	if err != nil || !report.SupportsPagination {
		t.Fatalf("Verify(paginated) report=%#v error=%v", report, err)
	}
	paginationSupported = false
	if _, err := adapter.Verify(context.Background(), source); !errors.Is(err, ErrDirectoryResponseInvalid) {
		t.Fatalf("Verify(no pagination) error=%v", err)
	}
}

func TestSecretBackedDirectoryAdapterRejectsSCIMTotalResultsDriftDeterministically(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/scim/v2/Users" {
			http.NotFound(writer, request)
			return
		}
		switch request.URL.Query().Get("startIndex") {
		case "1":
			writeDirectoryTestJSON(t, writer, directorySCIMList(2, 1, []map[string]any{{"schemas": []string{scimUserSchema}, "id": "user-1", "userName": "alice"}}))
		case "2":
			writeDirectoryTestJSON(t, writer, directorySCIMList(3, 2, []map[string]any{{"schemas": []string{scimUserSchema}, "id": "user-2", "userName": "bob"}}))
		default:
			t.Fatalf("unexpected startIndex=%q", request.URL.Query().Get("startIndex"))
		}
	}))
	t.Cleanup(server.Close)
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":1}`, server.URL+"/scim/v2")),
		"secret://iam/token": []byte("directory-bearer"),
		"secret://iam/ca":    directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"}
	first, err := adapter.Sync(context.Background(), source, "")
	if err != nil || first.NextCursor == "" {
		t.Fatalf("Sync(first)=%#v error=%v", first, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := adapter.Sync(context.Background(), source, first.NextCursor); !errors.Is(err, ErrDirectoryResponseInvalid) {
			t.Fatalf("Sync(drift attempt %d) error=%v", attempt+1, err)
		}
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
			writeDirectoryTestJSON(t, writer, map[string]any{
				"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
				"pagination": map[string]any{"supported": true},
			})
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
					"schemas": []string{scimUserSchema},
					"id":      "user-1", "userName": " Alice ", "displayName": " Alice Example ", "active": true,
					"emails": []map[string]any{{"value": "ALICE@EXAMPLE.COM", "primary": true}},
				}}))
				return
			}
			if startIndex == "2" {
				writeDirectoryTestJSON(t, writer, directorySCIMList(2, 2, []map[string]any{{
					"schemas": []string{scimUserSchema},
					"id":      "user-2", "userName": "bob", "displayName": "Bob", "active": false,
				}}))
				return
			}
			t.Fatalf("unexpected Users startIndex = %q", startIndex)
		case "/scim/v2/Groups":
			if request.URL.Query().Get("startIndex") != "1" || request.URL.Query().Get("count") != "1" {
				t.Fatalf("Groups query = %q", request.URL.RawQuery)
			}
			writeDirectoryTestJSON(t, writer, directorySCIMList(1, 1, []map[string]any{{
				"schemas": []string{scimGroupSchema},
				"id":      "group-1", "displayName": "Engineering",
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
		Secrets: resolver, RequestTimeout: 3 * time.Second, MaximumPages: 10, MaximumObjects: 10, AllowLoopbackHTTP: true,
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
		Secrets: resolver, RequestTimeout: 3 * time.Second, MaximumPages: 10, MaximumObjects: 4, AllowLoopbackHTTP: true,
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
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
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

func TestSecretBackedDirectoryAdapterRejectsHTTPSLoopbackByDefaultBeforeSendingBearer(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	t.Cleanup(server.Close)
	resolver := directorySecretMap{
		"secret://iam/scim":  []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":100}`, server.URL+"/scim/v2")),
		"secret://iam/token": []byte("directory-bearer"),
		"secret://iam/ca":    directoryTestServerCA(t, server),
	}
	adapter, err := NewSecretBackedDirectoryAdapter(SecretBackedDirectoryAdapterConfig{Secrets: resolver})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Verify(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, SecretReference: "secret://iam/scim"})
	if !errors.Is(err, ErrDirectoryConfigurationInvalid) || requests != 0 {
		t.Fatalf("Verify() error=%v requests=%d", err, requests)
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
