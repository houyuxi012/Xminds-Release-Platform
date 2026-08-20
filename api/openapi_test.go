package api_test

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOpenAPIContractIsValid(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	if document.OpenAPI != "3.1.0" {
		t.Fatalf("OpenAPI version = %q, want 3.1.0", document.OpenAPI)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}
}

func TestOpenAPIDefinesAuditorOnlyQueryAndExportOperations(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
	}{
		{path: "/api/v1/audit-events", method: "GET"},
		{path: "/api/v1/audit-exports", method: "POST"},
		{path: "/api/v1/audit-exports/{export_id}", method: "GET"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
	}
}

func TestOpenAPIDefinesProductRegistrationAndScopedReadOperations(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
	}{
		{path: "/api/v1/products", method: "POST"},
		{path: "/api/v1/products", method: "GET"},
		{path: "/api/v1/products/{product_id}", method: "GET"},
		{path: "/api/v1/products/{product_id}/deactivate", method: "POST"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
	}
}

func TestOpenAPIDefinesResumableArtifactOperations(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
	}{
		{path: "/api/v1/products/{product_id}/artifact-uploads", method: "POST"},
		{path: "/api/v1/products/{product_id}/artifact-uploads/{upload_id}/parts/{part_number}", method: "PUT"},
		{path: "/api/v1/products/{product_id}/artifact-uploads/{upload_id}/complete", method: "POST"},
		{path: "/api/v1/products/{product_id}/artifacts/{artifact_id}", method: "GET"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
	}
}

func TestOpenAPIDefinesReleaseApprovalAndPublicationOperations(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
	}{
		{path: "/api/v1/products/{product_id}/releases", method: "POST"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}", method: "GET"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}/submit", method: "POST"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}/approve", method: "POST"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}/reject", method: "POST"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}/publish", method: "POST"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}/retry", method: "POST"},
		{path: "/api/v1/products/{product_id}/releases/{release_id}/revoke", method: "POST"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
		operation := pathItem.GetOperation(testCase.method)
		if operation.Security == nil || operation.Extensions["x-required-action"] == nil {
			t.Errorf("%s %s is missing security or x-required-action", testCase.method, testCase.path)
		}
	}
}

func TestOpenAPIDefinesPrivateSCMManagementAndSignedWebhookOperations(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
	}{
		{path: "/api/v1/scm/connections", method: "POST"},
		{path: "/api/v1/scm/connections/{connection_id}/verify", method: "POST"},
		{path: "/api/v1/scm/connections/{connection_id}/credentials", method: "POST"},
		{path: "/api/v1/scm/webhooks/{connection_id}", method: "POST"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
	}
	webhook := document.Paths.Find("/api/v1/scm/webhooks/{connection_id}").Post
	if webhook.Security == nil || len(*webhook.Security) != 0 {
		t.Fatal("SCM webhook must explicitly disable Bearer security and rely on provider signature verification")
	}
}

func TestOpenAPIDefinesEndpointManagementAndUnauthenticatedDistributionOperations(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
		public bool
	}{
		{path: "/api/v1/endpoints", method: "POST"},
		{path: "/api/v1/endpoints/{endpoint_id}", method: "GET"},
		{path: "/api/v1/endpoints/{endpoint_id}/activate", method: "POST"},
		{path: "/metadata/{role}.json", method: "GET", public: true},
		{path: "/v1/products/{product}/channels/{channel}/metadata/{role}.json", method: "GET", public: true},
		{path: "/v1/products/{product}/artifacts/{sha256}", method: "GET", public: true},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
		operation := pathItem.GetOperation(testCase.method)
		if testCase.public {
			if operation.Security == nil || len(*operation.Security) != 0 {
				t.Errorf("%s %s must explicitly disable Bearer security", testCase.method, testCase.path)
			}
		} else if operation.Extensions["x-required-action"] != "integration.manage" {
			t.Errorf("%s %s action = %#v", testCase.method, testCase.path, operation.Extensions["x-required-action"])
		}
	}
}

func TestOpenAPIDefinesGovernedHighRiskIdentityWritesAndReauthentication(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, testCase := range []struct {
		path   string
		method string
	}{
		{path: "/api/v1/organizations", method: "GET"},
		{path: "/api/v1/organizations", method: "POST"},
		{path: "/api/v1/role-bindings", method: "GET"},
		{path: "/api/v1/role-bindings", method: "POST"},
		{path: "/api/v1/role-bindings/{binding_id}", method: "DELETE"},
		{path: "/api/v1/users/{user_id}/disable", method: "POST"},
		{path: "/api/v1/users/{user_id}/enable", method: "POST"},
		{path: "/api/v1/users/{user_id}/revoke-sessions", method: "POST"},
		{path: "/api/v1/identity-sources", method: "GET"},
		{path: "/api/v1/identity-sources", method: "POST"},
		{path: "/api/v1/identity-sources/{source_id}", method: "PATCH"},
		{path: "/api/v1/identity-sources/{source_id}/enable", method: "POST"},
		{path: "/api/v1/identity-sources/{source_id}/disable", method: "POST"},
		{path: "/api/v1/auth/reauth-challenges", method: "POST"},
		{path: "/api/v1/auth/reauth-challenges/{challenge_id}/complete", method: "POST"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
	}
	for _, schemaName := range []string{"HighRiskProof", "ReauthenticationChallenge", "ReauthenticationEvidence", "CreateRoleBindingRequest", "IAMVersionedHighRiskRequest", "IAMReasonedHighRiskRequest"} {
		if schema := document.Components.Schemas[schemaName]; schema == nil || schema.Value == nil {
			t.Fatalf("%s schema is missing", schemaName)
		}
	}
	challenge := document.Components.Schemas["ReauthenticationChallenge"].Value
	if _, leaked := challenge.Properties["evidence"]; leaked {
		t.Fatal("challenge creation response must not expose evidence")
	}
	proof := document.Components.Schemas["HighRiskProof"].Value
	for _, required := range []string{"challenge_id", "evidence", "confirmed"} {
		if _, found := proof.Properties[required]; !found {
			t.Fatalf("HighRiskProof.%s is missing", required)
		}
	}
	identitySource := document.Components.Schemas["IdentitySource"].Value
	if _, leaked := identitySource.Properties["secret_reference"]; leaked {
		t.Fatal("identity source read schema must not expose secret_reference")
	}
}

func TestOpenAPIDefinesPublicLocalAuthenticationWithoutSensitiveResponseFields(t *testing.T) {
	t.Parallel()
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	for _, path := range []string{
		"/api/v1/auth/local/activate",
		"/api/v1/auth/local/login",
		"/api/v1/auth/emergency/login",
	} {
		item := document.Paths.Find(path)
		if item == nil || item.Post == nil {
			t.Fatalf("missing POST %s", path)
		}
		if item.Post.Security == nil || len(*item.Post.Security) != 0 {
			t.Fatalf("POST %s must explicitly disable Bearer security", path)
		}
		if path != "/api/v1/auth/local/activate" {
			if response := item.Post.Responses.Value("400"); response == nil {
				t.Fatalf("POST %s must document malformed JSON as 400", path)
			}
		}
	}
	login := document.Components.Schemas["LocalLoginResponse"]
	if login == nil || login.Value == nil {
		t.Fatal("LocalLoginResponse schema is missing")
	}
	for _, required := range []string{"access_token", "token_type", "expires_at", "subject"} {
		if _, found := login.Value.Properties[required]; !found {
			t.Fatalf("LocalLoginResponse.%s is missing", required)
		}
	}
	for _, forbidden := range []string{"password", "activation_digest", "mfa_secret", "token_digest"} {
		if _, found := login.Value.Properties[forbidden]; found {
			t.Fatalf("LocalLoginResponse exposes %s", forbidden)
		}
	}
}
