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

func TestOpenAPIDefinesDurableDirectorySynchronizationWithoutWorkerState(t *testing.T) {
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
		{path: "/api/v1/identity-sources/{source_id}/verify", method: "POST"},
		{path: "/api/v1/identity-sources/{source_id}/sync-preview", method: "POST"},
		{path: "/api/v1/identity-sources/{source_id}/sync", method: "POST"},
		{path: "/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}", method: "GET"},
		{path: "/api/v1/identity-sources/{source_id}/sync-conflicts", method: "GET"},
	} {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
		operation := pathItem.GetOperation(testCase.method)
		if operation.Extensions["x-required-action"] != "identity.manage" {
			t.Fatalf("%s %s action = %#v", testCase.method, testCase.path, operation.Extensions["x-required-action"])
		}
	}
	job := document.Components.Schemas["DirectorySyncJob"]
	if job == nil || job.Value == nil {
		t.Fatal("DirectorySyncJob schema is missing")
	}
	for _, forbidden := range []string{"secret_reference", "bearer_token", "ca_reference", "cursor", "phase", "run_marker"} {
		if _, found := job.Value.Properties[forbidden]; found {
			t.Fatalf("DirectorySyncJob exposes %s", forbidden)
		}
	}
}

func TestOpenAPIDefinesDirectoryConflictResolutionAndStatusBoundPagination(t *testing.T) {
	t.Parallel()
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	list := document.Paths.Find("/api/v1/identity-sources/{source_id}/sync-conflicts")
	if list == nil || list.Get == nil {
		t.Fatal("directory conflict list operation is missing")
	}
	statusFound := false
	for _, parameter := range list.Get.Parameters {
		if parameter.Value != nil && parameter.Value.Name == "status" {
			statusFound = true
			if parameter.Value.Schema == nil || parameter.Value.Schema.Value == nil || parameter.Value.Schema.Value.Default != "open" {
				t.Fatal("directory conflict status must default to open")
			}
		}
	}
	if !statusFound {
		t.Fatal("directory conflict status query is missing")
	}
	resolve := document.Paths.Find("/api/v1/identity-sources/{source_id}/sync-conflicts/{conflict_id}/resolve")
	if resolve == nil || resolve.Post == nil || resolve.Post.Extensions["x-required-action"] != "identity.manage" {
		t.Fatal("directory conflict resolution operation is missing or unprotected")
	}
	for _, status := range []string{"200", "400", "403", "404", "409", "500"} {
		if resolve.Post.Responses.Value(status) == nil {
			t.Fatalf("directory conflict resolution response %s is missing", status)
		}
	}
	request := document.Components.Schemas["ResolveDirectorySyncConflictRequest"]
	if request == nil || request.Value == nil || request.Value.AdditionalProperties.Has == nil || *request.Value.AdditionalProperties.Has {
		t.Fatal("strict directory conflict resolution request schema is missing")
	}
	for _, field := range []string{"version", "decision", "reason", "reauthentication"} {
		if _, found := request.Value.Properties[field]; !found {
			t.Fatalf("ResolveDirectorySyncConflictRequest.%s is missing", field)
		}
	}
	reauthentication := request.Value.Properties["reauthentication"]
	if reauthentication == nil || reauthentication.Value == nil || reauthentication.Value.AdditionalProperties.Has == nil || *reauthentication.Value.AdditionalProperties.Has {
		t.Fatal("strict nested reauthentication schema is missing explicit additionalProperties: false")
	}
	conflict := document.Components.Schemas["DirectorySyncConflict"]
	if conflict == nil || conflict.Value == nil {
		t.Fatal("DirectorySyncConflict schema is missing")
	}
	for _, field := range []string{"version", "resolution_decision", "resolution_reason", "resolved_by", "resolved_at"} {
		if _, found := conflict.Value.Properties[field]; !found {
			t.Fatalf("DirectorySyncConflict.%s is missing", field)
		}
	}
}
