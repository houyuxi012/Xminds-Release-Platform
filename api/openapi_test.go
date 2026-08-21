package api_test

import (
	"context"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOpenAPIDefinesStrictLocalUserProvisioningAndReadContracts(t *testing.T) {
	t.Parallel()

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}

	operations := []struct {
		method, path, operationID string
		responses                 []string
	}{
		{method: "POST", path: "/api/v1/local-users", operationID: "createLocalUser", responses: []string{"201", "400", "403", "409", "500"}},
		{method: "GET", path: "/api/v1/users", operationID: "listUsers", responses: []string{"200", "400", "403", "500"}},
		{method: "GET", path: "/api/v1/users/{user_id}", operationID: "getUser", responses: []string{"200", "400", "403", "404", "500"}},
	}
	for _, testCase := range operations {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil {
			t.Fatalf("missing %s path", testCase.path)
		}
		operation := pathItem.GetOperation(testCase.method)
		if operation == nil {
			t.Fatalf("missing %s %s operation", testCase.method, testCase.path)
		}
		if operation.OperationID != testCase.operationID {
			t.Errorf("%s %s operationId = %q, want %q", testCase.method, testCase.path, operation.OperationID, testCase.operationID)
		}
		if operation.Extensions["x-required-action"] != "identity.manage" {
			t.Errorf("%s %s action = %#v", testCase.method, testCase.path, operation.Extensions["x-required-action"])
		}
		if !strings.Contains(operation.Summary, "用户") {
			t.Errorf("%s %s summary must be simplified Chinese user-facing text: %q", testCase.method, testCase.path, operation.Summary)
		}
		for _, status := range testCase.responses {
			if operation.Responses.Value(status) == nil {
				t.Errorf("%s %s response %s is missing", testCase.method, testCase.path, status)
			}
		}
		for _, status := range testCase.responses[1:] {
			assertProblemResponse(t, testCase.operationID, status, operation.Responses.Value(status))
		}
	}

	create := document.Paths.Find("/api/v1/local-users").Post
	if !strings.Contains(create.Description, "一次性") || !strings.Contains(create.Description, "后续无法查询") {
		t.Errorf("local user creation description must explain one-time secret visibility: %q", create.Description)
	}
	request := create.RequestBody.Value.Content["application/json"].Schema
	assertStrictRequiredSchema(t, "CreateLocalUserRequest", request, []string{"username", "display_name"})
	assertExactProperties(t, "CreateLocalUserRequest", request.Value.Properties, []string{"username", "display_name", "email"})
	assertStringBounds(t, "CreateLocalUserRequest.username", request.Value.Properties["username"], 3, 128, "^[a-z0-9][a-z0-9._-]{2,127}$", "")
	assertStringBounds(t, "CreateLocalUserRequest.display_name", request.Value.Properties["display_name"], 1, 256, "", "")
	assertStringBounds(t, "CreateLocalUserRequest.email", request.Value.Properties["email"], 0, 320, "", "email")
	if username := request.Value.Properties["username"]; username == nil || username.Value == nil || !strings.Contains(username.Value.Description, "首尾空白") || !strings.Contains(username.Value.Description, "小写") {
		t.Errorf("CreateLocalUserRequest.username must document canonical no-whitespace lowercase input")
	}
	if displayName := request.Value.Properties["display_name"]; displayName == nil || displayName.Value == nil || !strings.Contains(displayName.Value.Description, "首尾空白") {
		t.Errorf("CreateLocalUserRequest.display_name must document canonical no-whitespace input")
	}
	if email := request.Value.Properties["email"]; email == nil || email.Value == nil || !strings.Contains(email.Value.Description, "首尾空白") || !strings.Contains(email.Value.Description, "小写") {
		t.Errorf("CreateLocalUserRequest.email must document canonical no-whitespace lowercase input")
	}

	created := create.Responses.Value("201")
	location := created.Value.Headers["Location"]
	if location == nil || location.Value == nil || !strings.Contains(location.Value.Description, "/api/v1/users/{id}") {
		t.Errorf("local user creation response must document Location as /api/v1/users/{id}")
	}
	noStore := created.Value.Headers["Cache-Control"]
	if noStore == nil || noStore.Value == nil || noStore.Value.Schema == nil || noStore.Value.Schema.Value == nil || noStore.Value.Schema.Value.Const != "no-store" {
		t.Errorf("local user creation response must document Cache-Control: no-store")
	}
	if schema := created.Value.Content["application/json"].Schema; schema == nil || schema.Ref != "#/components/schemas/LocalUserProvisioning" {
		t.Errorf("local user creation response schema = %#v, want LocalUserProvisioning", schema)
	}

	user := document.Components.Schemas["User"]
	assertStrictRequiredSchema(t, "User", user, []string{"id", "username", "display_name", "kind", "status", "mfa_enrolled", "version", "created_at", "updated_at"})
	assertExactProperties(t, "User", user.Value.Properties, []string{"id", "identity_source_id", "external_subject", "username", "display_name", "email", "kind", "status", "mfa_enrolled", "credential_rotated_at", "version", "created_at", "updated_at", "disabled_at", "disabled_reason"})
	assertEnum(t, "User.kind", user.Value.Properties["kind"], []any{"external", "local", "emergency"})
	assertEnum(t, "User.status", user.Value.Properties["status"], []any{"pending", "active", "disabled", "locked"})
	if version := user.Value.Properties["version"]; version == nil || version.Value == nil || version.Value.Min == nil || *version.Value.Min != 1 {
		t.Errorf("User.version must have minimum 1")
	}

	page := document.Components.Schemas["UserPage"]
	assertStrictRequiredSchema(t, "UserPage", page, []string{"items"})
	assertExactProperties(t, "UserPage", page.Value.Properties, []string{"items", "next_cursor"})
	if items := page.Value.Properties["items"]; items == nil || items.Value == nil || items.Value.MaxItems == nil || *items.Value.MaxItems != 200 {
		t.Errorf("UserPage.items must have maxItems 200")
	}
	provisioning := document.Components.Schemas["LocalUserProvisioning"]
	assertStrictRequiredSchema(t, "LocalUserProvisioning", provisioning, []string{"user", "activation_token", "activation_expires_at"})
	assertExactProperties(t, "LocalUserProvisioning", provisioning.Value.Properties, []string{"user", "activation_token", "activation_expires_at"})
	if user := provisioning.Value.Properties["user"]; user == nil || user.Ref != "#/components/schemas/User" {
		t.Errorf("LocalUserProvisioning.user must use User")
	}
	assertStringBounds(t, "LocalUserProvisioning.activation_token", provisioning.Value.Properties["activation_token"], 32, 1024, "", "")
	activationToken := provisioning.Value.Properties["activation_token"].Value
	if !activationToken.ReadOnly || activationToken.WriteOnly {
		t.Errorf("LocalUserProvisioning.activation_token must be readOnly and not writeOnly")
	}
	if expiresAt := provisioning.Value.Properties["activation_expires_at"]; expiresAt == nil || expiresAt.Value == nil || expiresAt.Value.Format != "date-time" {
		t.Errorf("LocalUserProvisioning.activation_expires_at must be a date-time")
	}

	list := document.Paths.Find("/api/v1/users").Get
	assertParameters(t, "listUsers", list, []string{"limit", "cursor"})
	assertResponseSchema(t, "listUsers", list.Responses.Value("200"), "#/components/schemas/UserPage")
	detail := document.Paths.Find("/api/v1/users/{user_id}").Get
	assertParameters(t, "getUser", detail, []string{"user_id"})
	assertResponseSchema(t, "getUser", detail.Responses.Value("200"), "#/components/schemas/User")
	for _, schema := range []*openapi3.SchemaRef{user, page, document.Components.Schemas["ProblemDetails"]} {
		if schema != nil && schema.Value != nil {
			if _, exposed := schema.Value.Properties["activation_token"]; exposed {
				t.Errorf("%s must not expose activation_token", schema.Ref)
			}
		}
	}
}

func assertStrictRequiredSchema(t *testing.T, name string, schema *openapi3.SchemaRef, required []string) {
	t.Helper()
	if schema == nil || schema.Value == nil {
		t.Fatalf("%s schema is missing", name)
	}
	if schema.Value.AdditionalProperties.Has == nil || *schema.Value.AdditionalProperties.Has {
		t.Errorf("%s must set additionalProperties to false", name)
	}
	if !sameStringSet(schema.Value.Required, required) {
		t.Errorf("%s required = %#v, want %#v", name, schema.Value.Required, required)
	}
}

func assertExactProperties(t *testing.T, name string, properties openapi3.Schemas, expected []string) {
	t.Helper()
	if len(properties) != len(expected) {
		t.Errorf("%s has %d properties, want exactly %d", name, len(properties), len(expected))
	}
	for _, property := range expected {
		if _, found := properties[property]; !found {
			t.Errorf("%s.%s is missing", name, property)
		}
	}
}

func assertStringBounds(t *testing.T, name string, schema *openapi3.SchemaRef, minimum, maximum uint64, pattern, format string) {
	t.Helper()
	if schema == nil || schema.Value == nil {
		t.Errorf("%s schema is missing", name)
		return
	}
	if schema.Value.MinLength != minimum || schema.Value.MaxLength == nil || *schema.Value.MaxLength != maximum || schema.Value.Pattern != pattern || schema.Value.Format != format {
		t.Errorf("%s = min=%d max=%v pattern=%q format=%q", name, schema.Value.MinLength, schema.Value.MaxLength, schema.Value.Pattern, schema.Value.Format)
	}
}

func assertEnum(t *testing.T, name string, schema *openapi3.SchemaRef, expected []any) {
	t.Helper()
	if schema == nil || schema.Value == nil || !sameStringSet(stringsFromValues(schema.Value.Enum), stringsFromValues(expected)) {
		t.Errorf("%s enum = %#v, want %#v", name, schema.Value.Enum, expected)
	}
}

func assertParameters(t *testing.T, operationName string, operation *openapi3.Operation, expected []string) {
	t.Helper()
	if operation == nil {
		t.Fatalf("%s operation is missing", operationName)
	}
	actual := make([]string, 0, len(operation.Parameters))
	for _, parameter := range operation.Parameters {
		if parameter != nil && parameter.Value != nil {
			actual = append(actual, parameter.Value.Name)
		}
	}
	if !sameStringSet(actual, expected) {
		t.Errorf("%s parameters = %#v, want %#v", operationName, actual, expected)
	}
}

func assertResponseSchema(t *testing.T, operationName string, response *openapi3.ResponseRef, expectedRef string) {
	t.Helper()
	if response == nil || response.Value == nil || response.Value.Content["application/json"] == nil || response.Value.Content["application/json"].Schema == nil || response.Value.Content["application/json"].Schema.Ref != expectedRef {
		t.Errorf("%s success response must use %s", operationName, expectedRef)
	}
}

func assertProblemResponse(t *testing.T, operationName, status string, response *openapi3.ResponseRef) {
	t.Helper()
	if response == nil || response.Value == nil || response.Value.Content["application/problem+json"] == nil || response.Value.Content["application/problem+json"].Schema == nil || response.Value.Content["application/problem+json"].Schema.Ref != "#/components/schemas/ProblemDetails" {
		t.Errorf("%s response %s must use the RFC 9457 ProblemDetails contract", operationName, status)
	}
}

func sameStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	values := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		values[value] = struct{}{}
	}
	if len(values) != len(expected) {
		return false
	}
	for _, value := range expected {
		if _, found := values[value]; !found {
			return false
		}
	}
	return true
}

func stringsFromValues(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil
		}
		result = append(result, text)
	}
	return result
}

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
