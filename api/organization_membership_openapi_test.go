package api_test

import (
	"context"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// Mutation caught: documenting only the legacy organization list/create
// routes leaves generated clients unable to use the governance lifecycle.
func TestOpenAPIDefinesStrictOrganizationMembershipGovernanceContracts(t *testing.T) {
	t.Parallel()
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}
	operations := []struct {
		method, path, operationID string
		responses                 []string
	}{
		{method: "GET", path: "/api/v1/organizations/{organization_id}", operationID: "getOrganization", responses: []string{"200", "400", "403", "404", "500"}},
		{method: "GET", path: "/api/v1/organizations/{organization_id}/children", operationID: "listOrganizationChildren", responses: []string{"200", "400", "403", "404", "500"}},
		{method: "GET", path: "/api/v1/organizations/{organization_id}/memberships", operationID: "listOrganizationMemberships", responses: []string{"200", "400", "403", "404", "500"}},
		{method: "POST", path: "/api/v1/organizations/{organization_id}/memberships", operationID: "createOrganizationMembership", responses: []string{"201", "400", "403", "404", "409", "500"}},
		{method: "DELETE", path: "/api/v1/organizations/{organization_id}/memberships/{user_id}", operationID: "deleteOrganizationMembership", responses: []string{"204", "400", "403", "404", "409", "500"}},
	}
	for _, testCase := range operations {
		pathItem := document.Paths.Find(testCase.path)
		if pathItem == nil || pathItem.GetOperation(testCase.method) == nil {
			t.Fatalf("missing %s %s", testCase.method, testCase.path)
		}
		operation := pathItem.GetOperation(testCase.method)
		if operation.OperationID != testCase.operationID || operation.Extensions["x-required-action"] != "identity.manage" || !strings.Contains(operation.Summary, "组织") {
			t.Errorf("%s contract operationId=%q action=%#v summary=%q", testCase.path, operation.OperationID, operation.Extensions["x-required-action"], operation.Summary)
		}
		for _, status := range testCase.responses {
			if operation.Responses.Value(status) == nil {
				t.Errorf("%s response %s missing", testCase.operationID, status)
			}
		}
	}

	createRequest := document.Components.Schemas["CreateOrganizationMembershipRequest"]
	assertStrictRequiredSchema(t, "CreateOrganizationMembershipRequest", createRequest, []string{"organization_version", "user_id", "user_version", "reason", "reauthentication"})
	assertExactProperties(t, "CreateOrganizationMembershipRequest", createRequest.Value.Properties, []string{"organization_version", "user_id", "user_version", "reason", "reauthentication"})
	assertStringBounds(t, "CreateOrganizationMembershipRequest.reason", createRequest.Value.Properties["reason"], 8, 512, `^\S(?:[\s\S]{6,510}\S)?$`, "")

	deleteRequest := document.Components.Schemas["DeleteOrganizationMembershipRequest"]
	assertStrictRequiredSchema(t, "DeleteOrganizationMembershipRequest", deleteRequest, []string{"organization_version", "user_version", "membership_version", "reason", "reauthentication"})
	assertExactProperties(t, "DeleteOrganizationMembershipRequest", deleteRequest.Value.Properties, []string{"organization_version", "user_version", "membership_version", "reason", "reauthentication"})
	assertStringBounds(t, "DeleteOrganizationMembershipRequest.reason", deleteRequest.Value.Properties["reason"], 8, 512, `^\S(?:[\s\S]{6,510}\S)?$`, "")

	membership := document.Components.Schemas["OrganizationMembership"]
	assertStrictRequiredSchema(t, "OrganizationMembership", membership, []string{"organization_id", "user_id", "source_owned", "status", "version", "created_at", "updated_at"})
	assertExactProperties(t, "OrganizationMembership", membership.Value.Properties, []string{"organization_id", "user_id", "source_owned", "status", "version", "created_at", "updated_at"})
	assertEnum(t, "OrganizationMembership.status", membership.Value.Properties["status"], []any{"active", "removed"})

	page := document.Components.Schemas["OrganizationMembershipPage"]
	assertStrictRequiredSchema(t, "OrganizationMembershipPage", page, []string{"items"})
	assertExactProperties(t, "OrganizationMembershipPage", page.Value.Properties, []string{"items", "next_cursor"})
}
