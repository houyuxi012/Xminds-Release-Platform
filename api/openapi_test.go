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
