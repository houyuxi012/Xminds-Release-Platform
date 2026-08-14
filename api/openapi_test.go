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
