package contract_test

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestDirectorySynchronizationOpenAPIContract(t *testing.T) {
	t.Parallel()
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}
	for _, operation := range []struct {
		method string
		path   string
	}{
		{method: "POST", path: "/api/v1/identity-sources/{source_id}/verify"},
		{method: "POST", path: "/api/v1/identity-sources/{source_id}/sync-preview"},
		{method: "POST", path: "/api/v1/identity-sources/{source_id}/sync"},
		{method: "GET", path: "/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}"},
		{method: "GET", path: "/api/v1/identity-sources/{source_id}/sync-conflicts"},
		{method: "POST", path: "/api/v1/identity-sources/{source_id}/sync-conflicts/{conflict_id}/resolve"},
	} {
		pathItem := document.Paths.Find(operation.path)
		if pathItem == nil || pathItem.GetOperation(operation.method) == nil {
			t.Fatalf("missing %s %s", operation.method, operation.path)
		}
		if action := pathItem.GetOperation(operation.method).Extensions["x-required-action"]; action != "identity.manage" {
			t.Fatalf("%s %s action = %#v", operation.method, operation.path, action)
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
