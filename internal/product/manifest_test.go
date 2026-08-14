package product

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestParseManifestCanonicalDigestIsStable(t *testing.T) {
	t.Parallel()

	compact := mustReadFixture(t, "testdata/valid-ngep.json")
	reordered := []byte(`{
        "default_channels":[{"display_name":"Stable","name":"stable"},{"display_name":"Beta","name":"beta"}],
        "catalog_format":"xminds-tuf-v1",
        "compatibility_keys":["os","arch"],
        "version_scheme":"semver",
        "artifact_types":["container","desktop"],
        "display_name":"NGeP",
        "product_id":"ngep",
        "schema_version":"xminds-product-manifest/v1"
    }`)

	first, firstCanonical, firstDigest, err := ParseManifest(compact)
	if err != nil {
		t.Fatalf("ParseManifest(compact) error = %v", err)
	}
	second, secondCanonical, secondDigest, err := ParseManifest(reordered)
	if err != nil {
		t.Fatalf("ParseManifest(reordered) error = %v", err)
	}
	if first.ProductID != "ngep" || second.ProductID != first.ProductID {
		t.Fatalf("product IDs = %q and %q", first.ProductID, second.ProductID)
	}
	if string(firstCanonical) != string(secondCanonical) {
		t.Fatalf("canonical JSON differs:\n%s\n%s", firstCanonical, secondCanonical)
	}
	if firstDigest != secondDigest {
		t.Fatalf("digests = %q and %q", firstDigest, secondDigest)
	}
}

func TestParseManifestRejectsInvalidContract(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		manifest string
		want     error
	}{
		{
			name:     "uppercase product ID",
			manifest: validManifestReplacing(`"product_id":"ngep"`, `"product_id":"NGeP"`),
			want:     ErrProductIDInvalid,
		},
		{
			name:     "unsupported version scheme",
			manifest: validManifestReplacing(`"version_scheme":"semver"`, `"version_scheme":"calver"`),
			want:     ErrVersionSchemeUnsupported,
		},
		{
			name:     "duplicate artifact type",
			manifest: validManifestReplacing(`"artifact_types":["container","desktop"]`, `"artifact_types":["container","container"]`),
			want:     ErrArtifactTypeDuplicate,
		},
		{
			name:     "duplicate channel",
			manifest: validManifestReplacing(`"default_channels":[{"name":"stable","display_name":"Stable"}]`, `"default_channels":[{"name":"stable","display_name":"Stable"},{"name":"stable","display_name":"Stable 2"}]`),
			want:     ErrChannelDuplicate,
		},
		{
			name:     "unknown field",
			manifest: validManifestReplacing(`"display_name":"NGeP"`, `"display_name":"NGeP","unexpected":true`),
			want:     ErrManifestInvalid,
		},
		{
			name:     "duplicate JSON field",
			manifest: validManifestReplacing(`"product_id":"ngep"`, `"product_id":"ngep","product_id":"other"`),
			want:     ErrManifestDuplicateField,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := ParseManifest([]byte(testCase.manifest))
			if !errors.Is(err, testCase.want) {
				t.Fatalf("ParseManifest() error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestProductManifestJSONSchemaValidatesFixtures(t *testing.T) {
	t.Parallel()

	schemaPayload := mustReadFixture(t, "product-manifest-v1.schema.json")
	var schemaDocument any
	if err := json.Unmarshal(schemaPayload, &schemaDocument); err != nil {
		t.Fatalf("decode product manifest JSON Schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaLocation = "https://xminds.example/schemas/product-manifest-v1.schema.json"
	if err := compiler.AddResource(schemaLocation, schemaDocument); err != nil {
		t.Fatalf("add product manifest JSON Schema: %v", err)
	}
	schema, err := compiler.Compile(schemaLocation)
	if err != nil {
		t.Fatalf("compile product manifest JSON Schema: %v", err)
	}
	for _, fixture := range []string{"testdata/valid-ngep.json", "testdata/valid-second-product.json"} {
		var document any
		if err := json.Unmarshal(mustReadFixture(t, fixture), &document); err != nil {
			t.Fatalf("decode fixture %q: %v", fixture, err)
		}
		if err := schema.Validate(document); err != nil {
			t.Fatalf("validate fixture %q: %v", fixture, err)
		}
	}
}

func validManifestReplacing(oldValue string, newValue string) string {
	manifest := `{
        "schema_version":"xminds-product-manifest/v1",
        "product_id":"ngep",
        "display_name":"NGeP",
        "artifact_types":["container","desktop"],
        "version_scheme":"semver",
        "compatibility_keys":["os","arch"],
        "catalog_format":"xminds-tuf-v1",
        "default_channels":[{"name":"stable","display_name":"Stable"}]
    }`
	return strings.Replace(manifest, oldValue, newValue, 1)
}

func mustReadFixture(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	return payload
}
