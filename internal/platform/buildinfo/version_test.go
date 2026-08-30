package buildinfo

import "testing"

func TestCurrentHasStableProductIdentity(t *testing.T) {
	got := Current()
	if got.Product != "xminds-release-platform" {
		t.Fatalf("Product = %q", got.Product)
	}
	if got.Version == "" {
		t.Fatal("Version must not be empty")
	}
}
