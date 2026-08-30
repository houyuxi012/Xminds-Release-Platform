package endpoint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryCABundleLoaderReadsOnlyNamedFilesWithinConfiguredRoot(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	wanted := []byte("private enterprise CA")
	if err := os.WriteFile(filepath.Join(directory, "distribution-ca.pem"), wanted, 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := NewDirectoryCABundleLoader(directory)
	if err != nil {
		t.Fatalf("NewDirectoryCABundleLoader() error = %v", err)
	}
	bundle, err := loader.Load(context.Background(), "distribution-ca.pem")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(bundle) != string(wanted) {
		t.Fatalf("bundle = %q", bundle)
	}
	for _, reference := range []string{"../outside.pem", "/etc/passwd", "nested/ca.pem", ""} {
		if _, err := loader.Load(context.Background(), reference); !errors.Is(err, ErrCABundleReferenceInvalid) {
			t.Fatalf("Load(%q) error = %v", reference, err)
		}
	}
}
