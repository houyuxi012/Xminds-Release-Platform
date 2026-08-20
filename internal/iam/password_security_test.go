package iam

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileBreachCheckerRejectsDigestMatchesAndMalformedCorpus(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	password := "Known-Breached-Password!"
	digest := sha1.Sum([]byte(password))
	corpus := filepath.Join(directory, "breached.txt")
	if err := os.WriteFile(corpus, []byte(strings.ToUpper(hex.EncodeToString(digest[:]))+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	checker, err := NewFileBreachChecker(corpus)
	if err != nil {
		t.Fatalf("NewFileBreachChecker() error = %v", err)
	}
	breached, err := checker.IsBreached(context.Background(), password)
	if err != nil || !breached {
		t.Fatalf("IsBreached() = %v, %v", breached, err)
	}
	breached, err = checker.IsBreached(context.Background(), "A-Different-Safe-Password!")
	if err != nil || breached {
		t.Fatalf("IsBreached(safe) = %v, %v", breached, err)
	}

	malformed := filepath.Join(directory, "malformed.txt")
	if err := os.WriteFile(malformed, []byte("not-a-password-digest\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBreachChecker(malformed); !errors.Is(err, ErrBreachCorpusInvalid) {
		t.Fatalf("NewFileBreachChecker(malformed) error = %v", err)
	}
}

func TestFileBreachCheckerRejectsWritableOrLinkedCorpus(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "breached.txt")
	if err := os.WriteFile(path, []byte("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBreachChecker(path); !errors.Is(err, ErrBreachCorpusInvalid) {
		t.Fatalf("NewFileBreachChecker(writable) error = %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked.txt")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBreachChecker(link); !errors.Is(err, ErrBreachCorpusInvalid) {
		t.Fatalf("NewFileBreachChecker(symlink) error = %v", err)
	}
}

func TestDevelopmentBreachCheckerRejectsEmbeddedCommonPassword(t *testing.T) {
	t.Parallel()
	checker, err := NewDevelopmentBreachChecker()
	if err != nil {
		t.Fatal(err)
	}
	breached, err := checker.IsBreached(context.Background(), "password")
	if err != nil || !breached {
		t.Fatalf("IsBreached(password) = %v, %v", breached, err)
	}
}

func TestTOTPVerifierResolvesReferencedSecretAndRejectsWrongWindow(t *testing.T) {
	t.Parallel()

	now := time.Unix(59, 0).UTC()
	resolver := staticSecretResolver{value: []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")}
	verifier, err := NewTOTPVerifier(TOTPConfig{Digits: 8, Period: 30 * time.Second, Skew: 0}, &resolver, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewTOTPVerifier() error = %v", err)
	}
	assertion, err := verifier.Verify(context.Background(), "secret://iam/admin-totp", "94287082")
	if err != nil || assertion.Counter != 1 {
		t.Fatalf("Verify(valid) = %+v, %v", assertion, err)
	}
	if resolver.reference != "secret://iam/admin-totp" {
		t.Fatalf("resolved reference = %q", resolver.reference)
	}
	if _, err := verifier.Verify(context.Background(), "secret://iam/admin-totp", "07081804"); !errors.Is(err, ErrMFAProofInvalid) {
		t.Fatalf("Verify(future proof) error = %v", err)
	}
}

func TestDirectorySecretResolverConfinesReferencesToConfiguredRoot(t *testing.T) {
	t.Parallel()

	directory := resolvedTempDir(t)
	if err := os.WriteFile(filepath.Join(directory, "admin-totp"), []byte("JBSWY3DPEHPK3PXP\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	secret, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp")
	if err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Resolve(valid) = %q, %v", secret, err)
	}
	for _, reference := range []string{"secret://iam/../escape", "file:///etc/passwd", "secret://other/admin-totp"} {
		if _, err := resolver.Resolve(context.Background(), reference); !errors.Is(err, ErrSecretReferenceInvalid) {
			t.Fatalf("Resolve(%q) error = %v", reference, err)
		}
	}
}

func TestDirectorySecretResolverRejectsSymlinkRoot(t *testing.T) {
	t.Parallel()
	realRoot := resolvedTempDir(t)
	linkedRoot := filepath.Join(resolvedTempDir(t), "iam-secrets")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectorySecretResolver(linkedRoot); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("NewDirectorySecretResolver(symlink root) error = %v", err)
	}
}

func TestDirectorySecretResolverRejectsSymlinkAncestor(t *testing.T) {
	realParent := resolvedTempDir(t)
	realRoot := filepath.Join(realParent, "iam-secrets")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(resolvedTempDir(t), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectorySecretResolver(filepath.Join(linkedParent, "iam-secrets")); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("NewDirectorySecretResolver(symlink ancestor) error = %v", err)
	}
}

func TestDirectorySecretResolverRejectsGroupOrWorldWritableRoot(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"group writable": 0o770, "world writable": 0o702} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(resolvedTempDir(t), "iam-secrets")
			if err := os.Mkdir(root, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDirectorySecretResolver(root); !errors.Is(err, ErrSecretReferenceInvalid) {
				t.Fatalf("NewDirectorySecretResolver(%s root) error = %v", name, err)
			}
		})
	}
}

func TestDirectorySecretResolverRejectsRootPermissionChangeAfterConstruction(t *testing.T) {
	root := filepath.Join(resolvedTempDir(t), "iam-secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin-totp"), []byte("PINNED-SECRET"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp"); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("Resolve(group-writable pinned root) error = %v", err)
	}
}

func TestDirectorySecretResolverRejectsUntrustedOwnerWhenSupported(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing fixtures to an untrusted owner requires root")
	}
	t.Run("root", func(t *testing.T) {
		root := filepath.Join(resolvedTempDir(t), "iam-secrets")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(root, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDirectorySecretResolver(root); !errors.Is(err, ErrSecretReferenceInvalid) {
			t.Fatalf("NewDirectorySecretResolver(untrusted root owner) error = %v", err)
		}
	})
	t.Run("secret", func(t *testing.T) {
		root := filepath.Join(resolvedTempDir(t), "iam-secrets")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		secretPath := filepath.Join(root, "admin-totp")
		if err := os.WriteFile(secretPath, []byte("UNTRUSTED-SECRET"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(secretPath, 65534, -1); err != nil {
			t.Fatal(err)
		}
		resolver, err := NewDirectorySecretResolver(root)
		if err != nil {
			t.Fatal(err)
		}
		defer resolver.Close()
		if _, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp"); !errors.Is(err, ErrSecretReferenceInvalid) {
			t.Fatalf("Resolve(untrusted secret owner) error = %v", err)
		}
	})
}

func TestDirectorySecretResolverPinsOpenedRootAcrossPathReplacement(t *testing.T) {
	parent := resolvedTempDir(t)
	root := filepath.Join(parent, "iam-secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin-totp"), []byte("ORIGINAL-SECRET"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	pinned := filepath.Join(parent, "pinned-root")
	if err := os.Rename(root, pinned); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin-totp"), []byte("REPLACEMENT-SECRET"), 0o400); err != nil {
		t.Fatal(err)
	}
	secret, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp")
	if err != nil || string(secret) != "ORIGINAL-SECRET" {
		t.Fatalf("Resolve(after root replacement) = %q, %v", secret, err)
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

type staticSecretResolver struct {
	reference string
	value     []byte
}

func (resolver *staticSecretResolver) Resolve(_ context.Context, reference string) ([]byte, error) {
	resolver.reference = reference
	return append([]byte(nil), resolver.value...), nil
}
