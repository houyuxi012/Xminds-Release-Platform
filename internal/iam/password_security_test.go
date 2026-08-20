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

	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "admin-totp"), []byte("JBSWY3DPEHPK3PXP\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(directory)
	if err != nil {
		t.Fatal(err)
	}
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

type staticSecretResolver struct {
	reference string
	value     []byte
}

func (resolver *staticSecretResolver) Resolve(_ context.Context, reference string) ([]byte, error) {
	resolver.reference = reference
	return append([]byte(nil), resolver.value...), nil
}
