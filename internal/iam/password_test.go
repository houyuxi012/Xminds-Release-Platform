package iam

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPasswordManagerHashesAndVerifiesArgon2idWithoutPlaintext(t *testing.T) {
	t.Parallel()

	manager, err := NewPasswordManager(PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32,
	}, staticBreachChecker(false))
	if err != nil {
		t.Fatalf("NewPasswordManager() error = %v", err)
	}
	password := "correct horse battery staple"
	digest, err := manager.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if digest.Algorithm != "argon2id" || len(digest.Salt) != 16 || len(digest.DerivedKey) != 32 {
		t.Fatalf("digest = %+v", digest)
	}
	if strings.Contains(string(digest.Salt), password) || strings.Contains(string(digest.DerivedKey), password) || strings.Contains(digest.Parameters, password) {
		t.Fatal("password plaintext leaked into digest metadata")
	}
	if err := manager.Verify(password, digest); err != nil {
		t.Fatalf("Verify(correct) error = %v", err)
	}
	if err := manager.Verify("wrong password value", digest); !errors.Is(err, ErrLocalCredentialInvalid) {
		t.Fatalf("Verify(wrong) error = %v", err)
	}
}

func TestPasswordManagerRejectsBreachedPasswordAndUnsafeParameters(t *testing.T) {
	t.Parallel()

	valid := PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32,
	}
	manager, err := NewPasswordManager(valid, staticBreachChecker(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Hash(context.Background(), "breached password value"); !errors.Is(err, ErrPasswordBreached) {
		t.Fatalf("Hash() error = %v", err)
	}
	for name, invalid := range map[string]PasswordPolicyConfig{
		"short minimum": {MinimumLength: 8, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32},
		"low memory":    {MinimumLength: 16, MemoryKiB: 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32},
		"high memory":   {MinimumLength: 16, MemoryKiB: 512 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32},
		"iterations":    {MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 0, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32},
		"salt":          {MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 8, DerivedKeyBytes: 32},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPasswordManager(invalid, staticBreachChecker(false)); !errors.Is(err, ErrPasswordPolicyInvalid) {
				t.Fatalf("NewPasswordManager() error = %v", err)
			}
		})
	}
}

type staticBreachChecker bool

func (checker staticBreachChecker) IsBreached(context.Context, string) (bool, error) {
	return bool(checker), nil
}
