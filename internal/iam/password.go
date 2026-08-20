package iam

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var (
	ErrPasswordPolicyInvalid = errors.New("password policy configuration is invalid")
	ErrPasswordInvalid       = errors.New("password does not satisfy policy")
	ErrPasswordBreached      = errors.New("password appears in the breached-password corpus")
)

type BreachChecker interface {
	IsBreached(ctx context.Context, password string) (bool, error)
}

type PasswordPolicyConfig struct {
	MinimumLength   int
	MemoryKiB       uint32
	Iterations      uint32
	Parallelism     uint8
	SaltBytes       int
	DerivedKeyBytes uint32
}

type PasswordManager struct {
	policy   PasswordPolicyConfig
	breaches BreachChecker
}

func NewDummyPasswordDigest(ctx context.Context, passwords PasswordService) (PasswordDigest, error) {
	if passwords == nil {
		return PasswordDigest{}, ErrPasswordPolicyInvalid
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return PasswordDigest{}, fmt.Errorf("generate dummy authentication password: %w", err)
	}
	digest, err := passwords.Hash(ctx, "dummy-"+base64.RawURLEncoding.EncodeToString(secret))
	if err != nil {
		return PasswordDigest{}, fmt.Errorf("hash dummy authentication password: %w", err)
	}
	if _, _, _, _, err := parsePasswordDigest(digest); err != nil {
		return PasswordDigest{}, ErrPasswordPolicyInvalid
	}
	return digest, nil
}

func NewPasswordManager(policy PasswordPolicyConfig, breaches BreachChecker) (*PasswordManager, error) {
	if breaches == nil || !validPasswordPolicy(policy) {
		return nil, ErrPasswordPolicyInvalid
	}
	return &PasswordManager{policy: policy, breaches: breaches}, nil
}

func (manager *PasswordManager) Hash(ctx context.Context, password string) (PasswordDigest, error) {
	if manager == nil || manager.breaches == nil || !validPasswordPolicy(manager.policy) {
		return PasswordDigest{}, ErrPasswordPolicyInvalid
	}
	if err := validatePassword(password, manager.policy.MinimumLength); err != nil {
		return PasswordDigest{}, err
	}
	breached, err := manager.breaches.IsBreached(ctx, password)
	if err != nil {
		return PasswordDigest{}, fmt.Errorf("check breached password: %w", err)
	}
	if breached {
		return PasswordDigest{}, ErrPasswordBreached
	}
	salt := make([]byte, manager.policy.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return PasswordDigest{}, fmt.Errorf("generate password salt: %w", err)
	}
	derived := argon2.IDKey(
		[]byte(password), salt, manager.policy.Iterations, manager.policy.MemoryKiB,
		manager.policy.Parallelism, manager.policy.DerivedKeyBytes,
	)
	return PasswordDigest{
		Algorithm:  "argon2id",
		Parameters: fmt.Sprintf("m=%d,t=%d,p=%d,l=%d", manager.policy.MemoryKiB, manager.policy.Iterations, manager.policy.Parallelism, manager.policy.DerivedKeyBytes),
		Salt:       append([]byte(nil), salt...), DerivedKey: append([]byte(nil), derived...),
	}, nil
}

func (manager *PasswordManager) Verify(password string, digest PasswordDigest) error {
	if manager == nil {
		return ErrPasswordPolicyInvalid
	}
	memory, iterations, parallelism, length, err := parsePasswordDigest(digest)
	if err != nil {
		return ErrLocalCredentialInvalid
	}
	actual := argon2.IDKey([]byte(password), digest.Salt, iterations, memory, parallelism, length)
	if subtle.ConstantTimeCompare(actual, digest.DerivedKey) != 1 {
		return ErrLocalCredentialInvalid
	}
	return nil
}

func validPasswordPolicy(policy PasswordPolicyConfig) bool {
	return policy.MinimumLength >= 12 && policy.MinimumLength <= 128 &&
		policy.MemoryKiB >= 19*1024 && policy.MemoryKiB <= 256*1024 &&
		policy.Iterations >= 1 && policy.Iterations <= 10 &&
		policy.Parallelism >= 1 && policy.Parallelism <= 8 &&
		policy.SaltBytes >= 16 && policy.SaltBytes <= 64 &&
		policy.DerivedKeyBytes >= 16 && policy.DerivedKeyBytes <= 64
}

func validatePassword(password string, minimumLength int) error {
	if !utf8.ValidString(password) || strings.ContainsRune(password, '\x00') {
		return ErrPasswordInvalid
	}
	length := utf8.RuneCountInString(password)
	if length < minimumLength || length > 1024 {
		return ErrPasswordInvalid
	}
	return nil
}

func parsePasswordDigest(digest PasswordDigest) (uint32, uint32, uint8, uint32, error) {
	if digest.Algorithm != "argon2id" || len(digest.Salt) < 16 || len(digest.Salt) > 64 || len(digest.DerivedKey) < 16 || len(digest.DerivedKey) > 64 {
		return 0, 0, 0, 0, ErrLocalCredentialInvalid
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	var length uint32
	if _, err := fmt.Sscanf(digest.Parameters, "m=%d,t=%d,p=%d,l=%d", &memory, &iterations, &parallelism, &length); err != nil ||
		digest.Parameters != fmt.Sprintf("m=%d,t=%d,p=%d,l=%d", memory, iterations, parallelism, length) ||
		memory < 19*1024 || memory > 256*1024 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 8 ||
		length < 16 || length > 64 || int(length) != len(digest.DerivedKey) {
		return 0, 0, 0, 0, ErrLocalCredentialInvalid
	}
	return memory, iterations, parallelism, length, nil
}
