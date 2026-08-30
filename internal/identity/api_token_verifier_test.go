package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type apiTokenStoreFunc func(context.Context, uuid.UUID) (APITokenRecord, error)

func (function apiTokenStoreFunc) FindByID(ctx context.Context, id uuid.UUID) (APITokenRecord, error) {
	return function(ctx, id)
}

func TestAPITokenVerifierUsesArgon2idHashAndReturnsWorkloadPrincipal(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	secret := strings.Repeat("a9", 24)
	hash, err := HashAPITokenSecret(secret)
	if err != nil {
		t.Fatalf("HashAPITokenSecret() error = %v", err)
	}
	if strings.Contains(hash, secret) || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("stored hash is invalid or exposes secret: %q", hash)
	}
	verifier := NewAPITokenVerifier(apiTokenStoreFunc(func(_ context.Context, requestedID uuid.UUID) (APITokenRecord, error) {
		if requestedID != id {
			return APITokenRecord{}, errors.New("unexpected token ID")
		}
		return APITokenRecord{
			ID:         id,
			SecretHash: hash,
			Subject:    "release-automation",
			Roles:      []Role{RolePublisher},
			ProductIDs: []string{"product-a"},
			ExpiresAt:  time.Now().Add(time.Hour),
		}, nil
	}))

	principal, err := verifier.Verify(context.Background(), "xrp."+id.String()+"."+secret)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Kind != PrincipalKindWorkload || principal.Provider != WorkloadProviderAPIToken || principal.TokenID != id.String() {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestAPITokenVerifierRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	secret := strings.Repeat("b7", 24)
	hash, err := HashAPITokenSecret(secret)
	if err != nil {
		t.Fatalf("HashAPITokenSecret() error = %v", err)
	}
	verifier := NewAPITokenVerifier(apiTokenStoreFunc(func(context.Context, uuid.UUID) (APITokenRecord, error) {
		return APITokenRecord{
			ID:         id,
			SecretHash: hash,
			Subject:    "expired-automation",
			ExpiresAt:  time.Now().Add(-time.Minute),
		}, nil
	}))

	_, err = verifier.Verify(context.Background(), "xrp."+id.String()+"."+secret)
	if !errors.Is(err, ErrAPITokenExpired) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrAPITokenExpired)
	}
}

func TestHashAPITokenSecretRejectsNonURLSafeSecret(t *testing.T) {
	t.Parallel()

	_, err := HashAPITokenSecret(strings.Repeat("!", 40))
	if !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("HashAPITokenSecret() error = %v, want %v", err, ErrAPITokenInvalid)
	}
}

func TestWorkloadIdentityVerifierNeverFallsBackAfterAPITokenFailure(t *testing.T) {
	t.Parallel()

	apiFailure := errors.New("API token rejected")
	verifier := NewWorkloadIdentityVerifier(
		verifierFunc(func(context.Context, string) (Principal, error) {
			return Principal{Subject: "must-not-be-used", Kind: PrincipalKindWorkload}, nil
		}),
		verifierFunc(func(context.Context, string) (Principal, error) {
			return Principal{}, apiFailure
		}),
	)

	_, err := verifier.Verify(context.Background(), "xrp.00000000-0000-0000-0000-000000000001.invalid")
	if !errors.Is(err, apiFailure) {
		t.Fatalf("Verify() error = %v, want %v", err, apiFailure)
	}
}
