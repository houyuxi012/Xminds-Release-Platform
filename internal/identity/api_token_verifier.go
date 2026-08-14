package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	apiTokenPrefix       = "xrp"
	argonMemoryKiB       = 64 * 1024
	argonIterations      = 3
	argonParallelism     = 2
	argonSaltBytes       = 16
	argonDerivedKeyBytes = 32
)

var (
	ErrAPITokenInvalid       = errors.New("API token is invalid")
	ErrAPITokenExpired       = errors.New("API token is expired")
	ErrAPITokenRevoked       = errors.New("API token is revoked")
	ErrAPITokenStoreRequired = errors.New("API token store is required")
)

type APITokenRecord struct {
	ID         uuid.UUID
	SecretHash string
	Subject    string
	Roles      []Role
	ProductIDs []string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

type APITokenStore interface {
	FindByID(ctx context.Context, id uuid.UUID) (APITokenRecord, error)
}

type APITokenVerifier struct {
	store APITokenStore
	now   func() time.Time
}

func NewAPITokenVerifier(store APITokenStore) *APITokenVerifier {
	return &APITokenVerifier{store: store, now: time.Now}
}

func HashAPITokenSecret(secret string) (string, error) {
	if err := validateAPITokenSecret(secret); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate API token salt: %w", err)
	}
	derived := argon2.IDKey([]byte(secret), salt, argonIterations, argonMemoryKiB, argonParallelism, argonDerivedKeyBytes)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemoryKiB,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	), nil
}

func (verifier *APITokenVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	if verifier == nil || verifier.store == nil {
		return Principal{}, ErrAPITokenStoreRequired
	}
	id, secret, err := parseAPIToken(rawToken)
	if err != nil {
		return Principal{}, err
	}
	record, err := verifier.store.FindByID(ctx, id)
	if err != nil {
		return Principal{}, fmt.Errorf("load API token: %w", ErrAPITokenInvalid)
	}
	if record.ID != id || strings.TrimSpace(record.Subject) == "" {
		return Principal{}, ErrAPITokenInvalid
	}
	matched, err := verifyAPITokenSecret(secret, record.SecretHash)
	if err != nil || !matched {
		return Principal{}, ErrAPITokenInvalid
	}
	if record.RevokedAt != nil {
		return Principal{}, ErrAPITokenRevoked
	}
	if record.ExpiresAt.IsZero() || !record.ExpiresAt.After(verifier.now()) {
		return Principal{}, ErrAPITokenExpired
	}
	principal := Principal{
		Subject:    strings.TrimSpace(record.Subject),
		Kind:       PrincipalKindWorkload,
		Roles:      append([]Role(nil), record.Roles...),
		ProductIDs: append([]string(nil), record.ProductIDs...),
		TokenID:    id.String(),
		Provider:   WorkloadProviderAPIToken,
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, ErrAPITokenInvalid
	}
	return principal, nil
}

func parseAPIToken(rawToken string) (uuid.UUID, string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || parts[0] != apiTokenPrefix {
		return uuid.Nil, "", ErrAPITokenInvalid
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, "", ErrAPITokenInvalid
	}
	if err := validateAPITokenSecret(parts[2]); err != nil {
		return uuid.Nil, "", err
	}
	return id, parts[2], nil
}

func validateAPITokenSecret(secret string) error {
	if len(secret) < 32 || len(secret) > 256 {
		return ErrAPITokenInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) < 24 || len(decoded) > 192 {
		return ErrAPITokenInvalid
	}
	return nil
}

func verifyAPITokenSecret(secret string, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrAPITokenInvalid
	}
	versionText, found := strings.CutPrefix(parts[2], "v=")
	if !found {
		return false, ErrAPITokenInvalid
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version != argon2.Version {
		return false, ErrAPITokenInvalid
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, ErrAPITokenInvalid
	}
	if parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, parallelism) {
		return false, ErrAPITokenInvalid
	}
	if memory < 19*1024 || memory > 256*1024 || iterations == 0 || iterations > 10 || parallelism == 0 || parallelism > 8 {
		return false, ErrAPITokenInvalid
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false, ErrAPITokenInvalid
	}
	wanted, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(wanted) < 16 || len(wanted) > 64 {
		return false, ErrAPITokenInvalid
	}
	actual := argon2.IDKey([]byte(secret), salt, iterations, memory, parallelism, uint32(len(wanted)))
	return subtle.ConstantTimeCompare(actual, wanted) == 1, nil
}
