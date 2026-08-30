package scm

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CredentialKind string

const (
	CredentialKindWebhookSecret       CredentialKind = "webhook_secret"
	CredentialKindWebhookSigningToken CredentialKind = "webhook_signing_token"
	CredentialKindGitHubToken         CredentialKind = "github_token"
	CredentialKindGitHubAppToken      CredentialKind = "github_app_token"
	CredentialKindGitLabAccessToken   CredentialKind = "gitlab_access_token"
)

func (kind CredentialKind) valid() bool {
	switch kind {
	case CredentialKindWebhookSecret, CredentialKindWebhookSigningToken, CredentialKindGitHubToken, CredentialKindGitHubAppToken, CredentialKindGitLabAccessToken:
		return true
	default:
		return false
	}
}

type SecretCredential struct {
	ID         uuid.UUID
	Kind       CredentialKind
	Secret     []byte
	Identifier string
	ExpiresAt  *time.Time
}

type CredentialUser interface {
	UseCredential(ctx context.Context, id uuid.UUID, use func(SecretCredential) error) error
}

type CredentialRecord struct {
	ID           uuid.UUID
	ConnectionID uuid.UUID
	Version      int
	Kind         CredentialKind
	Encrypted    EncryptedSecret
	LastFour     string
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type CredentialMetadata struct {
	ID        uuid.UUID      `json:"id"`
	Kind      CredentialKind `json:"kind"`
	Version   int            `json:"version"`
	LastFour  string         `json:"last_four,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	RevokedAt *time.Time     `json:"revoked_at,omitempty"`
}

func (record CredentialRecord) Metadata() CredentialMetadata {
	return CredentialMetadata{
		ID: record.ID, Kind: record.Kind, Version: record.Version, LastFour: record.LastFour,
		ExpiresAt: record.ExpiresAt, CreatedAt: record.CreatedAt, RevokedAt: record.RevokedAt,
	}
}

type CredentialRepository interface {
	GetActiveCredential(ctx context.Context, id uuid.UUID) (CredentialRecord, error)
	FindActiveCredential(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, kind CredentialKind) (CredentialRecord, error)
	NextCredentialVersion(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, kind CredentialKind) (int, error)
	CreateCredential(ctx context.Context, tx pgx.Tx, record CredentialRecord) error
	BindCredential(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, kind CredentialKind, credentialID uuid.UUID, at time.Time) error
	RevokeCredential(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time) error
}

type CredentialService struct {
	repository CredentialRepository
	transactor SCMTransactor
	cipher     CredentialCipher
	clock      func() time.Time
}

func NewCredentialService(repository CredentialRepository, transactor SCMTransactor, cipher CredentialCipher, clock func() time.Time) (*CredentialService, error) {
	if repository == nil || transactor == nil || cipher == nil || clock == nil {
		return nil, ErrCredentialUnavailable
	}
	return &CredentialService{repository: repository, transactor: transactor, cipher: cipher, clock: clock}, nil
}

func (service *CredentialService) Rotate(ctx context.Context, connectionID uuid.UUID, kind CredentialKind, secret []byte, identifier string, expiresAt *time.Time) (CredentialMetadata, error) {
	if service == nil || connectionID == uuid.Nil || !kind.valid() || len(secret) < 8 || len(secret) > 64*1024 {
		return CredentialMetadata{}, ErrCredentialUnavailable
	}
	var result CredentialRecord
	err := service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		version, err := service.repository.NextCredentialVersion(ctx, tx, connectionID, kind)
		if err != nil {
			return err
		}
		now := service.clock().UTC().Truncate(time.Microsecond)
		previous, findErr := service.repository.FindActiveCredential(ctx, tx, connectionID, kind)
		if findErr != nil && !errors.Is(findErr, ErrCredentialUnavailable) {
			return findErr
		}
		candidate, err := NewCredentialRecord(connectionID, version, kind, secret, identifier, expiresAt, now, service.cipher)
		if err != nil {
			return err
		}
		if findErr == nil {
			if err := service.repository.RevokeCredential(ctx, tx, previous.ID, now); err != nil {
				return err
			}
		}
		if err := service.repository.CreateCredential(ctx, tx, candidate); err != nil {
			return err
		}
		if err := service.repository.BindCredential(ctx, tx, connectionID, kind, candidate.ID, now); err != nil {
			return err
		}
		result = candidate
		return nil
	})
	if err != nil {
		return CredentialMetadata{}, err
	}
	return result.Metadata(), nil
}

type EncryptedCredentialStore struct {
	repository CredentialRepository
	cipher     CredentialCipher
	clock      func() time.Time
}

func NewEncryptedCredentialStore(repository CredentialRepository, cipher CredentialCipher, clock func() time.Time) (*EncryptedCredentialStore, error) {
	if repository == nil || cipher == nil || clock == nil {
		return nil, ErrCredentialUnavailable
	}
	return &EncryptedCredentialStore{repository: repository, cipher: cipher, clock: clock}, nil
}

func (store *EncryptedCredentialStore) UseCredential(ctx context.Context, id uuid.UUID, use func(SecretCredential) error) error {
	if store == nil || id == uuid.Nil || use == nil {
		return ErrCredentialUnavailable
	}
	record, err := store.repository.GetActiveCredential(ctx, id)
	if err != nil || record.RevokedAt != nil || (record.ExpiresAt != nil && !record.ExpiresAt.After(store.clock().UTC())) {
		return ErrCredentialUnavailable
	}
	plaintext, err := store.cipher.Decrypt(record.ID, record.Version, record.Kind, record.Encrypted)
	if err != nil {
		return ErrCredentialUnavailable
	}
	defer wipeBytes(plaintext)
	return use(SecretCredential{
		ID: record.ID, Kind: record.Kind, Secret: plaintext, Identifier: record.LastFour, ExpiresAt: record.ExpiresAt,
	})
}

func NewCredentialRecord(connectionID uuid.UUID, version int, kind CredentialKind, secret []byte, identifier string, expiresAt *time.Time, at time.Time, cipher CredentialCipher) (CredentialRecord, error) {
	if connectionID == uuid.Nil || version <= 0 || !kind.valid() || cipher == nil || at.IsZero() {
		return CredentialRecord{}, ErrCredentialUnavailable
	}
	if expiresAt != nil && !expiresAt.After(at) {
		return CredentialRecord{}, ErrCredentialUnavailable
	}
	id, err := uuid.NewV7()
	if err != nil {
		return CredentialRecord{}, errors.Join(ErrCredentialUnavailable, err)
	}
	encrypted, err := cipher.Encrypt(id, version, kind, secret)
	if err != nil {
		return CredentialRecord{}, err
	}
	identifier = strings.TrimSpace(identifier)
	if len(identifier) > 4 {
		identifier = identifier[len(identifier)-4:]
	}
	at = at.UTC().Truncate(time.Microsecond)
	return CredentialRecord{
		ID: id, ConnectionID: connectionID, Version: version, Kind: kind, Encrypted: encrypted,
		LastFour: identifier, ExpiresAt: expiresAt, CreatedAt: at, UpdatedAt: at,
	}, nil
}
