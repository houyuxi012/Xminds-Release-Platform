package scm

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestCredentialRotationCreatesNewVersionAndRevokesOldInOneTransaction(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	connectionID := uuid.New()
	cipher, err := NewAESGCMCredentialCipher("primary", map[string][]byte{"primary": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryCredentialRepository{}
	service, err := NewCredentialService(repository, passthroughSCMTransactor{}, cipher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Rotate(context.Background(), connectionID, CredentialKindGitHubToken, []byte("provider-token-one"), "credential-one", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Rotate(context.Background(), connectionID, CredentialKindGitHubToken, []byte("provider-token-two"), "credential-two", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || second.Version != 2 || second.LastFour != "-two" || first.ID == second.ID {
		t.Fatalf("metadata = %+v / %+v", first, second)
	}
	if repository.records[0].RevokedAt == nil || !repository.records[0].RevokedAt.Equal(now) || repository.records[1].RevokedAt != nil || repository.bound != second.ID {
		t.Fatalf("records = %+v", repository.records)
	}
}

type memoryCredentialRepository struct {
	records []CredentialRecord
	bound   uuid.UUID
}

func (repository *memoryCredentialRepository) GetActiveCredential(_ context.Context, id uuid.UUID) (CredentialRecord, error) {
	for _, record := range repository.records {
		if record.ID == id && record.RevokedAt == nil {
			return record, nil
		}
	}
	return CredentialRecord{}, ErrCredentialUnavailable
}

func (repository *memoryCredentialRepository) FindActiveCredential(_ context.Context, _ pgx.Tx, connectionID uuid.UUID, kind CredentialKind) (CredentialRecord, error) {
	for _, record := range repository.records {
		if record.ConnectionID == connectionID && record.Kind == kind && record.RevokedAt == nil {
			return record, nil
		}
	}
	return CredentialRecord{}, ErrCredentialUnavailable
}

func (repository *memoryCredentialRepository) NextCredentialVersion(_ context.Context, _ pgx.Tx, connectionID uuid.UUID, kind CredentialKind) (int, error) {
	maximum := 0
	for _, record := range repository.records {
		if record.ConnectionID == connectionID && record.Kind == kind && record.Version > maximum {
			maximum = record.Version
		}
	}
	return maximum + 1, nil
}

func (repository *memoryCredentialRepository) CreateCredential(_ context.Context, _ pgx.Tx, record CredentialRecord) error {
	repository.records = append(repository.records, record)
	return nil
}

func (repository *memoryCredentialRepository) BindCredential(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ CredentialKind, credentialID uuid.UUID, _ time.Time) error {
	repository.bound = credentialID
	return nil
}

func (repository *memoryCredentialRepository) RevokeCredential(_ context.Context, _ pgx.Tx, id uuid.UUID, at time.Time) error {
	for index := range repository.records {
		if repository.records[index].ID == id && repository.records[index].RevokedAt == nil {
			repository.records[index].RevokedAt = &at
			return nil
		}
	}
	return ErrCredentialUnavailable
}
