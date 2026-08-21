package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestMFAServiceBeginsActivationEnrollmentWithServerOwnedSecretAndCappedExpiry(t *testing.T) {
	now := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)
	token := "activation-token-that-must-not-leak"
	digest := sha256.Sum256([]byte(token))
	userID := uuid.New()
	repository := &mfaEnrollmentStarterRepositoryFake{
		user:       UserPrincipal{ID: userID, Username: "operator+qa@example.com", Kind: UserKindLocal, Status: UserStatusPending, Version: 4},
		credential: LocalCredential{UserID: userID, ActivationDigest: hex.EncodeToString(digest[:]), ActivationExpiresAt: now.Add(6 * time.Minute)},
	}
	secrets := &mfaSecretStoreFake{values: map[string][]byte{}}
	auditor := &lockedAuditRecorder{}
	service := newMFAServiceHarness(t, repository, secrets, auditor, now)

	result, err := service.BeginActivationEnrollment(context.Background(), token, RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.44"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID == uuid.Nil || result.ID.Version() != 7 || len(result.Secret) != 32 || result.ExpiresAt != repository.credential.ActivationExpiresAt {
		t.Fatalf("enrollment result=%+v", result)
	}
	if !strings.HasPrefix(result.OTPAuthURI, "otpauth://totp/Xminds%20Release%20Platform:operator%2Bqa%40example.com?") ||
		!strings.Contains(result.OTPAuthURI, "secret="+result.Secret) || !strings.Contains(result.OTPAuthURI, "issuer=Xminds+Release+Platform") {
		t.Fatalf("otpauth URI=%q", result.OTPAuthURI)
	}
	if repository.inserted == nil || repository.inserted.UserID != userID || repository.inserted.SecretReference != "secret://iam-mfa/mfa-"+result.ID.String()+".totp" || repository.inserted.ExpiresAt != result.ExpiresAt {
		t.Fatalf("persisted enrollment=%+v", repository.inserted)
	}
	if string(secrets.values[repository.inserted.SecretReference]) != result.Secret {
		t.Fatal("Secret Store does not contain the one-time response seed")
	}
	for _, command := range auditor.commands {
		serialized := command.Action + command.ResourceID
		if strings.Contains(serialized, token) || strings.Contains(serialized, result.Secret) || strings.Contains(serialized, repository.inserted.SecretReference) {
			t.Fatalf("audit leaked MFA enrollment secret: %+v", command)
		}
	}
}

func TestMFAServiceCompensatesSecretWhenDatabaseAuditFails(t *testing.T) {
	now := time.Date(2026, 8, 21, 17, 30, 0, 0, time.UTC)
	token := "activation-audit-rollback-token-with-entropy"
	digest := sha256.Sum256([]byte(token))
	userID := uuid.New()
	repository := &mfaEnrollmentStarterRepositoryFake{
		user:       UserPrincipal{ID: userID, Username: "audit.rollback", Kind: UserKindLocal, Status: UserStatusPending, Version: 1},
		credential: LocalCredential{UserID: userID, ActivationDigest: hex.EncodeToString(digest[:]), ActivationExpiresAt: now.Add(time.Hour)},
	}
	secrets := &mfaSecretStoreFake{values: map[string][]byte{}}
	auditor := &lockedAuditRecorder{err: errors.New("audit unavailable")}
	service := newMFAServiceHarness(t, repository, secrets, auditor, now)

	if _, err := service.BeginActivationEnrollment(context.Background(), token, RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.45"}); err == nil {
		t.Fatal("BeginActivationEnrollment succeeded despite audit failure")
	}
	if repository.inserted != nil || len(secrets.values) != 0 || secrets.deleteCalls != 1 {
		t.Fatalf("rollback inserted=%+v secrets=%d deletes=%d", repository.inserted, len(secrets.values), secrets.deleteCalls)
	}
}

func newMFAServiceHarness(t *testing.T, repository *mfaEnrollmentStarterRepositoryFake, secrets *mfaSecretStoreFake, auditor AuditAppender, now time.Time) *MFAService {
	t.Helper()
	service, err := NewMFAService(MFAServiceConfig{
		Repository: repository, Auditor: auditor, Secrets: secrets, Policy: DefaultLocalAuthPolicy(),
		EnrollmentTTL: 10 * time.Minute, Issuer: "Xminds Release Platform", Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type mfaEnrollmentStarterRepositoryFake struct {
	user       UserPrincipal
	credential LocalCredential
	pending    *MFAEnrollment
	inserted   *MFAEnrollment
	gc         []string
}

func (repository *mfaEnrollmentStarterRepositoryFake) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	pending, inserted := repository.pending, repository.inserted
	gc := append([]string(nil), repository.gc...)
	err := function(nil)
	if err != nil {
		repository.pending, repository.inserted, repository.gc = pending, inserted, gc
	}
	return err
}

func (repository *mfaEnrollmentStarterRepositoryFake) FindActivation(_ context.Context, _ pgx.Tx, digest string) (UserPrincipal, LocalCredential, []PasswordDigest, bool, error) {
	if digest != repository.credential.ActivationDigest {
		return UserPrincipal{}, LocalCredential{}, nil, false, ErrLocalAuthenticationFailed
	}
	return repository.user, repository.credential, nil, false, nil
}

func (*mfaEnrollmentStarterRepositoryFake) CleanupExpiredRateLimits(context.Context, pgx.Tx, time.Time, int) (int64, error) {
	return 0, nil
}

func (*mfaEnrollmentStarterRepositoryFake) ConsumeRateLimit(context.Context, pgx.Tx, RateLimitScope, string, time.Time, int, time.Time) (bool, error) {
	return true, nil
}

func (repository *mfaEnrollmentStarterRepositoryFake) GetPendingMFAEnrollmentForUpdate(context.Context, pgx.Tx, uuid.UUID) (MFAEnrollment, error) {
	if repository.pending == nil {
		return MFAEnrollment{}, ErrMFAEnrollmentNotFound
	}
	return *repository.pending, nil
}

func (repository *mfaEnrollmentStarterRepositoryFake) ExpireMFAEnrollment(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ int64, _ time.Time) error {
	if repository.pending != nil {
		repository.gc = append(repository.gc, repository.pending.SecretReference)
		repository.pending = nil
	}
	return nil
}

func (repository *mfaEnrollmentStarterRepositoryFake) InsertMFAEnrollment(_ context.Context, _ pgx.Tx, enrollment MFAEnrollment) error {
	copy := enrollment
	repository.inserted = &copy
	repository.pending = &copy
	return nil
}

type mfaSecretStoreFake struct {
	values      map[string][]byte
	deleteCalls int
}

func (store *mfaSecretStoreFake) Create(_ context.Context, enrollmentID uuid.UUID, secret string) (string, error) {
	reference := "secret://iam-mfa/mfa-" + enrollmentID.String() + ".totp"
	store.values[reference] = []byte(secret)
	return reference, nil
}

func (store *mfaSecretStoreFake) Resolve(_ context.Context, reference string) ([]byte, error) {
	value, exists := store.values[reference]
	if !exists {
		return nil, ErrSecretReferenceInvalid
	}
	return append([]byte(nil), value...), nil
}

func (store *mfaSecretStoreFake) Delete(_ context.Context, reference string) error {
	store.deleteCalls++
	delete(store.values, reference)
	return nil
}

func (*mfaSecretStoreFake) ListOrphanCandidates(context.Context, time.Time, int) ([]string, error) {
	return nil, nil
}
