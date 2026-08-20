package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
)

func TestSessionVerifierHashesOpaqueTokenAndAtomicallyRefreshesIdleExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	token := "xms_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	digest := sha256.Sum256([]byte(token))
	repository := &memorySessionRepository{
		session: Session{
			ID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49101"), TokenDigest: hex.EncodeToString(digest[:]),
			SubjectID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49102"), AuthenticationMethod: AuthenticationMethodLocal,
			MFALevel: 1, AuthenticatedAt: now.Add(-time.Hour), LastUsedAt: now.Add(-time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Minute), Version: 3,
		},
		user:  UserPrincipal{ID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49102"), Username: "release.operator", Kind: UserKindLocal, Status: UserStatusActive},
		state: LoginState{Mode: LoginModeLocal},
	}
	verifier, err := NewSessionVerifier(repository, DefaultLocalAuthPolicy(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.Subject != "release.operator" || principal.Kind != identity.PrincipalKindLocal || principal.TokenID != repository.session.ID.String() || principal.AuthenticationAssurance != 1 {
		t.Fatalf("principal = %+v", principal)
	}
	if repository.loadedDigest != hex.EncodeToString(digest[:]) || !repository.session.LastUsedAt.Equal(now) || !repository.session.IdleExpiresAt.Equal(now.Add(30*time.Minute)) || repository.session.Version != 4 {
		t.Fatalf("session after use = %+v, loaded digest = %q", repository.session, repository.loadedDigest)
	}
}

func TestSessionVerifierRejectsRevokedExpiredDisabledAndModeDisallowedSessions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	baseSession := Session{
		ID: uuid.New(), SubjectID: uuid.New(), AuthenticationMethod: AuthenticationMethodLocal,
		AuthenticatedAt: now.Add(-time.Hour), LastUsedAt: now.Add(-time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Minute), Version: 1,
	}
	for name, mutate := range map[string]func(*Session, *UserPrincipal, *LoginState){
		"revoked":          func(session *Session, _ *UserPrincipal, _ *LoginState) { session.RevokedAt = now.Add(-time.Minute) },
		"absolute expired": func(session *Session, _ *UserPrincipal, _ *LoginState) { session.AbsoluteExpiresAt = now },
		"idle expired":     func(session *Session, _ *UserPrincipal, _ *LoginState) { session.IdleExpiresAt = now },
		"disabled":         func(_ *Session, user *UserPrincipal, _ *LoginState) { user.Status = UserStatusDisabled },
		"SSO mode":         func(_ *Session, _ *UserPrincipal, state *LoginState) { state.Mode = LoginModeSSO },
	} {
		t.Run(name, func(t *testing.T) {
			session := baseSession
			user := UserPrincipal{ID: session.SubjectID, Username: "release.operator", Kind: UserKindLocal, Status: UserStatusActive}
			state := LoginState{Mode: LoginModeLocal}
			mutate(&session, &user, &state)
			repository := &memorySessionRepository{session: session, user: user, state: state}
			verifier, err := NewSessionVerifier(repository, DefaultLocalAuthPolicy(), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(context.Background(), "xms_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, identity.ErrAuthenticationFailed) {
				t.Fatalf("Verify() error = %v", err)
			}
			if repository.touched {
				t.Fatal("rejected session was refreshed")
			}
		})
	}
	verifier, err := NewSessionVerifier(&memorySessionRepository{}, DefaultLocalAuthPolicy(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), "not-a-local-session"); !errors.Is(err, identity.ErrTokenUseInvalid) {
		t.Fatalf("Verify(wrong token type) error = %v", err)
	}
}

type memorySessionRepository struct {
	session      Session
	user         UserPrincipal
	state        LoginState
	loadedDigest string
	touched      bool
}

func (repository *memorySessionRepository) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

func (repository *memorySessionRepository) FindSession(_ context.Context, _ pgx.Tx, digest string) (Session, UserPrincipal, LoginState, error) {
	repository.loadedDigest = digest
	return repository.session, repository.user, repository.state, nil
}

func (repository *memorySessionRepository) TouchSession(_ context.Context, _ pgx.Tx, sessionID uuid.UUID, lastUsedAt, idleExpiresAt time.Time, expectedVersion int64) error {
	if repository.session.ID != sessionID || repository.session.Version != expectedVersion {
		return ErrIAMConflict
	}
	repository.session.LastUsedAt = lastUsedAt
	repository.session.IdleExpiresAt = idleExpiresAt
	repository.session.Version++
	repository.touched = true
	return nil
}
