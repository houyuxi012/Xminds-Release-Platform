package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
)

const localSessionPrefix = "xms_"

type SessionRepository interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	FindSession(ctx context.Context, tx pgx.Tx, tokenDigest string) (Session, UserPrincipal, LoginState, error)
	TouchSession(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, lastUsedAt, idleExpiresAt time.Time, expectedVersion int64) error
}

type SessionVerifier struct {
	repository SessionRepository
	policy     LocalAuthPolicy
	clock      func() time.Time
}

func NewSessionVerifier(repository SessionRepository, policy LocalAuthPolicy, clock func() time.Time) (*SessionVerifier, error) {
	if repository == nil || clock == nil || !validLocalAuthPolicy(policy) {
		return nil, ErrIAMConfiguration
	}
	return &SessionVerifier{repository: repository, policy: policy, clock: clock}, nil
}

func (verifier *SessionVerifier) Verify(ctx context.Context, rawToken string) (identity.Principal, error) {
	if verifier == nil || verifier.repository == nil || verifier.clock == nil {
		return identity.Principal{}, identity.ErrAuthenticationFailed
	}
	secret, found := strings.CutPrefix(rawToken, localSessionPrefix)
	if !found {
		return identity.Principal{}, identity.ErrTokenUseInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 || len(rawToken) > 128 {
		return identity.Principal{}, identity.ErrAuthenticationFailed
	}
	digest := sha256.Sum256([]byte(rawToken))
	now := verifier.clock().UTC().Truncate(time.Microsecond)
	var principal identity.Principal
	err = verifier.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		session, user, state, err := verifier.repository.FindSession(ctx, tx, hex.EncodeToString(digest[:]))
		if err != nil || session.ID == uuid.Nil || session.TokenDigest != hex.EncodeToString(digest[:]) || session.SubjectID != user.ID ||
			!session.RevokedAt.IsZero() || !session.AbsoluteExpiresAt.After(now) || !session.IdleExpiresAt.After(now) || user.Status != UserStatusActive {
			return identity.ErrAuthenticationFailed
		}
		idleTimeout := verifier.policy.SessionIdle
		switch session.AuthenticationMethod {
		case AuthenticationMethodLocal:
			if user.Kind != UserKindLocal || (state.Mode != LoginModeLocal && state.Mode != LoginModeConfiguring) {
				return identity.ErrAuthenticationFailed
			}
		case AuthenticationMethodEmergency:
			if user.Kind != UserKindEmergency || session.MFALevel < 1 {
				return identity.ErrAuthenticationFailed
			}
			idleTimeout = verifier.policy.EmergencyIdle
		default:
			return identity.ErrAuthenticationFailed
		}
		idleExpiresAt := now.Add(idleTimeout)
		if idleExpiresAt.After(session.AbsoluteExpiresAt) {
			idleExpiresAt = session.AbsoluteExpiresAt
		}
		if err := verifier.repository.TouchSession(ctx, tx, session.ID, now, idleExpiresAt, session.Version); err != nil {
			return identity.ErrAuthenticationFailed
		}
		principal = identity.Principal{
			Subject: user.Username, Kind: identity.PrincipalKindLocal, TokenID: session.ID.String(),
			AuthenticationAssurance: session.MFALevel,
		}
		return nil
	})
	if err != nil {
		return identity.Principal{}, identity.ErrAuthenticationFailed
	}
	return principal, nil
}
