package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

const mfaSecretCleanupTimeout = 2 * time.Second

type MFAEnrollmentStart struct {
	ID         uuid.UUID `json:"id"`
	Secret     string    `json:"secret"`
	OTPAuthURI string    `json:"otpauth_uri"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type mfaEnrollmentStarterRepository interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	FindActivation(ctx context.Context, tx pgx.Tx, digest string) (UserPrincipal, LocalCredential, []PasswordDigest, bool, error)
	CleanupExpiredRateLimits(ctx context.Context, tx pgx.Tx, before time.Time, limit int) (int64, error)
	ConsumeRateLimit(ctx context.Context, tx pgx.Tx, scope RateLimitScope, keyDigest string, windowStart time.Time, limit int, expiresAt time.Time) (bool, error)
	GetPendingMFAEnrollmentForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (MFAEnrollment, error)
	ExpireMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, expiredAt time.Time) error
	InsertMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollment MFAEnrollment) error
}

type MFAServiceConfig struct {
	Repository    mfaEnrollmentStarterRepository
	Auditor       AuditAppender
	Secrets       MFASecretStore
	Policy        LocalAuthPolicy
	EnrollmentTTL time.Duration
	Issuer        string
	Clock         func() time.Time
}

type MFAService struct {
	repository    mfaEnrollmentStarterRepository
	auditor       AuditAppender
	secrets       MFASecretStore
	policy        LocalAuthPolicy
	enrollmentTTL time.Duration
	issuer        string
	clock         func() time.Time
}

func NewMFAService(config MFAServiceConfig) (*MFAService, error) {
	if config.Repository == nil || config.Auditor == nil || config.Secrets == nil || config.Clock == nil ||
		!validLocalAuthPolicy(config.Policy) || config.EnrollmentTTL < 5*time.Minute || config.EnrollmentTTL > 15*time.Minute || !validMFATOTPIssuer(config.Issuer) {
		return nil, ErrIAMConfiguration
	}
	return &MFAService{
		repository: config.Repository, auditor: config.Auditor, secrets: config.Secrets,
		policy: cloneLocalAuthPolicy(config.Policy), enrollmentTTL: config.EnrollmentTTL,
		issuer: config.Issuer, clock: config.Clock,
	}, nil
}

func (service *MFAService) BeginActivationEnrollment(ctx context.Context, activationToken string, request RequestContext) (MFAEnrollmentStart, error) {
	if service == nil || ctx == nil {
		return MFAEnrollmentStart{}, ErrIAMConfiguration
	}
	token := strings.TrimSpace(activationToken)
	if len(token) < 32 || token != activationToken || len(token) > 1024 {
		return MFAEnrollmentStart{}, ErrLocalAuthenticationFailed
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	digestBytes := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(digestBytes[:])
	allowed, err := service.consumeBeginAttempt(ctx, digest, request, now)
	if err != nil {
		return MFAEnrollmentStart{}, err
	}
	if !allowed {
		return MFAEnrollmentStart{}, ErrLocalAuthenticationLimited
	}
	enrollmentID, err := uuid.NewV7()
	if err != nil {
		return MFAEnrollmentStart{}, ErrIAMConfiguration
	}
	seedBytes := make([]byte, 20)
	if _, err := rand.Read(seedBytes); err != nil {
		return MFAEnrollmentStart{}, ErrIAMConfiguration
	}
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seedBytes)
	reference, err := service.secrets.Create(ctx, enrollmentID, seed)
	if err != nil {
		return MFAEnrollmentStart{}, err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.Background(), mfaSecretCleanupTimeout)
		defer cancel()
		_ = service.secrets.Delete(cleanupContext, reference)
	}()
	var result MFAEnrollmentStart
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		user, credential, _, _, findErr := service.repository.FindActivation(ctx, tx, digest)
		if findErr != nil || user.Status != UserStatusPending || credential.ActivationDigest == "" || !credential.ActivationExpiresAt.After(now) {
			if findErr != nil && !errors.Is(findErr, ErrLocalAuthenticationFailed) {
				return findErr
			}
			return ErrLocalAuthenticationFailed
		}
		pending, pendingErr := service.repository.GetPendingMFAEnrollmentForUpdate(ctx, tx, user.ID)
		if pendingErr == nil {
			if err := service.repository.ExpireMFAEnrollment(ctx, tx, pending.ID, pending.Version, now); err != nil {
				return err
			}
		} else if !errors.Is(pendingErr, ErrMFAEnrollmentNotFound) {
			return pendingErr
		}
		expiresAt := now.Add(service.enrollmentTTL)
		if credential.ActivationExpiresAt.Before(expiresAt) {
			expiresAt = credential.ActivationExpiresAt.UTC()
		}
		enrollment := MFAEnrollment{
			ID: enrollmentID, UserID: user.ID, Purpose: MFAEnrollmentPurposeActivation, Status: MFAEnrollmentStatusPending,
			SecretReference: reference, ExpectedUserVersion: user.Version, ExpiresAt: expiresAt,
			Version: 1, CreatedAt: now, UpdatedAt: now,
		}
		if err := service.repository.InsertMFAEnrollment(ctx, tx, enrollment); err != nil {
			return err
		}
		if _, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor:  identity.Principal{Subject: "local-activation", Kind: identity.PrincipalKindLocal},
			Action: "identity.local_user.mfa_enrollment.begin", ResourceType: "user_principal", ResourceID: user.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"purpose": string(MFAEnrollmentPurposeActivation)},
		}); err != nil {
			return err
		}
		result = MFAEnrollmentStart{ID: enrollment.ID, Secret: seed, OTPAuthURI: mfaOTPAuthURI(service.issuer, user.Username, seed), ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrLocalAuthenticationFailed) {
			return MFAEnrollmentStart{}, ErrLocalAuthenticationFailed
		}
		return MFAEnrollmentStart{}, err
	}
	committed = true
	return result, nil
}

func (service *MFAService) consumeBeginAttempt(ctx context.Context, activationDigest string, request RequestContext, now time.Time) (bool, error) {
	address, parseErr := netip.ParseAddr(strings.TrimSpace(request.SourceIP))
	allowed := false
	err := service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := service.repository.CleanupExpiredRateLimits(ctx, tx, now, rateLimitCleanupBatchSize); err != nil {
			return err
		}
		if parseErr != nil {
			return nil
		}
		ipAllowed, err := consumeMFAEnrollmentRateLimit(ctx, service.repository, tx, RateLimitScopeIP, address.String(), service.policy.IPWindow, service.policy.IPLimit, now)
		if err != nil || !ipAllowed {
			return err
		}
		allowed, err = consumeMFAEnrollmentRateLimit(ctx, service.repository, tx, RateLimitScopeAccount, activationDigest, service.policy.AccountWindow, service.policy.AccountLimit, now)
		return err
	})
	return allowed, err
}

func consumeMFAEnrollmentRateLimit(ctx context.Context, repository mfaEnrollmentStarterRepository, tx pgx.Tx, scope RateLimitScope, value string, window time.Duration, limit int, now time.Time) (bool, error) {
	digest := sha256.Sum256([]byte("mfa-enrollment\x00" + string(scope) + "\x00" + value))
	seconds := int64(window / time.Second)
	windowStart := time.Unix((now.Unix()/seconds)*seconds, 0).UTC()
	return repository.ConsumeRateLimit(ctx, tx, scope, hex.EncodeToString(digest[:]), windowStart, limit, windowStart.Add(window))
}

func mfaOTPAuthURI(issuer, username, seed string) string {
	values := url.Values{}
	values.Set("issuer", issuer)
	values.Set("secret", seed)
	return "otpauth://totp/" + strictOTPAuthPathSegment(issuer) + ":" + strictOTPAuthPathSegment(username) + "?" + values.Encode()
}

func strictOTPAuthPathSegment(value string) string {
	escaped := url.PathEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%2B")
	escaped = strings.ReplaceAll(escaped, "@", "%40")
	return escaped
}

func validMFATOTPIssuer(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len([]rune(value)) > 128 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
