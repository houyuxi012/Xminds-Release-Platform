package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

const (
	passwordHistoryDepth      = 5
	rateLimitCleanupBatchSize = 128
)

type LocalAuthPolicy struct {
	AccountWindow     time.Duration
	AccountLimit      int
	IPWindow          time.Duration
	IPLimit           int
	SessionAbsolute   time.Duration
	SessionIdle       time.Duration
	EmergencyAbsolute time.Duration
	EmergencyIdle     time.Duration
	LockoutStages     []LockoutStage
}

type LockoutStage struct {
	FailedAttempts int
	Duration       time.Duration
}

func DefaultLocalAuthPolicy() LocalAuthPolicy {
	return LocalAuthPolicy{
		AccountWindow: 5 * time.Minute, AccountLimit: 15,
		IPWindow: 5 * time.Minute, IPLimit: 60,
		SessionAbsolute: 12 * time.Hour, SessionIdle: 30 * time.Minute,
		EmergencyAbsolute: 30 * time.Minute, EmergencyIdle: 10 * time.Minute,
		LockoutStages: []LockoutStage{
			{FailedAttempts: 5, Duration: 5 * time.Minute},
			{FailedAttempts: 8, Duration: 30 * time.Minute},
			{FailedAttempts: 10, Duration: 24 * time.Hour},
		},
	}
}

func validLocalAuthPolicy(policy LocalAuthPolicy) bool {
	return validLockoutStages(policy.LockoutStages) &&
		policy.AccountWindow >= time.Minute && policy.AccountWindow <= time.Hour && policy.AccountLimit >= 5 && policy.AccountLimit <= 1000 &&
		policy.IPWindow >= time.Minute && policy.IPWindow <= time.Hour && policy.IPLimit >= 10 && policy.IPLimit <= 10000 &&
		policy.SessionAbsolute >= time.Hour && policy.SessionAbsolute <= 24*time.Hour && policy.SessionIdle >= 5*time.Minute && policy.SessionIdle <= 2*time.Hour && policy.SessionIdle < policy.SessionAbsolute &&
		policy.EmergencyAbsolute >= 15*time.Minute && policy.EmergencyAbsolute <= time.Hour && policy.EmergencyIdle >= 5*time.Minute && policy.EmergencyIdle <= 15*time.Minute && policy.EmergencyIdle < policy.EmergencyAbsolute
}

func validLockoutStages(stages []LockoutStage) bool {
	if len(stages) < 1 || len(stages) > 5 {
		return false
	}
	previousAttempts, previousDuration := 0, time.Duration(0)
	for _, stage := range stages {
		if stage.FailedAttempts < 3 || stage.FailedAttempts > 50 || stage.FailedAttempts <= previousAttempts ||
			stage.Duration < time.Minute || stage.Duration > 24*time.Hour || stage.Duration <= previousDuration {
			return false
		}
		previousAttempts, previousDuration = stage.FailedAttempts, stage.Duration
	}
	return true
}

type ActivationRepository interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	FindActivation(ctx context.Context, tx pgx.Tx, digest string) (UserPrincipal, LocalCredential, []PasswordDigest, bool, error)
	SaveActivation(ctx context.Context, tx pgx.Tx, user UserPrincipal, credential LocalCredential, history PasswordDigest, expectedVersion int64) error
}

type LoginRepository interface {
	FindLogin(ctx context.Context, tx pgx.Tx, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, bool, error)
	ConsumeRateLimit(ctx context.Context, tx pgx.Tx, scope RateLimitScope, keyDigest string, windowStart time.Time, limit int, expiresAt time.Time) (bool, error)
	CleanupExpiredRateLimits(ctx context.Context, tx pgx.Tx, before time.Time, limit int) (int64, error)
	SaveAuthenticationFailure(ctx context.Context, tx pgx.Tx, userID uuid.UUID, failedAttempts int, lockedUntil time.Time) error
	SaveAuthenticationSuccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID, mfaCounter int64, session Session) error
}

type LocalAuthConfig struct {
	Repository    ActivationRepository
	Auditor       AuditAppender
	Passwords     PasswordService
	DummyPassword PasswordDigest
	MFA           MFAVerifier
	Policy        LocalAuthPolicy
	Clock         func() time.Time
}

type LocalAuthService struct {
	repository    ActivationRepository
	login         LoginRepository
	auditor       AuditAppender
	passwords     PasswordService
	dummyPassword PasswordDigest
	mfa           MFAVerifier
	policy        LocalAuthPolicy
	clock         func() time.Time
}

func NewLocalAuthService(config LocalAuthConfig) (*LocalAuthService, error) {
	login, ok := config.Repository.(LoginRepository)
	if config.Repository == nil || !ok || config.Auditor == nil || config.Passwords == nil || config.MFA == nil || config.Clock == nil || !validLocalAuthPolicy(config.Policy) {
		return nil, ErrIAMConfiguration
	}
	if _, _, _, _, err := parsePasswordDigest(config.DummyPassword); err != nil {
		return nil, ErrIAMConfiguration
	}
	return &LocalAuthService{
		repository: config.Repository, login: login, auditor: config.Auditor, passwords: config.Passwords,
		dummyPassword: config.DummyPassword, mfa: config.MFA, policy: cloneLocalAuthPolicy(config.Policy), clock: config.Clock,
	}, nil
}

func cloneLocalAuthPolicy(policy LocalAuthPolicy) LocalAuthPolicy {
	policy.LockoutStages = append([]LockoutStage(nil), policy.LockoutStages...)
	return policy
}

func (service *LocalAuthService) LoginLocal(ctx context.Context, command LocalLoginCommand, request RequestContext) (LoginResult, error) {
	return service.loginWithMethod(ctx, command, request, AuthenticationMethodLocal)
}

func (service *LocalAuthService) LoginEmergency(ctx context.Context, command LocalLoginCommand, request RequestContext) (LoginResult, error) {
	return service.loginWithMethod(ctx, command, request, AuthenticationMethodEmergency)
}

func (service *LocalAuthService) loginWithMethod(ctx context.Context, command LocalLoginCommand, request RequestContext, method AuthenticationMethod) (LoginResult, error) {
	username := canonicalUsername(command.Username)
	now := service.clock().UTC().Truncate(time.Microsecond)
	allowed, err := service.consumeAuthenticationAttempt(ctx, username, method, request, now)
	if err != nil {
		return LoginResult{}, err
	}
	if !allowed {
		return LoginResult{}, ErrLocalAuthenticationLimited
	}
	var result LoginResult
	var outcome error
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		state, user, credential, administrator, findErr := service.login.FindLogin(ctx, tx, username)
		if findErr != nil && !errors.Is(findErr, ErrLocalAuthenticationFailed) {
			return findErr
		}
		reasonCode := "CREDENTIAL_INVALID"
		eligible := findErr == nil
		if eligible && method == AuthenticationMethodLocal && user.Kind != UserKindLocal {
			eligible, reasonCode = false, "ENTRY_NOT_ALLOWED"
		}
		if eligible && method == AuthenticationMethodEmergency && user.Kind != UserKindEmergency {
			eligible, reasonCode = false, "ENTRY_NOT_ALLOWED"
		}
		if eligible && method == AuthenticationMethodLocal && state.Mode != LoginModeLocal && state.Mode != LoginModeConfiguring {
			eligible, reasonCode = false, "LOGIN_MODE_REJECTED"
		}
		if eligible && user.Status != UserStatusActive {
			eligible, reasonCode = false, "SUBJECT_INACTIVE"
		}
		if eligible && credential.LockedUntil.After(now) {
			eligible, reasonCode = false, "CREDENTIAL_LOCKED"
		}
		passwordDigest := service.dummyPassword
		if eligible {
			passwordDigest = credential.Password
		}
		passwordErr := service.passwords.Verify(command.Password, passwordDigest)
		authenticated := eligible
		authenticationFailed := eligible && passwordErr != nil
		if authenticationFailed {
			authenticated, reasonCode = false, "CREDENTIAL_INVALID"
		}
		mfaCounter := int64(0)
		requiresMFA := user.Kind == UserKindEmergency || administrator
		if authenticated && requiresMFA {
			if !user.MFAEnrolled || credential.MFASecretReference == "" || strings.TrimSpace(command.MFAProof) == "" {
				authenticated, authenticationFailed, reasonCode = false, true, "MFA_REQUIRED"
			} else {
				assertion, verifyErr := service.mfa.Verify(ctx, credential.MFASecretReference, command.MFAProof)
				if verifyErr != nil || assertion.Counter <= credential.MFALastCounter {
					authenticated, authenticationFailed, reasonCode = false, true, "MFA_PROOF_INVALID"
				} else {
					mfaCounter = assertion.Counter
				}
			}
		}
		if !authenticated {
			if authenticationFailed {
				attempts := credential.FailedAttempts + 1
				if err := service.login.SaveAuthenticationFailure(ctx, tx, user.ID, attempts, lockUntilForAttempts(now, attempts, service.policy.LockoutStages)); err != nil {
					return err
				}
			}
			outcome = ErrLocalAuthenticationFailed
			return service.appendLoginAudit(ctx, tx, user, method, audit.OutcomeDenied, reasonCode, request)
		}
		token, digest, generationErr := generateSessionToken()
		if generationErr != nil {
			return generationErr
		}
		sessionID, generationErr := uuid.NewV7()
		if generationErr != nil {
			return fmt.Errorf("generate session ID: %w", generationErr)
		}
		absolute, idle := service.policy.SessionAbsolute, service.policy.SessionIdle
		if method == AuthenticationMethodEmergency {
			absolute, idle = service.policy.EmergencyAbsolute, service.policy.EmergencyIdle
		}
		session := Session{
			ID: sessionID, TokenDigest: digest, SubjectID: user.ID, AuthenticationMethod: method,
			MFALevel: boolToMFA(requiresMFA), AuthenticatedAt: now, LastUsedAt: now,
			AbsoluteExpiresAt: now.Add(absolute), IdleExpiresAt: now.Add(idle), Version: 1,
		}
		if err := service.login.SaveAuthenticationSuccess(ctx, tx, user.ID, mfaCounter, session); err != nil {
			return err
		}
		if err := service.appendLoginAudit(ctx, tx, user, method, audit.OutcomeSuccess, "AUTHENTICATED", request); err != nil {
			return err
		}
		result = LoginResult{
			AccessToken: token, TokenType: "Bearer", ExpiresAt: session.AbsoluteExpiresAt,
			Subject: AuthenticatedSubject{ID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Kind: user.Kind},
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if outcome != nil {
		return LoginResult{}, outcome
	}
	return result, nil
}

func (service *LocalAuthService) consumeAuthenticationAttempt(ctx context.Context, username string, method AuthenticationMethod, request RequestContext, now time.Time) (bool, error) {
	address, parseErr := netip.ParseAddr(strings.TrimSpace(request.SourceIP))
	allowed := false
	err := service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := service.login.CleanupExpiredRateLimits(ctx, tx, now, rateLimitCleanupBatchSize); err != nil {
			return err
		}
		reasonCode := "SOURCE_IP_INVALID"
		if parseErr == nil {
			ipAllowed, err := service.consumeRateLimit(ctx, tx, RateLimitScopeIP, address.String(), service.policy.IPWindow, service.policy.IPLimit, now)
			if err != nil {
				return err
			}
			reasonCode = "IP_RATE_LIMITED"
			if ipAllowed {
				accountAllowed, err := service.consumeRateLimit(ctx, tx, RateLimitScopeAccount, username, service.policy.AccountWindow, service.policy.AccountLimit, now)
				if err != nil {
					return err
				}
				allowed = accountAllowed
				if accountAllowed {
					reasonCode = "RATE_LIMIT_ACCEPTED"
				} else {
					reasonCode = "ACCOUNT_RATE_LIMITED"
				}
			}
		}
		outcome := audit.OutcomeDenied
		if allowed {
			outcome = audit.OutcomeSuccess
		}
		return service.appendAuthenticationAttemptAudit(ctx, tx, method, outcome, reasonCode, request)
	})
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func (service *LocalAuthService) appendLoginAudit(ctx context.Context, tx pgx.Tx, user UserPrincipal, method AuthenticationMethod, outcome audit.Outcome, reasonCode string, request RequestContext) error {
	action, entrypoint := "identity.local_user.login", "local"
	if method == AuthenticationMethodEmergency {
		action, entrypoint = "identity.emergency.login", "emergency"
	}
	return service.appendAuthenticationAuditWithMetadata(ctx, tx, user, action, outcome, reasonCode, request, map[string]any{"entrypoint": entrypoint})
}

func (service *LocalAuthService) appendAuthenticationAttemptAudit(ctx context.Context, tx pgx.Tx, method AuthenticationMethod, outcome audit.Outcome, reasonCode string, request RequestContext) error {
	action, entrypoint := "identity.local_user.login.attempt", "local"
	if method == AuthenticationMethodEmergency {
		action, entrypoint = "identity.emergency.login.attempt", "emergency"
	}
	return service.appendAuthenticationAuditWithMetadata(ctx, tx, UserPrincipal{}, action, outcome, reasonCode, request, map[string]any{"entrypoint": entrypoint})
}

func (service *LocalAuthService) consumeRateLimit(ctx context.Context, tx pgx.Tx, scope RateLimitScope, value string, window time.Duration, limit int, now time.Time) (bool, error) {
	digest := sha256.Sum256([]byte(string(scope) + "\x00" + value))
	seconds := int64(window / time.Second)
	windowStart := time.Unix((now.Unix()/seconds)*seconds, 0).UTC()
	return service.login.ConsumeRateLimit(ctx, tx, scope, hex.EncodeToString(digest[:]), windowStart, limit, windowStart.Add(window))
}

func lockUntilForAttempts(now time.Time, attempts int, stages []LockoutStage) time.Time {
	for index := len(stages) - 1; index >= 0; index-- {
		if attempts >= stages[index].FailedAttempts {
			return now.Add(stages[index].Duration)
		}
	}
	return time.Time{}
}

func generateSessionToken() (string, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token := "xms_" + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:]), nil
}

func boolToMFA(required bool) int {
	if required {
		return 1
	}
	return 0
}

func (service *LocalAuthService) Activate(ctx context.Context, command ActivateLocalAccountCommand, request RequestContext) error {
	token := strings.TrimSpace(command.ActivationToken)
	if token == "" || len(token) > 1024 {
		return ErrLocalAuthenticationFailed
	}
	digest := sha256.Sum256([]byte(token))
	activationDigest := hex.EncodeToString(digest[:])
	now := service.clock().UTC().Truncate(time.Microsecond)
	var outcome error
	err := service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		user, credential, history, administrator, err := service.repository.FindActivation(ctx, tx, activationDigest)
		if err != nil && !errors.Is(err, ErrLocalAuthenticationFailed) {
			return err
		}
		if err != nil || user.Status != UserStatusPending || credential.ActivationDigest == "" || !credential.ActivationExpiresAt.After(now) {
			outcome = ErrLocalAuthenticationFailed
			return service.appendAuthenticationAudit(ctx, tx, UserPrincipal{}, "identity.local_user.activate", audit.OutcomeDenied, "ACTIVATION_INVALID", request)
		}
		if len(history) > passwordHistoryDepth {
			history = history[:passwordHistoryDepth]
		}
		for _, previous := range history {
			if service.passwords.Verify(command.NewPassword, previous) == nil {
				outcome = ErrPasswordRecentlyUsed
				return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "PASSWORD_RECENTLY_USED", request)
			}
		}
		password, err := service.passwords.Hash(ctx, command.NewPassword)
		if err != nil {
			outcome = err
			return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "PASSWORD_POLICY_REJECTED", request)
		}
		requiresMFA := user.Kind == UserKindEmergency || administrator
		hasMFAInput := strings.TrimSpace(command.MFASecretReference) != "" || strings.TrimSpace(command.MFAProof) != ""
		var assertion MFAAssertion
		if requiresMFA || hasMFAInput {
			if strings.TrimSpace(command.MFASecretReference) == "" || strings.TrimSpace(command.MFAProof) == "" {
				outcome = ErrLocalAuthenticationFailed
				return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "MFA_REQUIRED", request)
			}
			assertion, err = service.mfa.Verify(ctx, command.MFASecretReference, command.MFAProof)
			if err != nil || assertion.Counter <= credential.MFALastCounter {
				outcome = ErrLocalAuthenticationFailed
				return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "MFA_PROOF_INVALID", request)
			}
		}
		expectedVersion := user.Version
		user.Status = UserStatusActive
		user.MFAEnrolled = requiresMFA || hasMFAInput
		user.CredentialRotatedAt = now
		user.Version++
		user.UpdatedAt = now
		credential.Password = password
		credential.PasswordChangedAt = now
		credential.ActivationDigest = ""
		credential.ActivationExpiresAt = time.Time{}
		credential.FailedAttempts = 0
		credential.LockedUntil = time.Time{}
		if user.MFAEnrolled {
			credential.MFASecretReference = strings.TrimSpace(command.MFASecretReference)
			credential.MFALastCounter = assertion.Counter
		}
		if err := service.repository.SaveActivation(ctx, tx, user, credential, password, expectedVersion); err != nil {
			if errors.Is(err, ErrLocalAuthenticationFailed) || errors.Is(err, ErrIAMConflict) {
				outcome = ErrLocalAuthenticationFailed
				return err
			}
			return err
		}
		if err := service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeSuccess, "ACTIVATED", request); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if outcome != nil {
			return outcome
		}
		return err
	}
	return outcome
}

func (service *LocalAuthService) appendAuthenticationAudit(ctx context.Context, tx pgx.Tx, user UserPrincipal, action string, outcome audit.Outcome, reasonCode string, request RequestContext) error {
	return service.appendAuthenticationAuditWithMetadata(ctx, tx, user, action, outcome, reasonCode, request, nil)
}

func (service *LocalAuthService) appendAuthenticationAuditWithMetadata(ctx context.Context, tx pgx.Tx, user UserPrincipal, action string, outcome audit.Outcome, reasonCode string, request RequestContext, extra map[string]any) error {
	actorSubject := "local-authentication"
	resourceID := "unknown"
	if user.ID != uuid.Nil {
		actorSubject = user.Username
		resourceID = user.ID.String()
	}
	metadata := map[string]any{"reason_code": reasonCode}
	for key, value := range extra {
		metadata[key] = value
	}
	_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
		Actor:  identity.Principal{Subject: actorSubject, Kind: identity.PrincipalKindLocal},
		Action: action, ResourceType: "user_principal", ResourceID: resourceID, Outcome: outcome,
		RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: metadata,
	})
	return err
}
