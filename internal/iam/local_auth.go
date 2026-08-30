package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
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

type MFAActivationRepository interface {
	GetMFAActivationPreflight(ctx context.Context, activationDigest string, enrollmentID uuid.UUID) (MFAEnrollment, error)
	GetMFAEnrollmentForUpdate(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID) (MFAEnrollment, error)
	LockMFASecretReference(ctx context.Context, tx pgx.Tx, reference string) error
	MFASecretReferenceHasTombstone(ctx context.Context, tx pgx.Tx, reference string) (bool, error)
	ConfirmMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, confirmedAt time.Time) error
	ReplaceMFARecoveryCodes(ctx context.Context, tx pgx.Tx, userID, generationID uuid.UUID, digests []string, createdAt time.Time) error
}

type LoginRepository interface {
	FindLoginPreflight(ctx context.Context, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, bool, error)
	FindLogin(ctx context.Context, tx pgx.Tx, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, bool, error)
	ConsumeRateLimit(ctx context.Context, tx pgx.Tx, scope RateLimitScope, keyDigest string, windowStart time.Time, limit int, expiresAt time.Time) (bool, error)
	CleanupExpiredRateLimits(ctx context.Context, tx pgx.Tx, before time.Time, limit int) (int64, error)
	SaveAuthenticationFailure(ctx context.Context, tx pgx.Tx, userID uuid.UUID, failedAttempts int, lockedUntil time.Time) error
	SaveAuthenticationSuccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID, mfaCounter int64, session Session) error
}

type LoginStateRepository interface {
	GetLoginState(ctx context.Context, tx pgx.Tx) (LoginState, error)
}

type CurrentSessionRepository interface {
	RevokeCurrentSession(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, revokedAt time.Time, reason string) error
}

type MFARecoveryRepository interface {
	ConsumeMFARecoveryCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID, digest string, usedAt time.Time) (bool, error)
}

type LocalReauthenticationRepository interface {
	FindLocalReauthenticationPreflight(ctx context.Context, canonicalUsername string, sessionID uuid.UUID) (LoginState, UserPrincipal, LocalCredential, Session, bool, error)
	FindLocalReauthentication(ctx context.Context, tx pgx.Tx, canonicalUsername string, sessionID uuid.UUID) (LoginState, UserPrincipal, LocalCredential, Session, bool, error)
	SaveReauthenticationSuccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID, mfaCounter int64) error
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
	repository       ActivationRepository
	login            LoginRepository
	loginState       LoginStateRepository
	currentSession   CurrentSessionRepository
	reauthentication LocalReauthenticationRepository
	mfaActivation    MFAActivationRepository
	mfaRecovery      MFARecoveryRepository
	auditor          AuditAppender
	passwords        PasswordService
	dummyPassword    PasswordDigest
	mfa              MFAVerifier
	policy           LocalAuthPolicy
	clock            func() time.Time
}

func NewLocalAuthService(config LocalAuthConfig) (*LocalAuthService, error) {
	login, ok := config.Repository.(LoginRepository)
	loginState, loginStateOK := config.Repository.(LoginStateRepository)
	currentSession, currentSessionOK := config.Repository.(CurrentSessionRepository)
	reauthentication, reauthenticationOK := config.Repository.(LocalReauthenticationRepository)
	mfaActivation, mfaActivationOK := config.Repository.(MFAActivationRepository)
	mfaRecovery, mfaRecoveryOK := config.Repository.(MFARecoveryRepository)
	if config.Repository == nil || !ok || !loginStateOK || !currentSessionOK || !reauthenticationOK || !mfaActivationOK || !mfaRecoveryOK || config.Auditor == nil || config.Passwords == nil || config.MFA == nil || config.Clock == nil || !validLocalAuthPolicy(config.Policy) {
		return nil, ErrIAMConfiguration
	}
	if _, _, _, _, err := parsePasswordDigest(config.DummyPassword); err != nil {
		return nil, ErrIAMConfiguration
	}
	return &LocalAuthService{
		repository: config.Repository, login: login, loginState: loginState, currentSession: currentSession, reauthentication: reauthentication, auditor: config.Auditor, passwords: config.Passwords,
		dummyPassword: config.DummyPassword, mfa: config.MFA, mfaActivation: mfaActivation, mfaRecovery: mfaRecovery, policy: cloneLocalAuthPolicy(config.Policy), clock: config.Clock,
	}, nil
}

func (service *LocalAuthService) LogoutCurrentSession(ctx context.Context, principal identity.Principal, request RequestContext) error {
	if service == nil || service.repository == nil || service.currentSession == nil || service.auditor == nil || service.clock == nil || principal.Kind != identity.PrincipalKindLocal {
		return ErrLocalAuthenticationFailed
	}
	sessionID, err := uuid.Parse(strings.TrimSpace(principal.TokenID))
	if err != nil || sessionID == uuid.Nil {
		return ErrLocalAuthenticationFailed
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.currentSession.RevokeCurrentSession(ctx, tx, sessionID, now, "user logout"); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "identity.session.logout", ResourceType: "local_session", ResourceID: sessionID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
		})
		return err
	})
}

type PublicLoginState struct {
	Mode LoginMode `json:"mode"`
}

func (service *LocalAuthService) GetPublicLoginState(ctx context.Context) (PublicLoginState, error) {
	if service == nil || service.loginState == nil {
		return PublicLoginState{}, ErrIAMConfiguration
	}
	state, err := service.loginState.GetLoginState(ctx, nil)
	if err != nil {
		return PublicLoginState{}, err
	}
	switch state.Mode {
	case LoginModeLocal, LoginModeConfiguring, LoginModeSSO, LoginModeFault:
		return PublicLoginState{Mode: state.Mode}, nil
	default:
		return PublicLoginState{}, ErrIAMConfiguration
	}
}

type localFactorResult struct {
	authenticated        bool
	authenticationFailed bool
	reasonCode           string
	mfaCounter           int64
	factorType           string
}

type localLoginPreflight struct {
	state         LoginState
	user          UserPrincipal
	credential    LocalCredential
	administrator bool
	eligible      bool
	passwordValid bool
	mfaAssertion  MFAAssertion
	mfaError      error
}

type localReauthenticationPreflight struct {
	state         LoginState
	user          UserPrincipal
	credential    LocalCredential
	session       Session
	administrator bool
	eligible      bool
	passwordValid bool
	mfaAssertion  MFAAssertion
	mfaError      error
}

func (service *LocalAuthService) verifyLocalFactors(preflight localReauthenticationPreflight, user UserPrincipal, credential LocalCredential, session Session, administrator, eligible bool, mfaProof string) localFactorResult {
	result := localFactorResult{authenticated: eligible, reasonCode: "CREDENTIAL_INVALID"}
	if eligible && (!preflight.passwordValid || !sameLocalReauthenticationPreflight(preflight, user, credential, session, administrator)) {
		result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "CREDENTIAL_INVALID"
	}
	requiresMFA := user.MFAEnrolled || user.Kind == UserKindEmergency || administrator
	if result.authenticated && requiresMFA {
		if !user.MFAEnrolled || credential.MFASecretReference == "" || strings.TrimSpace(mfaProof) == "" {
			result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_REQUIRED"
		} else {
			assertion := preflight.mfaAssertion
			if preflight.mfaError != nil || assertion.Counter <= credential.MFALastCounter {
				result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_PROOF_INVALID"
			} else {
				result.mfaCounter = assertion.Counter
				result.factorType = "totp"
			}
		}
	} else if result.authenticated && strings.TrimSpace(mfaProof) != "" {
		result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_PROOF_INVALID"
	}
	return result
}

func (service *LocalAuthService) prepareLocalReauthenticationPreflight(ctx context.Context, username string, sessionID uuid.UUID, command CompleteReauthenticationCommand, now time.Time) (localReauthenticationPreflight, error) {
	state, user, credential, session, administrator, findErr := service.reauthentication.FindLocalReauthenticationPreflight(ctx, username, sessionID)
	if findErr != nil && !errors.Is(findErr, ErrLocalAuthenticationFailed) {
		return localReauthenticationPreflight{}, findErr
	}
	eligible := localReauthenticationEligibility(state, user, credential, session, administrator, findErr == nil, username, sessionID, now)
	passwordDigest := service.dummyPassword
	if eligible {
		passwordDigest = credential.Password
	}
	preflight := localReauthenticationPreflight{
		state: state, user: user, credential: credential, session: session, administrator: administrator, eligible: eligible,
		passwordValid: eligible && service.passwords.Verify(command.Password, passwordDigest) == nil,
	}
	if !eligible {
		_ = service.passwords.Verify(command.Password, passwordDigest)
		return preflight, nil
	}
	requiresMFA := user.MFAEnrolled || user.Kind == UserKindEmergency || administrator
	if preflight.passwordValid && requiresMFA && user.MFAEnrolled && credential.MFASecretReference != "" && strings.TrimSpace(command.MFAProof) != "" {
		preflight.mfaAssertion, preflight.mfaError = service.mfa.Verify(ctx, credential.MFASecretReference, command.MFAProof)
	}
	return preflight, nil
}

func localReauthenticationEligibility(state LoginState, user UserPrincipal, credential LocalCredential, session Session, _ bool, found bool, username string, sessionID uuid.UUID, now time.Time) bool {
	eligible := found && user.Username == username && user.Status == UserStatusActive && !credential.LockedUntil.After(now) &&
		session.ID == sessionID && session.SubjectID == user.ID && session.RevokedAt.IsZero() && session.AbsoluteExpiresAt.After(now) && session.IdleExpiresAt.After(now)
	if !eligible {
		return false
	}
	switch session.AuthenticationMethod {
	case AuthenticationMethodLocal:
		return user.Kind == UserKindLocal && (state.Mode == LoginModeLocal || state.Mode == LoginModeConfiguring)
	case AuthenticationMethodEmergency:
		return user.Kind == UserKindEmergency && session.MFALevel >= 1
	default:
		return false
	}
}

func sameLocalReauthenticationPreflight(preflight localReauthenticationPreflight, user UserPrincipal, credential LocalCredential, session Session, administrator bool) bool {
	return sameLocalLoginPreflight(localLoginPreflight{
		state: preflight.state, user: preflight.user, credential: preflight.credential,
		administrator: preflight.administrator, eligible: preflight.eligible,
	}, user, credential, administrator) &&
		preflight.session.ID == session.ID && preflight.session.Version == session.Version &&
		preflight.session.SubjectID == session.SubjectID && preflight.session.AuthenticationMethod == session.AuthenticationMethod &&
		preflight.session.MFALevel == session.MFALevel && preflight.session.RevokedAt.Equal(session.RevokedAt) &&
		preflight.session.AbsoluteExpiresAt.Equal(session.AbsoluteExpiresAt) && preflight.session.IdleExpiresAt.Equal(session.IdleExpiresAt)
}

func (service *LocalAuthService) verifyLoginFactors(ctx context.Context, tx pgx.Tx, preflight localLoginPreflight, user UserPrincipal, credential LocalCredential, administrator, eligible bool, mfaProof, recoveryCode string, now time.Time) (localFactorResult, error) {
	result := localFactorResult{authenticated: eligible, reasonCode: "CREDENTIAL_INVALID"}
	if eligible && (!preflight.passwordValid || !sameLocalLoginPreflight(preflight, user, credential, administrator)) {
		result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "CREDENTIAL_INVALID"
	}
	if !result.authenticated {
		return result, nil
	}

	totpPresent := strings.TrimSpace(mfaProof) != ""
	recoveryPresent := strings.TrimSpace(recoveryCode) != ""
	requiresMFA := user.MFAEnrolled || user.Kind == UserKindEmergency || administrator
	if !requiresMFA {
		if totpPresent || recoveryPresent {
			result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_PROOF_INVALID"
		}
		return result, nil
	}
	if !user.MFAEnrolled || totpPresent == recoveryPresent {
		result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_REQUIRED"
		return result, nil
	}
	if totpPresent {
		if credential.MFASecretReference == "" {
			result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_REQUIRED"
			return result, nil
		}
		assertion := preflight.mfaAssertion
		if preflight.mfaError != nil || assertion.Counter <= credential.MFALastCounter {
			result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_PROOF_INVALID"
			return result, nil
		}
		result.mfaCounter = assertion.Counter
		result.factorType = "totp"
		return result, nil
	}

	canonical, valid := canonicalMFARecoveryCode(recoveryCode)
	if !valid {
		result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_PROOF_INVALID"
		return result, nil
	}
	digest := sha256.Sum256([]byte(canonical))
	consumed, consumeErr := service.mfaRecovery.ConsumeMFARecoveryCode(ctx, tx, user.ID, hex.EncodeToString(digest[:]), now)
	if consumeErr != nil {
		return localFactorResult{}, consumeErr
	}
	if !consumed {
		result.authenticated, result.authenticationFailed, result.reasonCode = false, true, "MFA_PROOF_INVALID"
		return result, nil
	}
	result.factorType = "recovery_code"
	return result, nil
}

func (service *LocalAuthService) prepareLocalLoginPreflight(ctx context.Context, username string, command LocalLoginCommand, method AuthenticationMethod, now time.Time) (localLoginPreflight, error) {
	state, user, credential, administrator, findErr := service.login.FindLoginPreflight(ctx, username)
	if findErr != nil && !errors.Is(findErr, ErrLocalAuthenticationFailed) {
		return localLoginPreflight{}, findErr
	}
	eligible, _ := localLoginEligibility(state, user, credential, findErr == nil, method, now)
	passwordDigest := service.dummyPassword
	if eligible {
		passwordDigest = credential.Password
	}
	preflight := localLoginPreflight{
		state: state, user: user, credential: credential, administrator: administrator, eligible: eligible,
		passwordValid: eligible && service.passwords.Verify(command.Password, passwordDigest) == nil,
	}
	if !eligible {
		_ = service.passwords.Verify(command.Password, passwordDigest)
		return preflight, nil
	}
	requiresMFA := user.MFAEnrolled || user.Kind == UserKindEmergency || administrator
	totpPresent := strings.TrimSpace(command.MFAProof) != ""
	recoveryPresent := strings.TrimSpace(command.RecoveryCode) != ""
	if preflight.passwordValid && requiresMFA && user.MFAEnrolled && totpPresent && !recoveryPresent && credential.MFASecretReference != "" {
		preflight.mfaAssertion, preflight.mfaError = service.mfa.Verify(ctx, credential.MFASecretReference, command.MFAProof)
	}
	return preflight, nil
}

func localLoginEligibility(state LoginState, user UserPrincipal, credential LocalCredential, found bool, method AuthenticationMethod, now time.Time) (bool, string) {
	reasonCode := "CREDENTIAL_INVALID"
	eligible := found
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
	return eligible, reasonCode
}

func sameLocalLoginPreflight(preflight localLoginPreflight, user UserPrincipal, credential LocalCredential, administrator bool) bool {
	return preflight.eligible && preflight.state.Version >= 1 &&
		preflight.user.ID == user.ID && preflight.user.Version == user.Version && preflight.user.Kind == user.Kind &&
		preflight.user.Status == user.Status && preflight.user.MFAEnrolled == user.MFAEnrolled &&
		preflight.administrator == administrator && preflight.credential.UserID == credential.UserID &&
		preflight.credential.MFASecretReference == credential.MFASecretReference &&
		preflight.credential.MFALastCounter == credential.MFALastCounter &&
		preflight.credential.FailedAttempts == credential.FailedAttempts &&
		preflight.credential.LockedUntil.Equal(credential.LockedUntil) &&
		passwordDigestEqual(preflight.credential.Password, credential.Password)
}

func passwordDigestEqual(left, right PasswordDigest) bool {
	return left.Algorithm == right.Algorithm && left.Parameters == right.Parameters &&
		subtle.ConstantTimeCompare(left.Salt, right.Salt) == 1 && subtle.ConstantTimeCompare(left.DerivedKey, right.DerivedKey) == 1
}

func canonicalMFARecoveryCode(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	canonical := strings.ToUpper(strings.ReplaceAll(trimmed, "-", ""))
	if len(canonical) != 24 {
		return "", false
	}
	for _, character := range canonical {
		if (character < 'A' || character > 'Z') && (character < '2' || character > '7') {
			return "", false
		}
	}
	return canonical, true
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
	preflight, err := service.prepareLocalLoginPreflight(ctx, username, command, method, now)
	if err != nil {
		return LoginResult{}, err
	}
	var result LoginResult
	var outcome error
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		state, user, credential, administrator, findErr := service.login.FindLogin(ctx, tx, username)
		if findErr != nil && !errors.Is(findErr, ErrLocalAuthenticationFailed) {
			return findErr
		}
		eligible, reasonCode := localLoginEligibility(state, user, credential, findErr == nil, method, now)
		if eligible && (preflight.state.Mode != state.Mode || preflight.state.Version != state.Version) {
			eligible = false
		}
		factors, factorErr := service.verifyLoginFactors(ctx, tx, preflight, user, credential, administrator, eligible, command.MFAProof, command.RecoveryCode, now)
		if factorErr != nil {
			return factorErr
		}
		if !factors.authenticated {
			if factors.authenticationFailed {
				attempts := credential.FailedAttempts + 1
				if err := service.login.SaveAuthenticationFailure(ctx, tx, user.ID, attempts, lockUntilForAttempts(now, attempts, service.policy.LockoutStages)); err != nil {
					return err
				}
			}
			outcome = ErrLocalAuthenticationFailed
			if reasonCode == "CREDENTIAL_INVALID" {
				reasonCode = factors.reasonCode
			}
			return service.appendLoginAudit(ctx, tx, user, method, audit.OutcomeDenied, reasonCode, "", request)
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
			MFALevel: boolToMFA(factors.factorType != ""), AuthenticatedAt: now, LastUsedAt: now,
			AbsoluteExpiresAt: now.Add(absolute), IdleExpiresAt: now.Add(idle), Version: 1,
		}
		if err := service.login.SaveAuthenticationSuccess(ctx, tx, user.ID, factors.mfaCounter, session); err != nil {
			return err
		}
		if err := service.appendLoginAudit(ctx, tx, user, method, audit.OutcomeSuccess, "AUTHENTICATED", factors.factorType, request); err != nil {
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

func (service *LocalAuthService) Reauthenticate(ctx context.Context, actor identity.Principal, command CompleteReauthenticationCommand, request RequestContext) error {
	if service == nil || service.reauthentication == nil || actor.Kind != identity.PrincipalKindLocal {
		return ErrLocalAuthenticationFailed
	}
	sessionID, err := uuid.Parse(strings.TrimSpace(actor.TokenID))
	if err != nil || sessionID == uuid.Nil || sessionID.Version() != 7 {
		return ErrLocalAuthenticationFailed
	}
	username := canonicalUsername(actor.Subject)
	now := service.clock().UTC().Truncate(time.Microsecond)
	allowed, err := service.consumeAuthenticationAttempt(ctx, username, AuthenticationMethodReauthentication, request, now)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrLocalAuthenticationLimited
	}
	preflight, err := service.prepareLocalReauthenticationPreflight(ctx, username, sessionID, command, now)
	if err != nil {
		return err
	}
	var outcome error
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		state, user, credential, session, administrator, findErr := service.reauthentication.FindLocalReauthentication(ctx, tx, username, sessionID)
		if findErr != nil && !errors.Is(findErr, ErrLocalAuthenticationFailed) {
			return findErr
		}
		eligible := localReauthenticationEligibility(state, user, credential, session, administrator, findErr == nil, username, sessionID, now)
		if eligible && (preflight.state.Mode != state.Mode || preflight.state.Version != state.Version) {
			eligible = false
		}
		factors := service.verifyLocalFactors(preflight, user, credential, session, administrator, eligible, command.MFAProof)
		if !factors.authenticated {
			if factors.authenticationFailed {
				attempts := credential.FailedAttempts + 1
				if saveErr := service.login.SaveAuthenticationFailure(ctx, tx, user.ID, attempts, lockUntilForAttempts(now, attempts, service.policy.LockoutStages)); saveErr != nil {
					return saveErr
				}
			}
			outcome = ErrLocalAuthenticationFailed
			return service.appendAuthenticationAudit(ctx, tx, user, "identity.reauthentication.local", audit.OutcomeDenied, factors.reasonCode, request)
		}
		if saveErr := service.reauthentication.SaveReauthenticationSuccess(ctx, tx, user.ID, factors.mfaCounter); saveErr != nil {
			return saveErr
		}
		return service.appendAuthenticationAudit(ctx, tx, user, "identity.reauthentication.local", audit.OutcomeSuccess, "REAUTHENTICATED", request)
	})
	if err != nil {
		return err
	}
	return outcome
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

func (service *LocalAuthService) appendLoginAudit(ctx context.Context, tx pgx.Tx, user UserPrincipal, method AuthenticationMethod, outcome audit.Outcome, reasonCode, factorType string, request RequestContext) error {
	action, entrypoint := "identity.local_user.login", "local"
	if method == AuthenticationMethodEmergency {
		action, entrypoint = "identity.emergency.login", "emergency"
	}
	metadata := map[string]any{"entrypoint": entrypoint}
	if factorType != "" {
		metadata["factor_type"] = factorType
	}
	return service.appendAuthenticationAuditWithMetadata(ctx, tx, user, action, outcome, reasonCode, request, metadata)
}

func (service *LocalAuthService) appendAuthenticationAttemptAudit(ctx context.Context, tx pgx.Tx, method AuthenticationMethod, outcome audit.Outcome, reasonCode string, request RequestContext) error {
	action, entrypoint := "identity.local_user.login.attempt", "local"
	switch method {
	case AuthenticationMethodEmergency:
		action, entrypoint = "identity.emergency.login.attempt", "emergency"
	case AuthenticationMethodReauthentication:
		action, entrypoint = "identity.reauthentication.local.attempt", "reauthentication"
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
	_, err := service.ActivateWithResult(ctx, command, request)
	return err
}

func (service *LocalAuthService) ActivateWithResult(ctx context.Context, command ActivateLocalAccountCommand, request RequestContext) (LocalActivationResult, error) {
	token := strings.TrimSpace(command.ActivationToken)
	if token == "" || token != command.ActivationToken || len(token) > 1024 || strings.TrimSpace(command.MFASecretReference) != "" {
		return LocalActivationResult{}, ErrLocalAuthenticationFailed
	}
	digest := sha256.Sum256([]byte(token))
	activationDigest := hex.EncodeToString(digest[:])
	now := service.clock().UTC().Truncate(time.Microsecond)
	hasMFAInput := command.MFAEnrollmentID != uuid.Nil || strings.TrimSpace(command.MFAProof) != ""
	var preflightEnrollment MFAEnrollment
	var preflightAssertion MFAAssertion
	var preflightProofError error
	if command.MFAEnrollmentID != uuid.Nil && strings.TrimSpace(command.MFAProof) != "" {
		preflightEnrollment, preflightProofError = service.mfaActivation.GetMFAActivationPreflight(ctx, activationDigest, command.MFAEnrollmentID)
		if preflightProofError == nil {
			preflightAssertion, preflightProofError = service.mfa.Verify(ctx, preflightEnrollment.SecretReference, command.MFAProof)
		} else if !errors.Is(preflightProofError, ErrMFAEnrollmentNotFound) && !errors.Is(preflightProofError, ErrLocalAuthenticationFailed) {
			return LocalActivationResult{}, preflightProofError
		}
	}
	recoveryCodes := make([]string, 0)
	var recoveryDigests []string
	var recoveryGeneration uuid.UUID
	if command.MFAEnrollmentID != uuid.Nil {
		var err error
		recoveryCodes, recoveryDigests, recoveryGeneration, err = generateMFARecoveryCodeSet(10)
		if err != nil {
			return LocalActivationResult{}, err
		}
	}
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
		var assertion MFAAssertion
		var enrollment MFAEnrollment
		if requiresMFA || hasMFAInput {
			if command.MFAEnrollmentID == uuid.Nil || strings.TrimSpace(command.MFAProof) == "" {
				outcome = ErrLocalAuthenticationFailed
				return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "MFA_REQUIRED", request)
			}
			enrollment, err = service.mfaActivation.GetMFAEnrollmentForUpdate(ctx, tx, command.MFAEnrollmentID)
			if err != nil || enrollment.UserID != user.ID || enrollment.Purpose != MFAEnrollmentPurposeActivation || enrollment.Status != MFAEnrollmentStatusPending ||
				enrollment.ExpectedUserVersion != user.Version || !enrollment.ExpiresAt.After(now) {
				outcome = ErrLocalAuthenticationFailed
				return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "MFA_ENROLLMENT_INVALID", request)
			}
			if preflightProofError != nil || preflightEnrollment.ID != enrollment.ID || preflightEnrollment.Version != enrollment.Version ||
				preflightEnrollment.SecretReference != enrollment.SecretReference || preflightAssertion.Counter <= credential.MFALastCounter {
				outcome = ErrLocalAuthenticationFailed
				return service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeDenied, "MFA_PROOF_INVALID", request)
			}
			assertion = preflightAssertion
			if err := service.mfaActivation.LockMFASecretReference(ctx, tx, enrollment.SecretReference); err != nil {
				return err
			}
			tombstone, err := service.mfaActivation.MFASecretReferenceHasTombstone(ctx, tx, enrollment.SecretReference)
			if err != nil {
				return err
			}
			if tombstone {
				outcome = ErrLocalAuthenticationFailed
				return ErrIAMConflict
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
			credential.MFASecretReference = enrollment.SecretReference
			credential.MFALastCounter = assertion.Counter
		}
		if err := service.repository.SaveActivation(ctx, tx, user, credential, password, expectedVersion); err != nil {
			if errors.Is(err, ErrLocalAuthenticationFailed) || errors.Is(err, ErrIAMConflict) {
				outcome = ErrLocalAuthenticationFailed
				return err
			}
			return err
		}
		if user.MFAEnrolled {
			if err := service.mfaActivation.ConfirmMFAEnrollment(ctx, tx, enrollment.ID, enrollment.Version, now); err != nil {
				outcome = ErrLocalAuthenticationFailed
				return err
			}
			if err := service.mfaActivation.ReplaceMFARecoveryCodes(ctx, tx, user.ID, recoveryGeneration, recoveryDigests, now); err != nil {
				return err
			}
		}
		if err := service.appendAuthenticationAudit(ctx, tx, user, "identity.local_user.activate", audit.OutcomeSuccess, "ACTIVATED", request); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if outcome != nil {
			return LocalActivationResult{}, outcome
		}
		return LocalActivationResult{}, err
	}
	return LocalActivationResult{RecoveryCodes: recoveryCodes}, outcome
}

func generateMFARecoveryCodeSet(count int) ([]string, []string, uuid.UUID, error) {
	if count < 1 || count > 32 {
		return nil, nil, uuid.Nil, ErrIAMConfiguration
	}
	generationID, err := uuid.NewV7()
	if err != nil {
		return nil, nil, uuid.Nil, ErrIAMConfiguration
	}
	codes := make([]string, 0, count)
	digests := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for len(codes) < count {
		entropy := make([]byte, 15)
		if _, err := rand.Read(entropy); err != nil {
			return nil, nil, uuid.Nil, ErrIAMConfiguration
		}
		canonical := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy)
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		digest := sha256.Sum256([]byte(canonical))
		digests = append(digests, hex.EncodeToString(digest[:]))
		codes = append(codes, strings.Join([]string{canonical[0:4], canonical[4:8], canonical[8:12], canonical[12:16], canonical[16:20], canonical[20:24]}, "-"))
	}
	return codes, digests, generationID, nil
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
