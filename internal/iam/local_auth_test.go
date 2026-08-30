package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

func TestLocalReauthenticationReusesPasswordMFAAndDoesNotCreateSession(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, true, LoginModeLocal)
	sessionID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49003")
	harness.repository.sessions[sessionID] = Session{
		ID: sessionID, SubjectID: harness.userID, AuthenticationMethod: AuthenticationMethodLocal, MFALevel: 1,
		AuthenticatedAt: harness.now.Add(-time.Hour), LastUsedAt: harness.now.Add(-time.Minute),
		AbsoluteExpiresAt: harness.now.Add(time.Hour), IdleExpiresAt: harness.now.Add(time.Minute), Version: 1,
	}
	credential := harness.repository.credentials[harness.userID]
	credential.FailedAttempts = 2
	harness.repository.credentials[harness.userID] = credential
	actor := identity.Principal{Subject: "release.operator", Kind: identity.PrincipalKindLocal, TokenID: sessionID.String(), AuthenticationAssurance: 1}

	if err := harness.service.Reauthenticate(context.Background(), actor, CompleteReauthenticationCommand{
		Password: "Current-Strong-Password!", MFAProof: "123456",
	}, harness.request); err != nil {
		t.Fatalf("Reauthenticate() error = %v", err)
	}
	credential = harness.repository.credentials[harness.userID]
	if credential.FailedAttempts != 0 || !credential.LockedUntil.IsZero() || credential.MFALastCounter != 42 {
		t.Fatalf("credential after reauthentication = %+v", credential)
	}
	if len(harness.repository.sessions) != 1 {
		t.Fatalf("reauthentication created a session: %+v", harness.repository.sessions)
	}
	command := harness.auditor.commands[len(harness.auditor.commands)-1]
	if command.Action != "identity.reauthentication.local" || command.Outcome != audit.OutcomeSuccess {
		t.Fatalf("reauthentication audit = %+v", command)
	}
	attempt := harness.auditor.commands[len(harness.auditor.commands)-2]
	if attempt.Action != "identity.reauthentication.local.attempt" || attempt.Metadata["entrypoint"] != "reauthentication" {
		t.Fatalf("reauthentication rate-limit audit = %+v", attempt)
	}
	serialized := fmt.Sprintf("%v", command)
	for _, secret := range []string{"Current-Strong-Password!", "123456", sessionID.String()} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("reauthentication audit contains secret: %+v", command)
		}
	}
}

func TestLocalReauthenticationDoesNotHoldDatabaseTransactionDuringSecretResolution(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, true, LoginModeLocal)
	sessionID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49003")
	harness.repository.sessions[sessionID] = validMemorySession(harness, sessionID)
	actor := identity.Principal{Subject: "release.operator", Kind: identity.PrincipalKindLocal, TokenID: sessionID.String(), AuthenticationAssurance: 1}
	entered := make(chan struct{})
	release := make(chan struct{})
	harness.service.mfa = blockingMFAVerifier{entered: entered, release: release}
	done := make(chan error, 1)
	go func() {
		done <- harness.service.Reauthenticate(context.Background(), actor, CompleteReauthenticationCommand{
			Password: "Current-Strong-Password!", MFAProof: "123456",
		}, harness.request)
	}()
	<-entered
	if !harness.repository.mu.TryLock() {
		close(release)
		<-done
		t.Fatal("database transaction lock was held while reauthentication MFA secret was resolved")
	}
	harness.repository.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Reauthenticate() error = %v", err)
	}
}

func TestLocalReauthenticationCredentialAndMFAFailuresUseProgressiveLockout(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		password string
		mfaProof string
	}{
		{name: "password", password: "Wrong-Password-Value!", mfaProof: "123456"},
		{name: "missing mfa", password: "Current-Strong-Password!", mfaProof: ""},
		{name: "invalid mfa", password: "Current-Strong-Password!", mfaProof: "654321"},
		{name: "replayed mfa", password: "Current-Strong-Password!", mfaProof: "123456"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newActiveLocalAuthHarness(t, UserKindLocal, true, LoginModeLocal)
			sessionID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49003")
			harness.repository.sessions[sessionID] = validMemorySession(harness, sessionID)
			if testCase.name == "replayed mfa" {
				credential := harness.repository.credentials[harness.userID]
				credential.MFALastCounter = 42
				harness.repository.credentials[harness.userID] = credential
			}
			actor := identity.Principal{Subject: "release.operator", Kind: identity.PrincipalKindLocal, TokenID: sessionID.String(), AuthenticationAssurance: 1}
			for attempt := 1; attempt <= 5; attempt++ {
				err := harness.service.Reauthenticate(context.Background(), actor, CompleteReauthenticationCommand{Password: testCase.password, MFAProof: testCase.mfaProof}, harness.request)
				if !errors.Is(err, ErrLocalAuthenticationFailed) {
					t.Fatalf("attempt %d error = %v", attempt, err)
				}
			}
			credential := harness.repository.credentials[harness.userID]
			if credential.FailedAttempts != 5 || !credential.LockedUntil.Equal(harness.now.Add(5*time.Minute)) {
				t.Fatalf("lockout = %+v", credential)
			}
		})
	}
}

func TestIneligibleLocalReauthenticationHasNoEnumerationSideEffect(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*localAuthHarness, uuid.UUID)
	}{
		{name: "unknown session", mutate: func(h *localAuthHarness, id uuid.UUID) { delete(h.repository.sessions, id) }},
		{name: "revoked session", mutate: func(h *localAuthHarness, id uuid.UUID) {
			s := h.repository.sessions[id]
			s.RevokedAt = h.now.Add(-time.Second)
			h.repository.sessions[id] = s
		}},
		{name: "disabled user", mutate: func(h *localAuthHarness, _ uuid.UUID) {
			u := h.repository.users[h.userID]
			u.Status = UserStatusDisabled
			h.repository.users[h.userID] = u
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newActiveLocalAuthHarness(t, UserKindLocal, true, LoginModeLocal)
			sessionID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49003")
			harness.repository.sessions[sessionID] = validMemorySession(harness, sessionID)
			testCase.mutate(harness, sessionID)
			before := harness.repository.credentials[harness.userID]
			actor := identity.Principal{Subject: "release.operator", Kind: identity.PrincipalKindLocal, TokenID: sessionID.String(), AuthenticationAssurance: 1}
			if err := harness.service.Reauthenticate(context.Background(), actor, CompleteReauthenticationCommand{Password: "Wrong-Password-Value!", MFAProof: "654321"}, harness.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
				t.Fatalf("Reauthenticate() error = %v", err)
			}
			after := harness.repository.credentials[harness.userID]
			if after.FailedAttempts != before.FailedAttempts || !after.LockedUntil.Equal(before.LockedUntil) {
				t.Fatalf("ineligible reauthentication changed failure state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func validMemorySession(harness *localAuthHarness, sessionID uuid.UUID) Session {
	return Session{
		ID: sessionID, SubjectID: harness.userID, AuthenticationMethod: AuthenticationMethodLocal, MFALevel: 1,
		AuthenticatedAt: harness.now.Add(-time.Hour), LastUsedAt: harness.now.Add(-time.Minute),
		AbsoluteExpiresAt: harness.now.Add(time.Hour), IdleExpiresAt: harness.now.Add(time.Minute), Version: 1,
	}
}

func TestLocalLoginModeMatrixAndEmergencyEntryIsolation(t *testing.T) {
	t.Parallel()
	for _, mode := range []LoginMode{LoginModeLocal, LoginModeConfiguring, LoginModeSSO, LoginModeFault} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			local := newActiveLocalAuthHarness(t, UserKindLocal, false, mode)
			_, err := local.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Current-Strong-Password!"}, local.request)
			if mode == LoginModeLocal || mode == LoginModeConfiguring {
				if err != nil {
					t.Fatalf("LoginLocal(%s) error = %v", mode, err)
				}
			} else if !errors.Is(err, ErrLocalAuthenticationFailed) {
				t.Fatalf("LoginLocal(%s) error = %v", mode, err)
			}
			emergency := newActiveLocalAuthHarness(t, UserKindEmergency, false, mode)
			if _, err := emergency.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456"}, emergency.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
				t.Fatalf("ordinary entry authenticated emergency user: %v", err)
			}
			if _, err := emergency.service.LoginEmergency(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456"}, emergency.request); err != nil {
				t.Fatalf("LoginEmergency(%s) error = %v", mode, err)
			}
		})
	}
}

func TestLocalLoginReturnsOpaquePersistedSessionWithBoundedLifetime(t *testing.T) {
	t.Parallel()
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	result, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: " release.operator ", Password: "Current-Strong-Password!"}, harness.request)
	if err != nil {
		t.Fatalf("LoginLocal() error = %v", err)
	}
	if !strings.HasPrefix(result.AccessToken, "xms_") || result.TokenType != "Bearer" || !result.ExpiresAt.Equal(harness.now.Add(12*time.Hour)) {
		t.Fatalf("login result = %+v", result)
	}
	if result.Subject.ID != harness.userID || result.Subject.Username != "release.operator" {
		t.Fatalf("subject = %+v", result.Subject)
	}
	if len(harness.repository.sessions) != 1 {
		t.Fatalf("sessions = %+v", harness.repository.sessions)
	}
	for _, session := range harness.repository.sessions {
		want := sha256.Sum256([]byte(result.AccessToken))
		if session.TokenDigest != hex.EncodeToString(want[:]) || session.TokenDigest == result.AccessToken {
			t.Fatalf("session digest = %q", session.TokenDigest)
		}
		if !session.AbsoluteExpiresAt.Equal(harness.now.Add(12*time.Hour)) || !session.IdleExpiresAt.Equal(harness.now.Add(30*time.Minute)) {
			t.Fatalf("session expiry = %+v", session)
		}
	}
}

func TestLocalLoginRequiresMFAForEveryEnrolledUserAndDerivesSessionLevelFromUsedFactor(t *testing.T) {
	t.Run("enrolled ordinary user requires a factor", func(t *testing.T) {
		harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
		user := harness.repository.users[harness.userID]
		user.MFAEnrolled = true
		harness.repository.users[harness.userID] = user

		if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
			Username: "release.operator", Password: "Current-Strong-Password!",
		}, harness.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
			t.Fatalf("LoginLocal() error = %v, want authentication failure", err)
		}
		if len(harness.repository.sessions) != 0 {
			t.Fatalf("sessions = %+v, want none", harness.repository.sessions)
		}
	})

	t.Run("enrolled ordinary user TOTP creates level one session", func(t *testing.T) {
		harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
		user := harness.repository.users[harness.userID]
		user.MFAEnrolled = true
		harness.repository.users[harness.userID] = user

		if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
			Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456",
		}, harness.request); err != nil {
			t.Fatalf("LoginLocal() error = %v", err)
		}
		for _, session := range harness.repository.sessions {
			if session.MFALevel != 1 {
				t.Fatalf("MFA level = %d, want 1", session.MFALevel)
			}
		}
	})

	t.Run("unenrolled ordinary user accepts no factor and rejects supplied factor", func(t *testing.T) {
		harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
		if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
			Username: "release.operator", Password: "Current-Strong-Password!",
		}, harness.request); err != nil {
			t.Fatalf("LoginLocal() error = %v", err)
		}
		for _, session := range harness.repository.sessions {
			if session.MFALevel != 0 {
				t.Fatalf("MFA level = %d, want 0", session.MFALevel)
			}
		}

		withUnexpectedFactor := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
		if _, err := withUnexpectedFactor.service.LoginLocal(context.Background(), LocalLoginCommand{
			Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456",
		}, withUnexpectedFactor.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
			t.Fatalf("LoginLocal() error = %v, want authentication failure", err)
		}
	})
}

func TestLocalLoginRecoveryCodeIsAtomicSingleUseAndMutuallyExclusiveWithTOTP(t *testing.T) {
	const recoveryCode = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	user := harness.repository.users[harness.userID]
	user.MFAEnrolled = true
	harness.repository.users[harness.userID] = user
	canonical := strings.ReplaceAll(recoveryCode, "-", "")
	digest := sha256.Sum256([]byte(canonical))
	harness.repository.recoveryDigests[harness.userID] = []string{hex.EncodeToString(digest[:])}

	if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!", RecoveryCode: recoveryCode,
	}, harness.request); err != nil {
		t.Fatalf("first LoginLocal() error = %v", err)
	}
	for _, session := range harness.repository.sessions {
		if session.MFALevel != 1 {
			t.Fatalf("MFA level = %d, want 1", session.MFALevel)
		}
	}
	if !harness.repository.usedRecoveryDigests[harness.userID][hex.EncodeToString(digest[:])] {
		t.Fatal("recovery code was not consumed")
	}
	if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!", RecoveryCode: recoveryCode,
	}, harness.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("replayed LoginLocal() error = %v", err)
	}

	both := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	bothUser := both.repository.users[both.userID]
	bothUser.MFAEnrolled = true
	both.repository.users[both.userID] = bothUser
	both.repository.recoveryDigests[both.userID] = []string{hex.EncodeToString(digest[:])}
	if _, err := both.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456", RecoveryCode: recoveryCode,
	}, both.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("dual-factor LoginLocal() error = %v", err)
	}
	if both.repository.usedRecoveryDigests[both.userID][hex.EncodeToString(digest[:])] {
		t.Fatal("mutually exclusive factors consumed recovery code")
	}
}

func TestLocalLoginAuditFailureRollsBackRecoveryConsumptionAndSession(t *testing.T) {
	const recoveryCode = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	user := harness.repository.users[harness.userID]
	user.MFAEnrolled = true
	harness.repository.users[harness.userID] = user
	canonical := strings.ReplaceAll(recoveryCode, "-", "")
	digest := sha256.Sum256([]byte(canonical))
	digestString := hex.EncodeToString(digest[:])
	harness.repository.recoveryDigests[harness.userID] = []string{digestString}
	harness.auditor.failAction = "identity.local_user.login"

	if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!", RecoveryCode: recoveryCode,
	}, harness.request); err == nil {
		t.Fatal("LoginLocal() error = nil, want audit failure")
	}
	if harness.repository.usedRecoveryDigests[harness.userID][digestString] || len(harness.repository.sessions) != 0 {
		t.Fatalf("failed transaction state: used=%v sessions=%+v", harness.repository.usedRecoveryDigests, harness.repository.sessions)
	}
	harness.auditor.failAction = ""
	if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!", RecoveryCode: recoveryCode,
	}, harness.request); err != nil {
		t.Fatalf("retry LoginLocal() error = %v", err)
	}
}

func TestLocalLoginDoesNotHoldDatabaseTransactionDuringSecretResolution(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	user := harness.repository.users[harness.userID]
	user.MFAEnrolled = true
	harness.repository.users[harness.userID] = user
	entered := make(chan struct{})
	release := make(chan struct{})
	harness.service.mfa = blockingMFAVerifier{entered: entered, release: release}
	done := make(chan error, 1)
	go func() {
		_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
			Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456",
		}, harness.request)
		done <- err
	}()
	<-entered
	if !harness.repository.mu.TryLock() {
		close(release)
		<-done
		t.Fatal("database transaction lock was held while MFA secret was resolved")
	}
	harness.repository.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("LoginLocal() error = %v", err)
	}
}

func TestLocalLoginUsesUnifiedFailureAndProgressivePersistentLockout(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	harness.service.policy.LockoutStages = []LockoutStage{
		{FailedAttempts: 3, Duration: 2 * time.Minute},
		{FailedAttempts: 5, Duration: 15 * time.Minute},
		{FailedAttempts: 7, Duration: 2 * time.Hour},
	}
	for attempt := 1; attempt <= 7; attempt++ {
		_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, harness.request)
		if !errors.Is(err, ErrLocalAuthenticationFailed) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
		credential := harness.repository.credentials[harness.userID]
		if credential.FailedAttempts != attempt {
			t.Fatalf("attempt %d persisted count = %d", attempt, credential.FailedAttempts)
		}
		switch attempt {
		case 3:
			if !credential.LockedUntil.Equal(harness.now.Add(2 * time.Minute)) {
				t.Fatalf("three-attempt lock = %s", credential.LockedUntil)
			}
		case 5:
			if !credential.LockedUntil.Equal(harness.now.Add(15 * time.Minute)) {
				t.Fatalf("five-attempt lock = %s", credential.LockedUntil)
			}
		case 7:
			if !credential.LockedUntil.Equal(harness.now.Add(2 * time.Hour)) {
				t.Fatalf("seven-attempt lock = %s", credential.LockedUntil)
			}
		}
		if credential.LockedUntil.After(harness.now) {
			*harness.clock = credential.LockedUntil.Add(time.Second)
			harness.now = *harness.clock
		}
	}
	if len(harness.auditor.commands) != 14 {
		t.Fatalf("failed login audit count = %d", len(harness.auditor.commands))
	}
}

func TestLocalAuthPolicyRejectsUnsafeLockoutStageOrderingAndBounds(t *testing.T) {
	valid := DefaultLocalAuthPolicy()
	if !validLocalAuthPolicy(valid) {
		t.Fatal("default local authentication policy is invalid")
	}
	for name, stages := range map[string][]LockoutStage{
		"too few attempts":        {{FailedAttempts: 2, Duration: time.Minute}},
		"too many attempts":       {{FailedAttempts: 51, Duration: time.Minute}},
		"duration too short":      {{FailedAttempts: 3, Duration: 30 * time.Second}},
		"duration too long":       {{FailedAttempts: 3, Duration: 25 * time.Hour}},
		"duplicate threshold":     {{FailedAttempts: 3, Duration: time.Minute}, {FailedAttempts: 3, Duration: 2 * time.Minute}},
		"non increasing duration": {{FailedAttempts: 3, Duration: 5 * time.Minute}, {FailedAttempts: 5, Duration: 5 * time.Minute}},
		"too many stages": {
			{FailedAttempts: 3, Duration: time.Minute}, {FailedAttempts: 4, Duration: 2 * time.Minute},
			{FailedAttempts: 5, Duration: 3 * time.Minute}, {FailedAttempts: 6, Duration: 4 * time.Minute},
			{FailedAttempts: 7, Duration: 5 * time.Minute}, {FailedAttempts: 8, Duration: 6 * time.Minute},
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := DefaultLocalAuthPolicy()
			policy.LockoutStages = stages
			if validLocalAuthPolicy(policy) {
				t.Fatalf("unsafe lockout stages accepted: %+v", stages)
			}
		})
	}
}

func TestLocalLoginRejectsEveryAccountStateWithOneExternalFailure(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*localAuthHarness){
		"pending": func(harness *localAuthHarness) {
			user := harness.repository.users[harness.userID]
			user.Status = UserStatusPending
			harness.repository.users[harness.userID] = user
		},
		"disabled": func(harness *localAuthHarness) {
			user := harness.repository.users[harness.userID]
			user.Status = UserStatusDisabled
			user.DisabledAt = harness.now.Add(-time.Minute)
			harness.repository.users[harness.userID] = user
		},
		"locked": func(harness *localAuthHarness) {
			credential := harness.repository.credentials[harness.userID]
			credential.LockedUntil = harness.now.Add(time.Minute)
			harness.repository.credentials[harness.userID] = credential
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
			mutate(harness)
			_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Current-Strong-Password!"}, harness.request)
			if !errors.Is(err, ErrLocalAuthenticationFailed) {
				t.Fatalf("LoginLocal(%s) error = %v", name, err)
			}
		})
	}
}

func TestIneligibleLocalLoginCannotIncreasePersistentFailureState(t *testing.T) {
	for name, testCase := range map[string]struct {
		setup func(*localAuthHarness)
		login func(*localAuthHarness) error
	}{
		"wrong entry": {
			setup: func(harness *localAuthHarness) {
				user := harness.repository.users[harness.userID]
				user.Kind = UserKindEmergency
				harness.repository.users[harness.userID] = user
			},
			login: func(harness *localAuthHarness) error {
				_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, harness.request)
				return err
			},
		},
		"SSO mode": {
			setup: func(harness *localAuthHarness) { harness.repository.login.Mode = LoginModeSSO },
			login: func(harness *localAuthHarness) error {
				_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, harness.request)
				return err
			},
		},
		"pending": {
			setup: func(harness *localAuthHarness) {
				user := harness.repository.users[harness.userID]
				user.Status = UserStatusPending
				harness.repository.users[harness.userID] = user
			},
			login: func(harness *localAuthHarness) error {
				_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, harness.request)
				return err
			},
		},
		"disabled": {
			setup: func(harness *localAuthHarness) {
				user := harness.repository.users[harness.userID]
				user.Status = UserStatusDisabled
				harness.repository.users[harness.userID] = user
			},
			login: func(harness *localAuthHarness) error {
				_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, harness.request)
				return err
			},
		},
		"already locked": {
			setup: func(harness *localAuthHarness) {
				credential := harness.repository.credentials[harness.userID]
				credential.FailedAttempts = 5
				credential.LockedUntil = harness.now.Add(5 * time.Minute)
				harness.repository.credentials[harness.userID] = credential
			},
			login: func(harness *localAuthHarness) error {
				for range 10 {
					if _, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, harness.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
						return err
					}
				}
				return ErrLocalAuthenticationFailed
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
			testCase.setup(harness)
			before := harness.repository.credentials[harness.userID]
			if err := testCase.login(harness); !errors.Is(err, ErrLocalAuthenticationFailed) {
				t.Fatalf("login error = %v", err)
			}
			after := harness.repository.credentials[harness.userID]
			if after.FailedAttempts != before.FailedAttempts || !after.LockedUntil.Equal(before.LockedUntil) {
				t.Fatalf("ineligible login changed failure state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestEligibleMFAAuthenticationFailuresApplyProgressiveLockout(t *testing.T) {
	for _, account := range []struct {
		name  string
		kind  UserKind
		admin bool
		login func(*localAuthHarness, LocalLoginCommand) error
	}{
		{
			name: "local administrator", kind: UserKindLocal, admin: true,
			login: func(harness *localAuthHarness, command LocalLoginCommand) error {
				_, err := harness.service.LoginLocal(context.Background(), command, harness.request)
				return err
			},
		},
		{
			name: "emergency account", kind: UserKindEmergency,
			login: func(harness *localAuthHarness, command LocalLoginCommand) error {
				_, err := harness.service.LoginEmergency(context.Background(), command, harness.request)
				return err
			},
		},
	} {
		for _, failure := range []struct {
			name        string
			proof       string
			lastCounter int64
		}{
			{name: "missing proof", proof: "", lastCounter: 41},
			{name: "invalid proof", proof: "654321", lastCounter: 41},
			{name: "counter replay", proof: "123456", lastCounter: 42},
		} {
			t.Run(account.name+"/"+failure.name, func(t *testing.T) {
				harness := newActiveLocalAuthHarness(t, account.kind, account.admin, LoginModeLocal)
				credential := harness.repository.credentials[harness.userID]
				credential.MFALastCounter = failure.lastCounter
				harness.repository.credentials[harness.userID] = credential
				for attempt := 1; attempt <= 5; attempt++ {
					err := account.login(harness, LocalLoginCommand{
						Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: failure.proof,
					})
					if !errors.Is(err, ErrLocalAuthenticationFailed) {
						t.Fatalf("attempt %d error = %v", attempt, err)
					}
				}
				credential = harness.repository.credentials[harness.userID]
				if credential.FailedAttempts != 5 || !credential.LockedUntil.Equal(harness.now.Add(5*time.Minute)) {
					t.Fatalf("MFA failure lockout state = attempts:%d locked_until:%s", credential.FailedAttempts, credential.LockedUntil)
				}
			})
		}
	}
}

func TestLocalLoginEnforcesPersistentAccountAndIPLimitsWithoutSkippingAudit(t *testing.T) {
	t.Parallel()
	account := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	for attempt := 1; attempt <= 16; attempt++ {
		_, err := account.service.LoginLocal(context.Background(), LocalLoginCommand{Username: "release.operator", Password: "Wrong-Password-Value!"}, account.request)
		if attempt <= 15 && !errors.Is(err, ErrLocalAuthenticationFailed) {
			t.Fatalf("account attempt %d error = %v", attempt, err)
		}
		if attempt == 16 && !errors.Is(err, ErrLocalAuthenticationLimited) {
			t.Fatalf("account limit error = %v", err)
		}
	}
	if len(account.auditor.commands) != 31 {
		t.Fatalf("account limit audit count = %d", len(account.auditor.commands))
	}
	ip := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	for attempt := 1; attempt <= 61; attempt++ {
		username := "unknown." + time.Unix(int64(attempt), 0).UTC().Format("150405")
		_, err := ip.service.LoginLocal(context.Background(), LocalLoginCommand{Username: username, Password: "Wrong-Password-Value!"}, ip.request)
		if attempt == 61 && !errors.Is(err, ErrLocalAuthenticationLimited) {
			t.Fatalf("IP limit error = %v", err)
		}
	}
	if len(ip.auditor.commands) != 121 {
		t.Fatalf("IP limit audit count = %d", len(ip.auditor.commands))
	}
}

func TestIPLimitBoundsAnonymousAccountKeyCardinality(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	harness.service.policy.IPLimit = 10
	harness.service.policy.AccountLimit = 1000
	for attempt := 1; attempt <= 50; attempt++ {
		username := fmt.Sprintf("anonymous-%03d", attempt)
		_, _ = harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: username, Password: "Wrong-Password-Value!"}, harness.request)
	}
	accountKeys, ipKeys := 0, 0
	for key := range harness.repository.rateLimits {
		if strings.HasPrefix(key, string(RateLimitScopeAccount)+":") {
			accountKeys++
		}
		if strings.HasPrefix(key, string(RateLimitScopeIP)+":") {
			ipKeys++
		}
	}
	if accountKeys != 10 || ipKeys != 1 {
		t.Fatalf("rate-limit keys: account=%d ip=%d", accountKeys, ipKeys)
	}
}

func TestAuthenticationAttemptAuditFailureRollsBackRateLimitState(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	auditFailure := errors.New("audit unavailable")
	harness.auditor.err = auditFailure
	_, err := harness.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Wrong-Password-Value!",
	}, harness.request)
	if !errors.Is(err, auditFailure) {
		t.Fatalf("LoginLocal() error = %v", err)
	}
	if len(harness.repository.rateLimits) != 0 {
		t.Fatalf("audit failure committed rate-limit state: %+v", harness.repository.rateLimits)
	}
}

func TestAuthenticationAttemptPerformsBoundedExpiredRateLimitCleanup(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	for index := range 1000 {
		harness.repository.rateLimits[fmt.Sprintf("expired:%04d", index)] = memoryRateWindow{
			startedAt: harness.now.Add(-2 * time.Hour), expiresAt: harness.now.Add(-time.Hour), count: 1,
		}
	}
	for index := range 20 {
		harness.repository.rateLimits[fmt.Sprintf("current:%04d", index)] = memoryRateWindow{
			startedAt: harness.now, expiresAt: harness.now.Add(time.Hour), count: 1,
		}
	}
	_, _ = harness.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "unknown.operator", Password: "Wrong-Password-Value!",
	}, harness.request)
	expired, current := 0, 0
	for _, window := range harness.repository.rateLimits {
		if !window.expiresAt.After(harness.now) {
			expired++
		} else {
			current++
		}
	}
	if expired <= 0 || expired >= 1000 || current != 22 {
		t.Fatalf("bounded cleanup result: expired=%d current=%d", expired, current)
	}
}

func TestAdministratorLoginRejectsReplayedMFAProof(t *testing.T) {
	t.Parallel()
	harness := newActiveLocalAuthHarness(t, UserKindLocal, true, LoginModeLocal)
	command := LocalLoginCommand{Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456"}
	if _, err := harness.service.LoginLocal(context.Background(), command, harness.request); err != nil {
		t.Fatalf("LoginLocal(first MFA) error = %v", err)
	}
	if _, err := harness.service.LoginLocal(context.Background(), command, harness.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("LoginLocal(replayed MFA) error = %v", err)
	}
}

func TestEmergencyLoginUsesDistinctNonSensitiveAuditIdentity(t *testing.T) {
	harness := newActiveLocalAuthHarness(t, UserKindEmergency, false, LoginModeFault)
	if _, err := harness.service.LoginEmergency(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!", MFAProof: "123456",
	}, harness.request); err != nil {
		t.Fatalf("LoginEmergency() error = %v", err)
	}
	command := harness.auditor.commands[len(harness.auditor.commands)-1]
	if command.Action != "identity.emergency.login" || command.Metadata["entrypoint"] != "emergency" {
		t.Fatalf("emergency audit = %+v", command)
	}
	for _, sensitive := range []string{"password", "mfa_proof", "mfa_secret_reference"} {
		if _, exists := command.Metadata[sensitive]; exists {
			t.Fatalf("emergency audit exposed %s: %+v", sensitive, command.Metadata)
		}
	}
}

func TestActivateLocalAccountConsumesDigestAndPersistsPasswordHistory(t *testing.T) {
	t.Parallel()

	harness := newLocalAuthHarness(t, UserKindLocal, false)
	err := harness.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: harness.activationToken,
		NewPassword:     "A-Strong-Local-Password!",
	}, harness.request)
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	user := harness.repository.users[harness.userID]
	credential := harness.repository.credentials[harness.userID]
	if user.Status != UserStatusActive || user.Version != 2 || !user.CredentialRotatedAt.Equal(harness.now) {
		t.Fatalf("activated user = %+v", user)
	}
	if credential.ActivationDigest != "" || !credential.ActivationExpiresAt.IsZero() || credential.Password.Algorithm != "argon2id" {
		t.Fatalf("activated credential = %+v", credential)
	}
	if err := harness.passwords.Verify("A-Strong-Local-Password!", credential.Password); err != nil {
		t.Fatalf("stored password cannot be verified: %v", err)
	}
	if len(harness.repository.history[harness.userID]) != 1 {
		t.Fatalf("password history = %+v", harness.repository.history[harness.userID])
	}
	if len(harness.auditor.commands) != 1 || harness.auditor.commands[0].Action != "identity.local_user.activate" {
		t.Fatalf("audit commands = %+v", harness.auditor.commands)
	}
	if _, leaked := harness.auditor.commands[0].Metadata["activation_token"]; leaked {
		t.Fatal("activation token leaked into audit metadata")
	}
	if err := harness.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: harness.activationToken, NewPassword: "Another-Strong-Password!",
	}, harness.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("Activate(reused token) error = %v", err)
	}
}

func TestActivateLocalAccountFailsClosedForExpiredTokenAndPasswordHistory(t *testing.T) {
	t.Parallel()

	expired := newLocalAuthHarness(t, UserKindLocal, false)
	expired.repository.credentials[expired.userID] = withActivationExpiry(expired.repository.credentials[expired.userID], expired.now.Add(-time.Second))
	if err := expired.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: expired.activationToken, NewPassword: "A-Strong-Local-Password!",
	}, expired.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("Activate(expired) error = %v", err)
	}

	reused := newLocalAuthHarness(t, UserKindLocal, false)
	reusedDigest, err := reused.passwords.Hash(context.Background(), "Previously-Used-Password!")
	if err != nil {
		t.Fatal(err)
	}
	reused.repository.history[reused.userID] = []PasswordDigest{reusedDigest}
	if err := reused.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: reused.activationToken, NewPassword: "Previously-Used-Password!",
	}, reused.request); !errors.Is(err, ErrPasswordRecentlyUsed) {
		t.Fatalf("Activate(reused password) error = %v", err)
	}
	if reused.repository.users[reused.userID].Status != UserStatusPending {
		t.Fatal("password-history rejection changed user state")
	}
}

func TestActivateAdministratorRequiresNonReplayableMFAEnrollment(t *testing.T) {
	t.Parallel()

	harness := newLocalAuthHarness(t, UserKindLocal, true)
	enrollmentID := seedActivationMFAEnrollment(t, harness)
	command := ActivateLocalAccountCommand{
		ActivationToken: harness.activationToken,
		NewPassword:     "A-Strong-Admin-Password!",
		MFAEnrollmentID: enrollmentID,
		MFAProof:        "123456",
	}
	result, err := harness.service.ActivateWithResult(context.Background(), command, harness.request)
	if err != nil {
		t.Fatalf("Activate(admin) error = %v", err)
	}
	user := harness.repository.users[harness.userID]
	credential := harness.repository.credentials[harness.userID]
	wantReference := "secret://iam-mfa/mfa-" + enrollmentID.String() + ".totp"
	if !user.MFAEnrolled || credential.MFASecretReference != wantReference || credential.MFALastCounter != 42 || len(result.RecoveryCodes) != 10 || len(harness.repository.recoveryDigests[harness.userID]) != 10 {
		t.Fatalf("MFA activation state = user=%+v credential=%+v", user, credential)
	}
	for _, code := range result.RecoveryCodes {
		if len(strings.ReplaceAll(code, "-", "")) != 24 || code != strings.ToUpper(code) {
			t.Fatalf("invalid recovery code format=%q", code)
		}
	}

	missing := newLocalAuthHarness(t, UserKindEmergency, false)
	if err := missing.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: missing.activationToken, NewPassword: "A-Strong-Emergency-Password!",
	}, missing.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("Activate(emergency without MFA) error = %v", err)
	}
}

func TestLocalActivationDoesNotHoldDatabaseTransactionDuringSecretResolution(t *testing.T) {
	harness := newLocalAuthHarness(t, UserKindEmergency, true)
	enrollmentID := seedActivationMFAEnrollment(t, harness)
	entered := make(chan struct{})
	release := make(chan struct{})
	harness.service.mfa = blockingMFAVerifier{entered: entered, release: release}
	done := make(chan error, 1)
	go func() {
		_, err := harness.service.ActivateWithResult(context.Background(), ActivateLocalAccountCommand{
			ActivationToken: harness.activationToken, NewPassword: "A-Different-Strong-Password!",
			MFAEnrollmentID: enrollmentID, MFAProof: "123456",
		}, harness.request)
		done <- err
	}()
	<-entered
	if !harness.repository.mu.TryLock() {
		close(release)
		<-done
		t.Fatal("database transaction lock was held while MFA secret was resolved")
	}
	harness.repository.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("ActivateWithResult() error = %v", err)
	}
}

func seedActivationMFAEnrollment(t *testing.T, harness *localAuthHarness) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	harness.repository.enrollments[id] = MFAEnrollment{
		ID: id, UserID: harness.userID, Purpose: MFAEnrollmentPurposeActivation, Status: MFAEnrollmentStatusPending,
		SecretReference: "secret://iam-mfa/mfa-" + id.String() + ".totp", ExpectedUserVersion: 1,
		ExpiresAt: harness.now.Add(10 * time.Minute), Version: 1, CreatedAt: harness.now, UpdatedAt: harness.now,
	}
	return id
}

func TestActivateLocalAccountAllowsOnlyOneConcurrentConsumer(t *testing.T) {
	harness := newLocalAuthHarness(t, UserKindLocal, false)
	start := make(chan struct{})
	errorsChannel := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errorsChannel <- harness.service.Activate(context.Background(), ActivateLocalAccountCommand{
				ActivationToken: harness.activationToken, NewPassword: "A-Strong-Local-Password!",
			}, harness.request)
		}()
	}
	close(start)
	succeeded, rejected := 0, 0
	for range 2 {
		err := <-errorsChannel
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrLocalAuthenticationFailed):
			rejected++
		default:
			t.Fatalf("Activate(concurrent) error = %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent results: success=%d rejected=%d", succeeded, rejected)
	}
}

func TestActivateLocalAccountRollsBackPartialRepositoryConflict(t *testing.T) {
	t.Parallel()
	harness := newLocalAuthHarness(t, UserKindLocal, false)
	harness.repository.failActivationAfterUserUpdate = true
	err := harness.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: harness.activationToken, NewPassword: "A-Strong-Local-Password!",
	}, harness.request)
	if !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("Activate(conflict) error = %v", err)
	}
	if harness.repository.users[harness.userID].Status != UserStatusPending || harness.repository.credentials[harness.userID].ActivationDigest == "" {
		t.Fatalf("partial activation committed: user=%+v credential=%+v", harness.repository.users[harness.userID], harness.repository.credentials[harness.userID])
	}
}

func TestLocalAuthenticationDoesNotMaskRepositoryFailuresAsCredentials(t *testing.T) {
	t.Parallel()
	infrastructureFailure := errors.New("database unavailable")
	activation := newLocalAuthHarness(t, UserKindLocal, false)
	activation.repository.findActivationError = infrastructureFailure
	if err := activation.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: activation.activationToken, NewPassword: "A-Strong-Local-Password!",
	}, activation.request); !errors.Is(err, infrastructureFailure) {
		t.Fatalf("Activate(repository failure) error = %v", err)
	}
	login := newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal)
	login.repository.findLoginError = infrastructureFailure
	if _, err := login.service.LoginLocal(context.Background(), LocalLoginCommand{
		Username: "release.operator", Password: "Current-Strong-Password!",
	}, login.request); !errors.Is(err, infrastructureFailure) {
		t.Fatalf("LoginLocal(repository failure) error = %v", err)
	}
}

func TestUnknownAndIneligibleAuthenticationUsesComparableArgon2Cost(t *testing.T) {
	manager, err := NewPasswordManager(PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, staticBreachChecker(false))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := manager.Hash(context.Background(), "Current-Strong-Password!")
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := NewDummyPasswordDigest(context.Background(), manager)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := func(username string, mode LoginMode) time.Duration {
		harness := newActiveLocalAuthHarness(t, UserKindLocal, false, mode)
		harness.service.passwords = manager
		harness.service.dummyPassword = dummy
		credential := harness.repository.credentials[harness.userID]
		credential.Password = actual
		harness.repository.credentials[harness.userID] = credential
		started := time.Now()
		for range 3 {
			_, _ = harness.service.LoginLocal(context.Background(), LocalLoginCommand{Username: username, Password: "Wrong-Password-Value!"}, harness.request)
		}
		return time.Since(started)
	}
	credentialFailure := elapsed("release.operator", LoginModeLocal)
	for name, duration := range map[string]time.Duration{
		"unknown account": elapsed("unknown.operator", LoginModeLocal),
		"SSO rejected":    elapsed("release.operator", LoginModeSSO),
	} {
		if duration*4 < credentialFailure || credentialFailure*4 < duration {
			t.Fatalf("%s Argon2 cost = %s, credential failure = %s", name, duration, credentialFailure)
		}
	}
}

type localAuthHarness struct {
	service         *LocalAuthService
	repository      *memoryLocalAuthRepository
	passwords       *testPasswordManager
	auditor         *lockedAuditRecorder
	now             time.Time
	clock           *time.Time
	userID          uuid.UUID
	activationToken string
	request         RequestContext
}

func newLocalAuthHarness(t *testing.T, kind UserKind, admin bool) *localAuthHarness {
	t.Helper()
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	clock := now
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49001")
	activationToken := "activation-token-with-at-least-256-bits-of-test-entropy"
	digest := sha256.Sum256([]byte(activationToken))
	repository := &memoryLocalAuthRepository{
		login: LoginState{Mode: LoginModeLocal, Version: 1},
		users: map[uuid.UUID]UserPrincipal{userID: {
			ID: userID, Username: "release.operator", DisplayName: "Release Operator", Kind: kind,
			Status: UserStatusPending, Version: 1, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
		}},
		credentials: map[uuid.UUID]LocalCredential{userID: {
			UserID: userID, ActivationDigest: hex.EncodeToString(digest[:]), ActivationExpiresAt: now.Add(time.Hour),
		}},
		history:             map[uuid.UUID][]PasswordDigest{},
		admins:              map[uuid.UUID]bool{userID: admin},
		rateLimits:          map[string]memoryRateWindow{},
		sessions:            map[uuid.UUID]Session{},
		enrollments:         map[uuid.UUID]MFAEnrollment{},
		recoveryDigests:     map[uuid.UUID][]string{},
		usedRecoveryDigests: map[uuid.UUID]map[string]bool{},
		mfaTombstones:       map[string]bool{},
	}
	passwords := &testPasswordManager{}
	dummyPassword, err := passwords.Hash(context.Background(), "Dummy-Authentication-Password!")
	if err != nil {
		t.Fatal(err)
	}
	auditor := &lockedAuditRecorder{}
	service, err := NewLocalAuthService(LocalAuthConfig{
		Repository:    repository,
		Auditor:       auditor,
		Passwords:     passwords,
		DummyPassword: dummyPassword,
		MFA:           fixedMFAVerifier{proof: "123456", counter: 42},
		Policy:        DefaultLocalAuthPolicy(),
		Clock:         func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &localAuthHarness{
		service: service, repository: repository, passwords: passwords, auditor: auditor, now: now, clock: &clock,
		userID: userID, activationToken: activationToken,
		request: RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f49002", SourceIP: "192.0.2.10"},
	}
}

func newActiveLocalAuthHarness(t *testing.T, kind UserKind, admin bool, mode LoginMode) *localAuthHarness {
	t.Helper()
	harness := newLocalAuthHarness(t, kind, admin)
	digest, err := harness.passwords.Hash(context.Background(), "Current-Strong-Password!")
	if err != nil {
		t.Fatal(err)
	}
	user := harness.repository.users[harness.userID]
	user.Status = UserStatusActive
	user.MFAEnrolled = kind == UserKindEmergency || admin
	user.CredentialRotatedAt = harness.now.Add(-time.Hour)
	harness.repository.users[harness.userID] = user
	credential := harness.repository.credentials[harness.userID]
	credential.Password = digest
	credential.PasswordChangedAt = harness.now.Add(-time.Hour)
	credential.ActivationDigest = ""
	credential.ActivationExpiresAt = time.Time{}
	credential.MFASecretReference = "secret://iam/admin-totp"
	credential.MFALastCounter = 41
	harness.repository.credentials[harness.userID] = credential
	harness.repository.login.Mode = mode
	return harness
}

func withActivationExpiry(credential LocalCredential, expiry time.Time) LocalCredential {
	credential.ActivationExpiresAt = expiry
	return credential
}

type memoryLocalAuthRepository struct {
	mu                            sync.Mutex
	login                         LoginState
	users                         map[uuid.UUID]UserPrincipal
	credentials                   map[uuid.UUID]LocalCredential
	history                       map[uuid.UUID][]PasswordDigest
	admins                        map[uuid.UUID]bool
	rateLimits                    map[string]memoryRateWindow
	sessions                      map[uuid.UUID]Session
	enrollments                   map[uuid.UUID]MFAEnrollment
	recoveryDigests               map[uuid.UUID][]string
	usedRecoveryDigests           map[uuid.UUID]map[string]bool
	mfaTombstones                 map[string]bool
	failActivationAfterUserUpdate bool
	findActivationError           error
	findLoginError                error
}

type memoryRateWindow struct {
	startedAt time.Time
	expiresAt time.Time
	count     int
}

func (repository *memoryLocalAuthRepository) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	users := cloneUsers(repository.users)
	credentials := cloneCredentials(repository.credentials)
	history := cloneHistory(repository.history)
	rateLimits := cloneRateLimits(repository.rateLimits)
	sessions := cloneSessions(repository.sessions)
	enrollments := cloneMFAEnrollments(repository.enrollments)
	recoveryDigests := cloneStringSlices(repository.recoveryDigests)
	usedRecoveryDigests := cloneRecoveryUsage(repository.usedRecoveryDigests)
	err := function(nil)
	if err != nil {
		repository.users = users
		repository.credentials = credentials
		repository.history = history
		repository.rateLimits = rateLimits
		repository.sessions = sessions
		repository.enrollments = enrollments
		repository.recoveryDigests = recoveryDigests
		repository.usedRecoveryDigests = usedRecoveryDigests
	}
	return err
}

func cloneRecoveryUsage(source map[uuid.UUID]map[string]bool) map[uuid.UUID]map[string]bool {
	result := make(map[uuid.UUID]map[string]bool, len(source))
	for userID, digests := range source {
		result[userID] = make(map[string]bool, len(digests))
		for digest, used := range digests {
			result[userID][digest] = used
		}
	}
	return result
}

func cloneMFAEnrollments(source map[uuid.UUID]MFAEnrollment) map[uuid.UUID]MFAEnrollment {
	result := make(map[uuid.UUID]MFAEnrollment, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneStringSlices(source map[uuid.UUID][]string) map[uuid.UUID][]string {
	result := make(map[uuid.UUID][]string, len(source))
	for key, value := range source {
		result[key] = append([]string(nil), value...)
	}
	return result
}

func cloneSessions(source map[uuid.UUID]Session) map[uuid.UUID]Session {
	result := make(map[uuid.UUID]Session, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneRateLimits(source map[string]memoryRateWindow) map[string]memoryRateWindow {
	result := make(map[string]memoryRateWindow, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (repository *memoryLocalAuthRepository) FindActivation(_ context.Context, _ pgx.Tx, digest string) (UserPrincipal, LocalCredential, []PasswordDigest, bool, error) {
	if repository.findActivationError != nil {
		return UserPrincipal{}, LocalCredential{}, nil, false, repository.findActivationError
	}
	for id, credential := range repository.credentials {
		if credential.ActivationDigest == digest {
			return repository.users[id], credential, append([]PasswordDigest(nil), repository.history[id]...), repository.admins[id], nil
		}
	}
	return UserPrincipal{}, LocalCredential{}, nil, false, ErrLocalAuthenticationFailed
}

func (repository *memoryLocalAuthRepository) SaveActivation(_ context.Context, _ pgx.Tx, user UserPrincipal, credential LocalCredential, history PasswordDigest, expectedVersion int64) error {
	current := repository.users[user.ID]
	if current.Version != expectedVersion || current.Status != UserStatusPending || repository.credentials[user.ID].ActivationDigest == "" {
		return ErrLocalAuthenticationFailed
	}
	if repository.failActivationAfterUserUpdate {
		repository.users[user.ID] = user
		return ErrIAMConflict
	}
	repository.users[user.ID] = user
	repository.credentials[user.ID] = credential
	repository.history[user.ID] = append([]PasswordDigest{history}, repository.history[user.ID]...)
	return nil
}

func (repository *memoryLocalAuthRepository) GetMFAEnrollmentForUpdate(_ context.Context, _ pgx.Tx, enrollmentID uuid.UUID) (MFAEnrollment, error) {
	enrollment, exists := repository.enrollments[enrollmentID]
	if !exists {
		return MFAEnrollment{}, ErrMFAEnrollmentNotFound
	}
	return enrollment, nil
}

func (repository *memoryLocalAuthRepository) GetMFAActivationPreflight(_ context.Context, activationDigest string, enrollmentID uuid.UUID) (MFAEnrollment, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	enrollment, exists := repository.enrollments[enrollmentID]
	if !exists || repository.credentials[enrollment.UserID].ActivationDigest != activationDigest {
		return MFAEnrollment{}, ErrMFAEnrollmentNotFound
	}
	return enrollment, nil
}

func (*memoryLocalAuthRepository) LockMFASecretReference(context.Context, pgx.Tx, string) error {
	return nil
}

func (repository *memoryLocalAuthRepository) MFASecretReferenceHasTombstone(_ context.Context, _ pgx.Tx, reference string) (bool, error) {
	return repository.mfaTombstones[reference], nil
}

func (repository *memoryLocalAuthRepository) ConfirmMFAEnrollment(_ context.Context, _ pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, confirmedAt time.Time) error {
	enrollment, exists := repository.enrollments[enrollmentID]
	if !exists || enrollment.Status != MFAEnrollmentStatusPending || enrollment.Version != expectedVersion || !enrollment.ExpiresAt.After(confirmedAt) {
		return ErrIAMConflict
	}
	enrollment.Status = MFAEnrollmentStatusConfirmed
	enrollment.ConfirmedAt = confirmedAt
	enrollment.UpdatedAt = confirmedAt
	enrollment.Version++
	repository.enrollments[enrollmentID] = enrollment
	return nil
}

func (repository *memoryLocalAuthRepository) ReplaceMFARecoveryCodes(_ context.Context, _ pgx.Tx, userID, _ uuid.UUID, digests []string, _ time.Time) error {
	repository.recoveryDigests[userID] = append([]string(nil), digests...)
	repository.usedRecoveryDigests[userID] = map[string]bool{}
	return nil
}

func (repository *memoryLocalAuthRepository) ConsumeMFARecoveryCode(_ context.Context, _ pgx.Tx, userID uuid.UUID, digest string, _ time.Time) (bool, error) {
	found := false
	for _, candidate := range repository.recoveryDigests[userID] {
		if candidate == digest {
			found = true
			break
		}
	}
	if !found || repository.usedRecoveryDigests[userID][digest] {
		return false, nil
	}
	if repository.usedRecoveryDigests[userID] == nil {
		repository.usedRecoveryDigests[userID] = map[string]bool{}
	}
	repository.usedRecoveryDigests[userID][digest] = true
	return true, nil
}

func cloneUsers(source map[uuid.UUID]UserPrincipal) map[uuid.UUID]UserPrincipal {
	result := make(map[uuid.UUID]UserPrincipal, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneCredentials(source map[uuid.UUID]LocalCredential) map[uuid.UUID]LocalCredential {
	result := make(map[uuid.UUID]LocalCredential, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneHistory(source map[uuid.UUID][]PasswordDigest) map[uuid.UUID][]PasswordDigest {
	result := make(map[uuid.UUID][]PasswordDigest, len(source))
	for key, value := range source {
		result[key] = append([]PasswordDigest(nil), value...)
	}
	return result
}

func (repository *memoryLocalAuthRepository) FindLogin(_ context.Context, _ pgx.Tx, username string) (LoginState, UserPrincipal, LocalCredential, bool, error) {
	if repository.findLoginError != nil {
		return repository.login, UserPrincipal{}, LocalCredential{}, false, repository.findLoginError
	}
	for id, user := range repository.users {
		if user.Username == username {
			return repository.login, user, repository.credentials[id], repository.admins[id], nil
		}
	}
	return repository.login, UserPrincipal{}, LocalCredential{}, false, ErrLocalAuthenticationFailed
}

func (repository *memoryLocalAuthRepository) FindLoginPreflight(_ context.Context, username string) (LoginState, UserPrincipal, LocalCredential, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.FindLogin(context.Background(), nil, username)
}

func (repository *memoryLocalAuthRepository) FindLocalReauthentication(_ context.Context, _ pgx.Tx, username string, sessionID uuid.UUID) (LoginState, UserPrincipal, LocalCredential, Session, bool, error) {
	if repository.findLoginError != nil {
		return repository.login, UserPrincipal{}, LocalCredential{}, Session{}, false, repository.findLoginError
	}
	for id, user := range repository.users {
		if user.Username == username {
			session, exists := repository.sessions[sessionID]
			if !exists {
				return repository.login, UserPrincipal{}, LocalCredential{}, Session{}, false, ErrLocalAuthenticationFailed
			}
			return repository.login, user, repository.credentials[id], session, repository.admins[id], nil
		}
	}
	return repository.login, UserPrincipal{}, LocalCredential{}, Session{}, false, ErrLocalAuthenticationFailed
}

func (repository *memoryLocalAuthRepository) FindLocalReauthenticationPreflight(_ context.Context, username string, sessionID uuid.UUID) (LoginState, UserPrincipal, LocalCredential, Session, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.FindLocalReauthentication(context.Background(), nil, username, sessionID)
}

func (repository *memoryLocalAuthRepository) ConsumeRateLimit(_ context.Context, _ pgx.Tx, scope RateLimitScope, keyDigest string, windowStart time.Time, limit int, expiresAt time.Time) (bool, error) {
	key := string(scope) + ":" + keyDigest
	window := repository.rateLimits[key]
	if !window.startedAt.Equal(windowStart) {
		window = memoryRateWindow{startedAt: windowStart, expiresAt: expiresAt}
	}
	window.count++
	repository.rateLimits[key] = window
	return window.count <= limit, nil
}

func (repository *memoryLocalAuthRepository) CleanupExpiredRateLimits(_ context.Context, _ pgx.Tx, before time.Time, limit int) (int64, error) {
	var removed int64
	for key, window := range repository.rateLimits {
		if removed >= int64(limit) {
			break
		}
		if !window.expiresAt.After(before) {
			delete(repository.rateLimits, key)
			removed++
		}
	}
	return removed, nil
}

func (repository *memoryLocalAuthRepository) SaveAuthenticationFailure(_ context.Context, _ pgx.Tx, userID uuid.UUID, failedAttempts int, lockedUntil time.Time) error {
	credential := repository.credentials[userID]
	credential.FailedAttempts = failedAttempts
	credential.LockedUntil = lockedUntil
	repository.credentials[userID] = credential
	return nil
}

func (repository *memoryLocalAuthRepository) SaveAuthenticationSuccess(_ context.Context, _ pgx.Tx, userID uuid.UUID, mfaCounter int64, session Session) error {
	credential := repository.credentials[userID]
	credential.FailedAttempts = 0
	credential.LockedUntil = time.Time{}
	if mfaCounter > 0 {
		credential.MFALastCounter = mfaCounter
	}
	repository.credentials[userID] = credential
	repository.sessions[session.ID] = session
	return nil
}

func (repository *memoryLocalAuthRepository) SaveReauthenticationSuccess(_ context.Context, _ pgx.Tx, userID uuid.UUID, mfaCounter int64) error {
	credential := repository.credentials[userID]
	credential.FailedAttempts = 0
	credential.LockedUntil = time.Time{}
	if mfaCounter > credential.MFALastCounter {
		credential.MFALastCounter = mfaCounter
	}
	repository.credentials[userID] = credential
	return nil
}

type testPasswordManager struct{}

func (*testPasswordManager) Hash(_ context.Context, password string) (PasswordDigest, error) {
	digest := sha256.Sum256([]byte(password))
	return PasswordDigest{Algorithm: "argon2id", Parameters: "m=65536,t=3,p=2,l=32", Salt: make([]byte, 16), DerivedKey: digest[:]}, nil
}

func (*testPasswordManager) Verify(password string, digest PasswordDigest) error {
	wanted := sha256.Sum256([]byte(password))
	if string(wanted[:]) != string(digest.DerivedKey) {
		return ErrLocalCredentialInvalid
	}
	return nil
}

type fixedMFAVerifier struct {
	proof   string
	counter int64
}

type blockingMFAVerifier struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (verifier blockingMFAVerifier) Verify(_ context.Context, _ string, _ string) (MFAAssertion, error) {
	close(verifier.entered)
	<-verifier.release
	return MFAAssertion{Counter: 42}, nil
}

func (verifier fixedMFAVerifier) Verify(_ context.Context, _ string, proof string) (MFAAssertion, error) {
	if proof != verifier.proof {
		return MFAAssertion{}, ErrMFAProofInvalid
	}
	return MFAAssertion{Counter: verifier.counter}, nil
}

type lockedAuditRecorder struct {
	mu         sync.Mutex
	commands   []audit.AppendCommand
	err        error
	failAction string
}

func (recorder *lockedAuditRecorder) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.err != nil {
		return audit.Event{}, recorder.err
	}
	if recorder.failAction != "" && command.Action == recorder.failAction {
		return audit.Event{}, ErrIAMConflict
	}
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}
