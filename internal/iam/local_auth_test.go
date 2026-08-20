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
)

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
	command := ActivateLocalAccountCommand{
		ActivationToken:    harness.activationToken,
		NewPassword:        "A-Strong-Admin-Password!",
		MFASecretReference: "secret://iam/admin-totp",
		MFAProof:           "123456",
	}
	if err := harness.service.Activate(context.Background(), command, harness.request); err != nil {
		t.Fatalf("Activate(admin) error = %v", err)
	}
	user := harness.repository.users[harness.userID]
	credential := harness.repository.credentials[harness.userID]
	if !user.MFAEnrolled || credential.MFASecretReference != "secret://iam/admin-totp" || credential.MFALastCounter != 42 {
		t.Fatalf("MFA activation state = user=%+v credential=%+v", user, credential)
	}

	missing := newLocalAuthHarness(t, UserKindEmergency, false)
	if err := missing.service.Activate(context.Background(), ActivateLocalAccountCommand{
		ActivationToken: missing.activationToken, NewPassword: "A-Strong-Emergency-Password!",
	}, missing.request); !errors.Is(err, ErrLocalAuthenticationFailed) {
		t.Fatalf("Activate(emergency without MFA) error = %v", err)
	}
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
		history:    map[uuid.UUID][]PasswordDigest{},
		admins:     map[uuid.UUID]bool{userID: admin},
		rateLimits: map[string]memoryRateWindow{},
		sessions:   map[uuid.UUID]Session{},
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
	err := function(nil)
	if err != nil {
		repository.users = users
		repository.credentials = credentials
		repository.history = history
		repository.rateLimits = rateLimits
	}
	return err
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

func (verifier fixedMFAVerifier) Verify(_ context.Context, _ string, proof string) (MFAAssertion, error) {
	if proof != verifier.proof {
		return MFAAssertion{}, ErrMFAProofInvalid
	}
	return MFAAssertion{Counter: verifier.counter}, nil
}

type lockedAuditRecorder struct {
	mu       sync.Mutex
	commands []audit.AppendCommand
	err      error
}

func (recorder *lockedAuditRecorder) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.err != nil {
		return audit.Event{}, recorder.err
	}
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}
