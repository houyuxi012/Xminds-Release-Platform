package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestIAMPostgresLocalAuthenticationConcurrencyAndRollback(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE local_sessions, local_auth_rate_limits, emergency_access_events, directory_sync_conflicts,
directory_sync_jobs, role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM tables: %v", err)
	}
	now := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := iam.NewDummyPasswordDigest(ctx, passwords)
	if err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	mfa := &controlledMFAVerifier{}
	authenticator, err := iam.NewLocalAuthService(iam.LocalAuthConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords,
		DummyPassword: dummy, MFA: mfa, Policy: iam.DefaultLocalAuthPolicy(), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	seedPending := func(username, token string) uuid.UUID {
		t.Helper()
		userID := uuid.New()
		digest := sha256.Sum256([]byte(token))
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO user_principals (id, username, display_name, user_kind, status, version, created_at, updated_at)
VALUES ($1, $2, $2, 'local', 'pending', 1, $3, $3)`, userID, username, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO local_credentials (user_id, failed_attempts, activation_digest, activation_expires_at)
VALUES ($1, 0, $2, $3)`, userID, hex.EncodeToString(digest[:]), now.Add(time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		return userID
	}

	activationToken := "concurrent-activation-token-with-sufficient-entropy"
	activationUserID := seedPending("concurrent.activation", activationToken)
	activationErrors := make(chan error, 2)
	var activationGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		activationGroup.Add(1)
		go func() {
			defer activationGroup.Done()
			activationErrors <- authenticator.Activate(ctx, iam.ActivateLocalAccountCommand{
				ActivationToken: activationToken, NewPassword: "Concurrent-Strong-Password!",
			}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.41"})
		}()
	}
	activationGroup.Wait()
	close(activationErrors)
	activationSuccess, activationDenied := 0, 0
	for activationErr := range activationErrors {
		if activationErr == nil {
			activationSuccess++
		} else if errors.Is(activationErr, iam.ErrLocalAuthenticationFailed) {
			activationDenied++
		} else {
			t.Fatalf("concurrent Activate() error = %v", activationErr)
		}
	}
	var activationHistory int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_password_history WHERE user_id=$1`, activationUserID).Scan(&activationHistory); err != nil {
		t.Fatal(err)
	}
	if activationSuccess != 1 || activationDenied != 1 || activationHistory != 1 {
		t.Fatalf("activation results: success=%d denied=%d history=%d", activationSuccess, activationDenied, activationHistory)
	}
	if _, err := authenticator.LoginLocal(ctx, iam.LocalLoginCommand{
		Username: "concurrent.activation", Password: "Concurrent-Strong-Password!",
	}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.43"}); err != nil {
		t.Fatalf("create rollback session fixture: %v", err)
	}

	mfaToken := "concurrent-mfa-activation-token-with-sufficient-entropy"
	mfaUserID := seedPending("concurrent.mfa", mfaToken)
	mfa.counter.Store(100)
	if err := authenticator.Activate(ctx, iam.ActivateLocalAccountCommand{
		ActivationToken: mfaToken, NewPassword: "Concurrent-MFA-Password!",
		MFASecretReference: "secret://iam/concurrent-mfa", MFAProof: "123456",
	}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.42"}); err != nil {
		t.Fatalf("activate MFA fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($1, 'user', $2, 'admin', 'platform', 'allow', $3, 'test:bootstrap', 1, $3, $3)`, uuid.New(), mfaUserID, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("seed MFA administrator binding: %v", err)
	}
	mfa.counter.Store(101)
	loginErrors := make(chan error, 2)
	var loginGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		loginGroup.Add(1)
		go func(index int) {
			defer loginGroup.Done()
			_, loginErr := authenticator.LoginLocal(ctx, iam.LocalLoginCommand{
				Username: "concurrent.mfa", Password: "Concurrent-MFA-Password!", MFAProof: "123456",
			}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2." + string(rune('5'+index))})
			loginErrors <- loginErr
		}(index)
	}
	loginGroup.Wait()
	close(loginErrors)
	loginSuccess, replayDenied := 0, 0
	for loginErr := range loginErrors {
		if loginErr == nil {
			loginSuccess++
		} else if errors.Is(loginErr, iam.ErrLocalAuthenticationFailed) {
			replayDenied++
		} else {
			t.Fatalf("concurrent LoginLocal() error = %v", loginErr)
		}
	}
	if loginSuccess != 1 || replayDenied != 1 {
		t.Fatalf("TOTP replay results: success=%d denied=%d", loginSuccess, replayDenied)
	}

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE local_auth_rate_limits`); err != nil {
		t.Fatal(err)
	}
	const attempts, limit = 40, 20
	allowedCount := atomic.Int64{}
	var rateGroup sync.WaitGroup
	for range attempts {
		rateGroup.Add(1)
		go func() {
			defer rateGroup.Done()
			rateErr := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
				allowed, consumeErr := repository.ConsumeRateLimit(ctx, tx, iam.RateLimitScopeIP, strings.Repeat("a", 64), now, limit, now.Add(time.Minute))
				if allowed {
					allowedCount.Add(1)
				}
				return consumeErr
			})
			if rateErr != nil {
				t.Errorf("ConsumeRateLimit() error = %v", rateErr)
			}
		}()
	}
	rateGroup.Wait()
	var storedAttempts int
	if err := pool.QueryRow(ctx, `SELECT attempt_count FROM local_auth_rate_limits WHERE scope='ip'`).Scan(&storedAttempts); err != nil {
		t.Fatal(err)
	}
	if allowedCount.Load() != limit || storedAttempts != attempts {
		t.Fatalf("rate-limit concurrency: allowed=%d stored=%d", allowedCount.Load(), storedAttempts)
	}

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE local_auth_rate_limits`); err != nil {
		t.Fatal(err)
	}
	failingAuthenticator, err := iam.NewLocalAuthService(iam.LocalAuthConfig{
		Repository: repository, Auditor: failingIAMAuditAppender{}, Passwords: passwords, DummyPassword: dummy,
		MFA: mfa, Policy: iam.DefaultLocalAuthPolicy(), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingAuthenticator.LoginLocal(ctx, iam.LocalLoginCommand{
		Username: "unknown.audit", Password: "Wrong-Password-Value!",
	}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.61"}); !errors.Is(err, errIntegrationAuditFailure) {
		t.Fatalf("LoginLocal(audit failure) error = %v", err)
	}
	var rateRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_auth_rate_limits`).Scan(&rateRows); err != nil || rateRows != 0 {
		t.Fatalf("audit rollback rate rows=%d error=%v", rateRows, err)
	}

	failingService, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: failingIAMAuditAppender{}, Sessions: repository, Passwords: passwords,
		HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := failingService.DisableUser(ctx,
		identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}},
		activationUserID, "rollback validation", iam.HighRiskProof{Confirmed: true, ChallengeID: "rollback", Evidence: "rollback"},
		iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "127.0.0.1"}); !errors.Is(err, errIntegrationAuditFailure) {
		t.Fatalf("DisableUser(audit failure) error = %v", err)
	}
	var status iam.UserStatus
	var revokedSessions int
	if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, activationUserID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE subject_id=$1 AND revoked_at IS NOT NULL`, activationUserID).Scan(&revokedSessions); err != nil {
		t.Fatal(err)
	}
	if status != iam.UserStatusActive || revokedSessions != 0 {
		t.Fatalf("disable rollback: status=%s revoked_sessions=%d", status, revokedSessions)
	}

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE local_auth_rate_limits`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO local_auth_rate_limits (scope, key_digest, window_started_at, attempt_count, expires_at)
SELECT 'account', repeat(md5(value::text), 2), $1, 1, $2 FROM generate_series(1, 200) value`, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var cleaned int64
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var cleanupErr error
		cleaned, cleanupErr = repository.CleanupExpiredRateLimits(ctx, tx, now, 64)
		return cleanupErr
	}); err != nil {
		t.Fatal(err)
	}
	if cleaned != 64 {
		t.Fatalf("bounded cleanup removed %d rows", cleaned)
	}
}

func TestIAMSessionTouchAndModeSwitchUsePostgresLoginStateBarrier(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE local_sessions, local_auth_rate_limits, emergency_access_events, directory_sync_conflicts,
directory_sync_jobs, role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)
	sourceID, emergencyID := uuid.New(), uuid.New()
	secret := make([]byte, 32)
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	rawToken := "xms_" + base64.RawURLEncoding.EncodeToString(secret)
	tokenDigest := sha256.Sum256([]byte(rawToken))
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, required_mappings_complete, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Barrier OIDC', 'oidc', 'verified', TRUE, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed barrier source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, 'barrier-emergency', 'Barrier Emergency', 'emergency', 'active', TRUE, $2, 1, $2, $2)`, emergencyID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed barrier emergency account: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (
    id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at,
    last_used_at, absolute_expires_at, idle_expires_at, version
) VALUES ($1, $2, $3, 'emergency_password', 1, $4, $4, $5, $6, 1)`,
		uuid.New(), hex.EncodeToString(tokenDigest[:]), emergencyID, now.Add(-time.Hour), now.Add(2*time.Hour), now.Add(15*time.Minute)); err != nil {
		t.Fatalf("seed barrier fixtures: %v", err)
	}

	repository := iam.NewPostgresRepository(pool)
	blocking := &blockingIAMSessionRepository{PostgresRepository: repository, found: make(chan struct{}), release: make(chan struct{})}
	verifier, err := iam.NewSessionVerifier(blocking, iam.DefaultLocalAuthPolicy(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	verifyDone := make(chan error, 1)
	go func() {
		_, verifyErr := verifier.Verify(ctx, rawToken)
		verifyDone <- verifyErr
	}()
	select {
	case <-blocking.found:
	case <-ctx.Done():
		t.Fatal("session verification did not reach the controlled transaction boundary")
	}

	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Sessions: repository,
		Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	switchDone := make(chan error, 1)
	go func() {
		switchDone <- service.EnableSSO(ctx,
			identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "barrier-admin"},
			sourceID, iam.HighRiskProof{Confirmed: true, ChallengeID: "barrier", Evidence: "barrier"},
			iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "127.0.0.1"})
	}()
	select {
	case switchErr := <-switchDone:
		t.Fatalf("mode switch crossed an in-flight session verification: %v", switchErr)
	case <-time.After(250 * time.Millisecond):
	}
	close(blocking.release)
	if verifyErr := <-verifyDone; verifyErr != nil {
		t.Fatalf("session verification that started before the switch error = %v", verifyErr)
	}
	if switchErr := <-switchDone; switchErr != nil {
		t.Fatalf("EnableSSO() error = %v", switchErr)
	}
}

func TestIAMLocalAuthenticationPostgresLifecycle(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE local_sessions, local_auth_rate_limits, emergency_access_events, directory_sync_conflicts,
directory_sync_jobs, role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset local authentication tables: %v", err)
	}
	now := time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49201")
	organizationID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49202")
	bindingValidFrom := time.Now().UTC().Add(-time.Hour)
	activationToken := "postgres-activation-token-with-256-bits-minimum-entropy"
	activationDigest := sha256.Sum256([]byte(activationToken))
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, username, display_name, user_kind, status, version, created_at, updated_at)
VALUES ($1, 'postgres.operator', 'Postgres Operator', 'local', 'pending', 1, $2, $2)`, userID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed pending local user principal: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts, locked_until,
    password_changed_at, activation_digest, activation_expires_at
) VALUES ($1, NULL, NULL, NULL, NULL, 0, NULL, NULL, $2, $3)`,
		userID, hex.EncodeToString(activationDigest[:]), now.Add(time.Hour)); err != nil {
		t.Fatalf("seed pending local credential: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_units (
    id, external_id, name, source_owned, status, version, created_at, updated_at
) VALUES ($1, '', 'Platform Administrators', FALSE, 'active', 1, $2, $2)`, organizationID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed administrator organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id, user_id, source_owned, created_at)
VALUES ($1, $2, FALSE, $3)`, organizationID, userID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed inherited administrator membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($3, 'organization', $1, 'admin', 'platform', 'allow', $2,
          'test:bootstrap', 1, $2, $2)`, organizationID, bindingValidFrom, uuid.New()); err != nil {
		t.Fatalf("seed inherited platform administrator binding: %v", err)
	}
	repository := iam.NewPostgresRepository(pool)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	dummyPassword, err := iam.NewDummyPasswordDigest(ctx, passwords)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := iam.NewLocalAuthService(iam.LocalAuthConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords,
		DummyPassword: dummyPassword, MFA: &integrationMFAVerifier{}, Policy: iam.DefaultLocalAuthPolicy(), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "192.0.2.20"}
	if err := authenticator.Activate(ctx, iam.ActivateLocalAccountCommand{
		ActivationToken: activationToken, NewPassword: "Postgres-Strong-Password!",
	}, request); !errors.Is(err, iam.ErrLocalAuthenticationFailed) {
		t.Fatalf("Activate(inherited administrator without MFA) error = %v", err)
	}
	if err := authenticator.Activate(ctx, iam.ActivateLocalAccountCommand{
		ActivationToken: activationToken, NewPassword: "Postgres-Strong-Password!",
		MFASecretReference: "secret://iam/postgres-operator", MFAProof: "123456",
	}, request); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	var status iam.UserStatus
	var activation *string
	var historyCount int
	if err := pool.QueryRow(ctx, `
SELECT user_record.status, credential.activation_digest,
       (SELECT count(*) FROM local_password_history WHERE user_id = user_record.id)
FROM user_principals user_record JOIN local_credentials credential ON credential.user_id=user_record.id
WHERE user_record.id=$1`, userID).Scan(&status, &activation, &historyCount); err != nil {
		t.Fatal(err)
	}
	if status != iam.UserStatusActive || activation != nil || historyCount != 1 {
		t.Fatalf("activation state: status=%s digest=%v history=%d", status, activation, historyCount)
	}
	login, err := authenticator.LoginLocal(ctx, iam.LocalLoginCommand{
		Username: "postgres.operator", Password: "Postgres-Strong-Password!", MFAProof: "123456",
	}, request)
	if err != nil {
		t.Fatalf("LoginLocal() error = %v", err)
	}
	var storedDigest string
	if err := pool.QueryRow(ctx, `SELECT token_digest FROM local_sessions WHERE subject_id=$1`, userID).Scan(&storedDigest); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256([]byte(login.AccessToken))
	if storedDigest != hex.EncodeToString(wantDigest[:]) || storedDigest == login.AccessToken {
		t.Fatalf("stored session digest = %q", storedDigest)
	}
	verifier, err := iam.NewSessionVerifier(repository, iam.DefaultLocalAuthPolicy(), func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, login.AccessToken); err != nil {
		t.Fatalf("Verify(active session) error = %v", err)
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.RevokeSubject(ctx, tx, userID, "integration-test")
	}); err != nil {
		t.Fatalf("RevokeSubject() error = %v", err)
	}
	if _, err := verifier.Verify(ctx, login.AccessToken); !errors.Is(err, identity.ErrAuthenticationFailed) {
		t.Fatalf("Verify(revoked session) error = %v", err)
	}
}

func TestIAMRepositoryEnablesSSOAtomicallyWithEmergencyAccessAndAudit(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE emergency_access_events, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())
`); err != nil {
		t.Fatalf("reset IAM test tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	sourceID := uuid.New()
	emergencyID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, required_mappings_complete, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Corporate OIDC', 'oidc', 'verified', TRUE, $2, $2, 1, $2, $2)
`, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed identity source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, 'break-glass', '应急管理员', 'emergency', 'active', TRUE, $2, 1, $2, $2)
`, emergencyID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed emergency administrator: %v", err)
	}

	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: auditor, Sessions: integrationSessionRevoker{}, Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "admin-token"}
	err = service.EnableSSO(ctx, actor, sourceID, iam.HighRiskProof{Confirmed: true, ChallengeID: "test", Evidence: "test"}, iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("EnableSSO() error = %v", err)
	}
	state, err := repository.GetLoginState(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != iam.LoginModeSSO || state.ActiveSourceID != sourceID || state.Version != 2 {
		t.Fatalf("login state = %+v", state)
	}
	source, err := repository.GetIdentitySource(ctx, nil, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if source.Status != iam.IdentitySourceStatusEnabled || source.Version != 2 {
		t.Fatalf("identity source = %+v", source)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'identity.sso.enable' AND resource_id = $1`, sourceID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("SSO enable audit count = %d", auditCount)
	}
}

func TestIAMGovernedPrincipalResolverIsolatesPostgresIdentitySources(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE emergency_access_events, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
`); err != nil {
		t.Fatalf("reset IAM test tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	sourceAID := uuid.New()
	sourceBID := uuid.New()
	sourceAUserID := uuid.New()
	sourceBUserID := uuid.New()
	wrongSourceUserID := uuid.New()
	disabledUserID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (id, name, source_kind, status, version, created_at, updated_at)
VALUES ($1, 'Source A', 'oidc', 'enabled', 1, $3, $3),
       ($2, 'Source B', 'oidc', 'enabled', 1, $3, $3)
`, sourceAID, sourceBID, now); err != nil {
		t.Fatalf("seed identity sources: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO iam_login_state (singleton, login_mode, active_source_id, version, updated_by, updated_at)
VALUES (TRUE, 'sso', $1, 1, 'test:bootstrap', $2)
`, sourceAID, now); err != nil {
		t.Fatalf("seed IAM login state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, identity_source_id, external_subject, username, display_name, user_kind, status,
    version, created_at, updated_at, disabled_at, disabled_reason
) VALUES
    ($4, $1, 'shared-subject', 'source-a-user', 'Source A User', 'external', 'active', 1, $3, $3, NULL, ''),
    ($5, $2, 'shared-subject', 'source-b-user', 'Source B User', 'external', 'active', 1, $3, $3, NULL, ''),
    ($6, $2, 'wrong-source-only', 'wrong-source-user', 'Wrong Source User', 'external', 'active', 1, $3, $3, NULL, ''),
    ($7, $1, 'disabled-user', 'disabled-source-a-user', 'Disabled Source A User', 'external', 'disabled', 1, $3, $3, $3, 'directory disabled')
`, sourceAID, sourceBID, now, sourceAUserID, sourceBUserID, wrongSourceUserID, disabledUserID); err != nil {
		t.Fatalf("seed governed users: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES
	    ($4, 'user', $2, 'viewer', 'platform', 'allow', $1, 'test:bootstrap', 1, $1, $1),
	    ($5, 'user', $3, 'publisher', 'platform', 'allow', $1, 'test:bootstrap', 1, $1, $1)
`, now, sourceAUserID, sourceBUserID, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("seed governed role bindings: %v", err)
	}

	resolver, err := iam.NewGovernedPrincipalResolver(iam.NewPostgresRepository(pool), func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	resolveHuman := func(subject string) (identity.Principal, error) {
		return resolver.ResolvePrincipal(ctx, identity.Principal{
			Subject: subject, Kind: identity.PrincipalKindHuman,
			Roles: []identity.Role{identity.RoleAdmin}, ProductIDs: []string{"untrusted-product"},
		})
	}
	assertOnlyRole := func(t *testing.T, principal identity.Principal, role identity.Role) {
		t.Helper()
		if !principal.Governed || len(principal.Roles) != 0 || len(principal.ProductIDs) != 0 || len(principal.RoleScopes) != 1 || principal.RoleScopes[0].Role != role {
			t.Fatalf("resolved principal = %+v, want only governed %q scope", principal, role)
		}
	}
	assertUnavailable := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, iam.ErrGovernedPrincipalUnavailable) {
			t.Fatalf("ResolvePrincipal() error = %v, want %v", err, iam.ErrGovernedPrincipalUnavailable)
		}
	}

	t.Run("active source selects only its duplicate subject", func(t *testing.T) {
		resolved, resolveErr := resolveHuman("shared-subject")
		if resolveErr != nil {
			t.Fatalf("ResolvePrincipal() error = %v", resolveErr)
		}
		assertOnlyRole(t, resolved, identity.RoleViewer)
	})

	t.Run("subject from wrong source fails closed", func(t *testing.T) {
		_, resolveErr := resolveHuman("wrong-source-only")
		assertUnavailable(t, resolveErr)
	})

	t.Run("switching active source selects the other duplicate subject", func(t *testing.T) {
		if _, updateErr := pool.Exec(ctx, `UPDATE iam_login_state SET active_source_id=$1, version=version+1, updated_at=$2 WHERE singleton=TRUE`, sourceBID, now.Add(time.Minute)); updateErr != nil {
			t.Fatal(updateErr)
		}
		resolved, resolveErr := resolveHuman("shared-subject")
		if resolveErr != nil {
			t.Fatalf("ResolvePrincipal() error = %v", resolveErr)
		}
		assertOnlyRole(t, resolved, identity.RolePublisher)
	})

	t.Run("disabled active source fails closed", func(t *testing.T) {
		if _, updateErr := pool.Exec(ctx, `UPDATE identity_sources SET status='disabled', version=version+1, updated_at=$2 WHERE id=$1`, sourceBID, now.Add(2*time.Minute)); updateErr != nil {
			t.Fatal(updateErr)
		}
		_, resolveErr := resolveHuman("shared-subject")
		assertUnavailable(t, resolveErr)
	})

	t.Run("disabled active-source user fails closed", func(t *testing.T) {
		if _, updateErr := pool.Exec(ctx, `UPDATE iam_login_state SET active_source_id=$1, version=version+1, updated_at=$2 WHERE singleton=TRUE`, sourceAID, now.Add(3*time.Minute)); updateErr != nil {
			t.Fatal(updateErr)
		}
		_, resolveErr := resolveHuman("disabled-user")
		assertUnavailable(t, resolveErr)
	})

	t.Run("local principal cannot match external username", func(t *testing.T) {
		_, resolveErr := resolver.ResolvePrincipal(ctx, identity.Principal{Subject: "source-a-user", Kind: identity.PrincipalKindLocal})
		assertUnavailable(t, resolveErr)
	})
}

func TestIAMRepositoryCreatesAndPaginatesLocalUsersWithoutPlaintextActivationToken(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE emergency_access_events, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())
`); err != nil {
		t.Fatalf("reset IAM test tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
	provisioning, err := service.CreateLocalUser(ctx, actor, iam.CreateLocalUserCommand{
		Username: "release.operator", DisplayName: "发布操作员", Email: "operator@example.com",
	}, iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateLocalUser() error = %v", err)
	}

	var activationDigest string
	if err := pool.QueryRow(ctx, `SELECT activation_digest FROM local_credentials WHERE user_id = $1`, provisioning.User.ID).Scan(&activationDigest); err != nil {
		t.Fatal(err)
	}
	if activationDigest == provisioning.ActivationToken || len(activationDigest) != 64 {
		t.Fatalf("stored activation digest is unsafe: %q", activationDigest)
	}
	page, err := service.ListUsers(ctx, actor, iam.Page{Limit: 1})
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != provisioning.User.ID || page.Items[0].Status != iam.UserStatusPending {
		t.Fatalf("user page = %+v", page)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'identity.local_user.create' AND resource_id = $1`, provisioning.User.ID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("local user audit count = %d", auditCount)
	}
}

func TestIAMRepositoryPersistsGovernedResourcesWithAppendAudit(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE emergency_access_events, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM test tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e91")
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, username, display_name, user_kind, status, version, created_at, updated_at)
VALUES ($1, 'audit.reader', '审计阅读者', 'local', 'active', 1, $2, $2)`, userID, now); err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	repository := iam.NewPostgresRepository(pool)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
	request := iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "127.0.0.1"}
	organization, err := service.CreateOrganization(ctx, actor, iam.CreateOrganizationCommand{Name: "Release Engineering"}, request)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	if _, err := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
		SubjectType: iam.SubjectTypeUser, SubjectID: userID, Role: identity.RoleAuditor, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectAllow,
	}, iam.HighRiskProof{Confirmed: true, ChallengeID: "test", Evidence: "test"}, request); err != nil {
		t.Fatalf("CreateRoleBinding() error = %v", err)
	}
	source, err := service.CreateIdentitySource(ctx, actor, iam.CreateIdentitySourceCommand{Name: "Corporate OIDC", Kind: iam.IdentitySourceOIDC, SecretReference: "secret://iam/corporate-oidc"}, request)
	if err != nil {
		t.Fatalf("CreateIdentitySource() error = %v", err)
	}

	organizations, err := service.ListOrganizations(ctx, actor, iam.Page{Limit: 10})
	if err != nil || len(organizations.Items) != 1 || organizations.Items[0].ID != organization.ID {
		t.Fatalf("organization page = %+v, error = %v", organizations, err)
	}
	bindings, err := service.ListRoleBindings(ctx, actor, iam.Page{Limit: 10})
	if err != nil || len(bindings.Items) != 1 || bindings.Items[0].SubjectID != userID {
		t.Fatalf("role binding page = %+v, error = %v", bindings, err)
	}
	sources, err := service.ListIdentitySources(ctx, actor, iam.Page{Limit: 10})
	if err != nil || len(sources.Items) != 1 || sources.Items[0].ID != source.ID {
		t.Fatalf("identity source page = %+v, error = %v", sources, err)
	}
	var storedReference string
	if err := pool.QueryRow(ctx, `SELECT secret_reference FROM identity_sources WHERE id = $1`, source.ID).Scan(&storedReference); err != nil {
		t.Fatal(err)
	}
	if storedReference != "secret://iam/corporate-oidc" {
		t.Fatalf("stored secret reference = %q", storedReference)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=$1 AND action IN ('identity.organization.create', 'identity.role_binding.create', 'identity.source.create')`, request.RequestID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 3 {
		t.Fatalf("governed resource audit count = %d", auditCount)
	}
}

type integrationBreachChecker struct{}

func (integrationBreachChecker) IsBreached(context.Context, string) (bool, error) { return false, nil }

var errIntegrationAuditFailure = errors.New("integration audit failure")

type failingIAMAuditAppender struct{}

func (failingIAMAuditAppender) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, errIntegrationAuditFailure
}

type controlledMFAVerifier struct{ counter atomic.Int64 }

func (verifier *controlledMFAVerifier) Verify(context.Context, string, string) (iam.MFAAssertion, error) {
	return iam.MFAAssertion{Counter: verifier.counter.Load()}, nil
}

type blockingIAMSessionRepository struct {
	*iam.PostgresRepository
	found   chan struct{}
	release chan struct{}
}

func (repository *blockingIAMSessionRepository) FindSession(ctx context.Context, tx pgx.Tx, tokenDigest string) (iam.Session, iam.UserPrincipal, iam.LoginState, error) {
	session, user, state, err := repository.PostgresRepository.FindSession(ctx, tx, tokenDigest)
	close(repository.found)
	select {
	case <-repository.release:
	case <-ctx.Done():
		return iam.Session{}, iam.UserPrincipal{}, iam.LoginState{}, ctx.Err()
	}
	return session, user, state, err
}

type integrationMFAVerifier struct{ counter atomic.Int64 }

func (verifier *integrationMFAVerifier) Verify(context.Context, string, string) (iam.MFAAssertion, error) {
	return iam.MFAAssertion{Counter: verifier.counter.Add(1)}, nil
}

type integrationSessionRevoker struct{}

func (integrationSessionRevoker) RevokeSubject(context.Context, pgx.Tx, uuid.UUID, string) error {
	return nil
}

func (integrationSessionRevoker) RevokeOrganizationMembers(context.Context, pgx.Tx, uuid.UUID, string) error {
	return nil
}

func (integrationSessionRevoker) RevokeRegularLocalSessions(context.Context, pgx.Tx, string) error {
	return nil
}

type integrationHighRiskAuthorizer struct{}

func (integrationHighRiskAuthorizer) Authorize(context.Context, identity.Principal, string, iam.HighRiskProof) error {
	return nil
}
