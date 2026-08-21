package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

// Mutation caught: preserving the legacy client-authored readiness bit during
// upgrade allows an unverified configuration to satisfy the SSO gate.
func TestIdentitySourceCapabilityMigrationV18UpgradeRollbackAndReapply(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "identity_source_capability_migration_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 18)); err != nil {
		t.Fatalf("apply migrations 1..18: %v", err)
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	sourceID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO identity_sources (id,name,source_kind,status,required_mappings_complete,verified_at,version,created_at,updated_at) VALUES ($1,'Legacy Ready OIDC','oidc','verified',TRUE,$2,4,$2,$2)`, sourceID, now); err != nil {
		t.Fatal(err)
	}
	checksums := migrationChecksums(t, ctx, pool, 18)
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("upgrade v18 to v19: %v", err)
	}
	for version, checksum := range checksums {
		var current string
		if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, version).Scan(&current); err != nil || current != checksum {
			t.Fatalf("migration %d checksum changed: before=%s after=%s error=%v", version, checksum, current, err)
		}
	}
	var configurationVersion int64
	var verifiedConfigurationVersion *int64
	var mappingsComplete bool
	if err := pool.QueryRow(ctx, `SELECT configuration_version,verified_configuration_version,required_mappings_complete FROM identity_sources WHERE id=$1`, sourceID).Scan(&configurationVersion, &verifiedConfigurationVersion, &mappingsComplete); err != nil {
		t.Fatal(err)
	}
	if configurationVersion != 1 || verifiedConfigurationVersion != nil || mappingsComplete {
		t.Fatalf("upgraded capability config=%d verified=%v mappings=%t", configurationVersion, verifiedConfigurationVersion, mappingsComplete)
	}
	if _, err := pool.Exec(ctx, `UPDATE identity_sources SET configuration_version=0 WHERE id=$1`, sourceID); err == nil {
		t.Fatal("configuration_version=0 accepted")
	}
	for name, statement := range map[string]string{
		"true without verified generation": `UPDATE identity_sources SET required_mappings_complete=TRUE,verified_configuration_version=NULL WHERE id=$1`,
		"false with verified generation":   `UPDATE identity_sources SET required_mappings_complete=FALSE,verified_configuration_version=1 WHERE id=$1`,
		"mismatched verified generation":   `UPDATE identity_sources SET required_mappings_complete=TRUE,verified_configuration_version=2 WHERE id=$1`,
	} {
		_, updateErr := pool.Exec(ctx, statement, sourceID)
		var postgresError *pgconn.PgError
		if !errors.As(updateErr, &postgresError) || postgresError.Code != "23514" {
			t.Errorf("%s error=%v, want SQLSTATE 23514", name, updateErr)
			if _, resetErr := pool.Exec(ctx, `UPDATE identity_sources SET required_mappings_complete=FALSE,verified_configuration_version=NULL WHERE id=$1`, sourceID); resetErr != nil {
				t.Fatal(resetErr)
			}
		}
	}
	downSQL, err := fs.ReadFile(migrations.FS, "000019_identity_source_capabilities.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(downSQL)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=19`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var capabilityColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='identity_sources' AND column_name IN ('configuration_version','verified_configuration_version')`).Scan(&capabilityColumns); err != nil || capabilityColumns != 0 {
		t.Fatalf("capability columns after down=%d error=%v", capabilityColumns, err)
	}
	if err := pool.QueryRow(ctx, `SELECT required_mappings_complete FROM identity_sources WHERE id=$1`, sourceID).Scan(&mappingsComplete); err != nil || mappingsComplete {
		t.Fatalf("down restored untrusted mapping readiness=%t error=%v", mappingsComplete, err)
	}
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("reapply v19: %v", err)
	}
	var serverVersion string
	if err := pool.QueryRow(ctx, `SHOW server_version`).Scan(&serverVersion); err != nil || !strings.HasPrefix(serverVersion, "17.10") {
		t.Fatalf("PostgreSQL server_version=%q error=%v, require 17.10", serverVersion, err)
	}
}

// Mutation caught: leaving configuration fields out of repository scans or
// updates silently drops the generation binding created by Verify.
func TestIdentitySourceCapabilityRepositoryRoundTrip(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "identity_source_capability_repository_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE identity_sources CASCADE`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 12, 30, 0, 0, time.UTC)
	source := iam.IdentitySource{
		ID: uuid.New(), Name: "Repository OIDC", Kind: iam.IdentitySourceOIDC, Status: iam.IdentitySourceStatusDraft,
		SecretReference: "secret://iam/repository", ConfigurationVersion: 1, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	repository := iam.NewPostgresRepository(pool)
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error { return repository.InsertIdentitySource(ctx, tx, source) }); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.GetIdentitySource(ctx, nil, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ConfigurationVersion != 1 || loaded.VerifiedConfigurationVersion != 0 || loaded.RequiredMappingsComplete {
		t.Fatalf("created source=%+v", loaded)
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		current, getErr := repository.GetIdentitySource(ctx, tx, source.ID)
		if getErr != nil {
			return getErr
		}
		current.Status = iam.IdentitySourceStatusVerified
		current.RequiredMappingsComplete = true
		current.VerifiedConfigurationVersion = current.ConfigurationVersion
		current.VerifiedAt = now.Add(time.Minute)
		current.Version++
		current.UpdatedAt = now.Add(time.Minute)
		return repository.SaveIdentitySource(ctx, tx, current, 1)
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err = repository.GetIdentitySource(ctx, nil, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ConfigurationVersion != 1 || loaded.VerifiedConfigurationVersion != 1 || !loaded.RequiredMappingsComplete || loaded.VerifiedAt.IsZero() || loaded.Version != 2 {
		t.Fatalf("verified source=%+v", loaded)
	}
}

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
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: failingIAMAuditAppender{}, Sessions: repository, Passwords: passwords,
		HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := failingService.DisableUser(ctx,
		identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}},
		activationUserID, 2, "rollback validation", iam.HighRiskProof{Confirmed: true, ChallengeID: "rollback", Evidence: "rollback"},
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

func TestIAMPostgresReauthenticationConcurrencyAndAuditRollback(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE iam_reauthentication_challenges`); err != nil {
		t.Fatalf("reset reauthentication tables: %v", err)
	}
	now := time.Date(2026, 8, 20, 17, 0, 0, 0, time.UTC)
	repository := iam.NewPostgresRepository(pool)
	goodAuditor := audit.NewService(audit.NewPostgresRepository(pool))
	service, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: goodAuditor, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceAID, sourceBID, sourceAUserID, sourceBUserID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	creator := identity.Principal{
		Subject: "postgres.admin", Kind: identity.PrincipalKindHuman, TokenID: "oidc-old-token", Governed: true,
		IdentitySourceID: sourceAID.String(), GovernedUserID: sourceAUserID.String(),
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
	completer := creator
	completer.TokenID = "oidc-fresh-token"
	completer.AuthenticatedAt = now.Add(-time.Minute)
	completer.AuthenticationAssurance = 1
	request := iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.90"}

	failingService, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: failingIAMAuditAppender{}, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	crossSourceCompleter := completer
	crossSourceCompleter.IdentitySourceID = sourceBID.String()
	crossSourceCompleter.GovernedUserID = sourceBUserID.String()
	crossSourceChallenge, err := service.CreateChallenge(ctx, creator, iam.ReauthenticationOperationUserEnable, request)
	if err != nil {
		t.Fatalf("CreateChallenge() for cross-source proof error = %v", err)
	}
	if completed, completeErr := service.CompleteChallenge(ctx, crossSourceCompleter, crossSourceChallenge.ID, iam.CompleteReauthenticationCommand{}, request); !errors.Is(completeErr, iam.ErrHighRiskConfirmationRequired) || completed.Evidence != "" {
		t.Fatalf("cross-source CompleteChallenge() = %#v, %v", completed, completeErr)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, crossSourceChallenge.ID).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("cross-source completion status=%q error=%v", status, err)
	}
	sameSourceEvidence, err := service.CompleteChallenge(ctx, completer, crossSourceChallenge.ID, iam.CompleteReauthenticationCommand{}, request)
	if err != nil {
		t.Fatalf("same-source CompleteChallenge() error = %v", err)
	}
	crossSourceProof := iam.HighRiskProof{ChallengeID: crossSourceChallenge.ID.String(), Evidence: sameSourceEvidence.Evidence, Confirmed: true}
	if authorizeErr := service.Authorize(ctx, crossSourceCompleter, string(iam.ReauthenticationOperationUserEnable), crossSourceProof, request); !errors.Is(authorizeErr, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("cross-source Authorize() error = %v", authorizeErr)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, crossSourceChallenge.ID).Scan(&status); err != nil || status != "verified" {
		t.Fatalf("cross-source authorization status=%q error=%v", status, err)
	}
	if authorizeErr := service.Authorize(ctx, completer, string(iam.ReauthenticationOperationUserEnable), crossSourceProof, request); authorizeErr != nil {
		t.Fatalf("same-source Authorize() error = %v", authorizeErr)
	}
	var challengeCountBeforeFailure int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_reauthentication_challenges`).Scan(&challengeCountBeforeFailure); err != nil {
		t.Fatal(err)
	}
	if _, err := failingService.CreateChallenge(ctx, creator, iam.ReauthenticationOperationUserDisable, request); err == nil {
		t.Fatal("CreateChallenge() with failing audit error = nil")
	}
	var challengeCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_reauthentication_challenges`).Scan(&challengeCount); err != nil || challengeCount != challengeCountBeforeFailure {
		t.Fatalf("challenge count after create rollback = %d, want %d, error=%v", challengeCount, challengeCountBeforeFailure, err)
	}

	created, err := service.CreateChallenge(ctx, creator, iam.ReauthenticationOperationUserDisable, request)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	completeResults := make(chan iam.ReauthenticationEvidence, 2)
	completeErrors := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, completeErr := service.CompleteChallenge(ctx, completer, created.ID, iam.CompleteReauthenticationCommand{}, request)
			completeResults <- result
			completeErrors <- completeErr
		}()
	}
	group.Wait()
	close(completeResults)
	close(completeErrors)
	completeSuccess, completeDenied := 0, 0
	var completed iam.ReauthenticationEvidence
	for result := range completeResults {
		if result.Evidence != "" {
			completed = result
		}
	}
	for completeErr := range completeErrors {
		if completeErr == nil {
			completeSuccess++
		} else if errors.Is(completeErr, iam.ErrHighRiskConfirmationRequired) {
			completeDenied++
		} else {
			t.Fatalf("concurrent CompleteChallenge() error = %v", completeErr)
		}
	}
	if completeSuccess != 1 || completeDenied != 1 || completed.Evidence == "" {
		t.Fatalf("complete results: success=%d denied=%d evidence=%t", completeSuccess, completeDenied, completed.Evidence != "")
	}
	var evidenceDigest, createdTokenDigest, verifiedTokenDigest string
	if err := pool.QueryRow(ctx, `SELECT evidence_digest, created_token_digest, verified_token_digest FROM iam_reauthentication_challenges WHERE id=$1`, created.ID).
		Scan(&evidenceDigest, &createdTokenDigest, &verifiedTokenDigest); err != nil {
		t.Fatal(err)
	}
	if evidenceDigest == completed.Evidence || evidenceDigest != integrationSHA256Hex(completed.Evidence) ||
		createdTokenDigest != integrationSHA256Hex(creator.TokenID) || verifiedTokenDigest != integrationSHA256Hex(completer.TokenID) {
		t.Fatalf("stored reauthentication digests are invalid")
	}

	proof := iam.HighRiskProof{ChallengeID: created.ID.String(), Evidence: completed.Evidence, Confirmed: true}
	authorizeErrors := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			authorizeErrors <- service.Authorize(ctx, completer, string(iam.ReauthenticationOperationUserDisable), proof, request)
		}()
	}
	group.Wait()
	close(authorizeErrors)
	authorizeSuccess, authorizeDenied := 0, 0
	for authorizeErr := range authorizeErrors {
		if authorizeErr == nil {
			authorizeSuccess++
		} else if errors.Is(authorizeErr, iam.ErrHighRiskConfirmationRequired) {
			authorizeDenied++
		} else {
			t.Fatalf("concurrent Authorize() error = %v", authorizeErr)
		}
	}
	if authorizeSuccess != 1 || authorizeDenied != 1 {
		t.Fatalf("authorize results: success=%d denied=%d", authorizeSuccess, authorizeDenied)
	}

	rollbackChallenge, err := service.CreateChallenge(ctx, creator, iam.ReauthenticationOperationSSOEnable, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingService.CompleteChallenge(ctx, completer, rollbackChallenge.ID, iam.CompleteReauthenticationCommand{}, request); err == nil {
		t.Fatal("CompleteChallenge() audit failure error = nil")
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, rollbackChallenge.ID).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("status after complete rollback = %q, %v", status, err)
	}
	rollbackEvidence, err := service.CompleteChallenge(ctx, completer, rollbackChallenge.ID, iam.CompleteReauthenticationCommand{}, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := failingService.Authorize(ctx, completer, string(iam.ReauthenticationOperationSSOEnable), iam.HighRiskProof{ChallengeID: rollbackChallenge.ID.String(), Evidence: rollbackEvidence.Evidence, Confirmed: true}, request); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("Authorize() audit failure error = %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, rollbackChallenge.ID).Scan(&status); err != nil || status != "verified" {
		t.Fatalf("status after consume rollback = %q, %v", status, err)
	}

	localActor := creator
	localActor.Subject = "local:postgres-emergency-admin"
	localActor.Kind = identity.PrincipalKindLocal
	localActor.IdentitySourceID = ""
	localActor.GovernedUserID = uuid.NewString()
	localActor.TokenID = "local-session-token"
	localActor.AuthenticationAssurance = 1
	localChallenge, err := service.CreateChallenge(ctx, localActor, iam.ReauthenticationOperationUserRevokeSessions, request)
	if err != nil {
		t.Fatalf("local CreateChallenge() error = %v", err)
	}
	localEvidence, err := service.CompleteChallenge(ctx, localActor, localChallenge.ID, iam.CompleteReauthenticationCommand{}, request)
	if err != nil {
		t.Fatalf("local CompleteChallenge() error = %v", err)
	}
	if authorizeErr := service.Authorize(ctx, localActor, string(iam.ReauthenticationOperationUserRevokeSessions), iam.HighRiskProof{
		ChallengeID: localChallenge.ID.String(), Evidence: localEvidence.Evidence, Confirmed: true,
	}, request); authorizeErr != nil {
		t.Fatalf("local Authorize() error = %v", authorizeErr)
	}

	expiringChallenge, err := service.CreateChallenge(ctx, creator, iam.ReauthenticationOperationSSODisable, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.91"})
	if err != nil {
		t.Fatal(err)
	}
	expiringEvidence, err := service.CompleteChallenge(ctx, completer, expiringChallenge.ID, iam.CompleteReauthenticationCommand{}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.91"})
	if err != nil {
		t.Fatal(err)
	}
	pendingChallenge, err := service.CreateChallenge(ctx, creator, iam.ReauthenticationOperationUserEnable, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.91"})
	if err != nil {
		t.Fatal(err)
	}
	futureService, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: goodAuditor, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now.Add(6 * time.Minute) }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := futureService.Authorize(ctx, completer, string(iam.ReauthenticationOperationSSODisable), iam.HighRiskProof{
		ChallengeID: expiringChallenge.ID.String(), Evidence: expiringEvidence.Evidence, Confirmed: true,
	}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.92"}); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("expired evidence authorization error = %v", err)
	}
	if _, err := futureService.CreateChallenge(ctx, creator, iam.ReauthenticationOperationUserDisable, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.92"}); err != nil {
		t.Fatalf("trigger pending cleanup: %v", err)
	}
	for name, challengeID := range map[string]uuid.UUID{"verified": expiringChallenge.ID, "pending": pendingChallenge.ID} {
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, challengeID).Scan(&status); err != nil || status != "expired" {
			t.Fatalf("%s challenge cleanup status = %q, %v", name, status, err)
		}
	}
}

func TestIAMPostgresHighRiskWritesUseProductionProofAndTransactionalAudit(t *testing.T) {
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
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 18, 0, 0, 0, time.UTC)
	sourceID, userID, emergencyID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, required_mappings_complete, verified_configuration_version, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'High Risk OIDC', 'oidc', 'verified', TRUE, 1, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed high-risk source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES
	    ($1, 'highrisk.target', 'High Risk Target', 'local', 'active', FALSE, $3, 1, $3, $3),
	    ($2, 'highrisk.breakglass', 'High Risk Break Glass', 'emergency', 'active', TRUE, $3, 1, $3, $3)`, userID, emergencyID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed high-risk users: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts, password_changed_at
) VALUES ($1, 'argon2id', 'm=19456,t=1,p=1', decode(repeat('11', 16), 'hex'), decode(repeat('22', 32), 'hex'), 0, $2)`, userID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed high-risk local credential: %v", err)
	}
	seedIntegrationUsableEmergencyAdministrator(t, ctx, pool, emergencyID, now)
	insertSession := func(label string) uuid.UUID {
		t.Helper()
		sessionID := uuid.New()
		if _, insertErr := pool.Exec(ctx, `
INSERT INTO local_sessions (
    id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at,
    last_used_at, absolute_expires_at, idle_expires_at, version
) VALUES ($1, $2, $3, 'local_password', 0, $4, $4, $5, $5, 1)`,
			sessionID, integrationSHA256Hex(label), userID, now.Add(-time.Hour), now.Add(time.Hour)); insertErr != nil {
			t.Fatal(insertErr)
		}
		return sessionID
	}
	insertSession("role-delete-session")

	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	reauthentication, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: auditor, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: auditor, Sessions: repository, Passwords: passwords,
		HighRisk: reauthentication, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	creator := identity.Principal{
		Subject: "postgres.admin", Kind: identity.PrincipalKindHuman, TokenID: "oidc-old-token", Governed: true,
		IdentitySourceID: uuid.NewString(), GovernedUserID: uuid.NewString(),
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
	actor := creator
	actor.TokenID = "oidc-fresh-token"
	actor.AuthenticatedAt = now.Add(-time.Minute)
	actor.AuthenticationAssurance = 1
	auditRequests := make([]string, 0, 7)
	proofFor := func(operation iam.ReauthenticationOperation) (iam.HighRiskProof, iam.RequestContext) {
		t.Helper()
		return completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, operation)
	}

	proof, request := proofFor(iam.ReauthenticationOperationRoleBindingCreate)
	binding, err := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
		SubjectType: iam.SubjectTypeUser, SubjectID: userID, SubjectVersion: 1, Role: identity.RoleViewer,
		ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectAllow,
	}, proof, request)
	if err != nil {
		t.Fatalf("CreateRoleBinding() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)

	proof, request = proofFor(iam.ReauthenticationOperationRoleBindingDelete)
	if err := service.DeleteRoleBinding(ctx, actor, binding.ID, 1, proof, request); err != nil {
		t.Fatalf("DeleteRoleBinding() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)

	insertSession("disable-session")
	proof, request = proofFor(iam.ReauthenticationOperationUserDisable)
	if err := service.DisableUser(ctx, actor, userID, 1, "security incident", proof, request); err != nil {
		t.Fatalf("DisableUser() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)
	proof, request = proofFor(iam.ReauthenticationOperationUserEnable)
	if err := service.EnableUser(ctx, actor, userID, 2, "incident resolved", proof, request); err != nil {
		t.Fatalf("EnableUser() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)

	insertSession("explicit-revoke-session")
	proof, request = proofFor(iam.ReauthenticationOperationUserRevokeSessions)
	if err := service.RevokeUserSessions(ctx, actor, userID, 3, "credential rotation", proof, request); err != nil {
		t.Fatalf("RevokeUserSessions() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)
	var userStatus iam.UserStatus
	var userVersion, activeSessions int
	if err := pool.QueryRow(ctx, `SELECT status, version FROM user_principals WHERE id=$1`, userID).Scan(&userStatus, &userVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE subject_id=$1 AND revoked_at IS NULL`, userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if userStatus != iam.UserStatusActive || userVersion != 3 || activeSessions != 0 {
		t.Fatalf("user lifecycle state: status=%s version=%d active_sessions=%d", userStatus, userVersion, activeSessions)
	}

	proof, request = proofFor(iam.ReauthenticationOperationSSOEnable)
	if err := service.EnableSSO(ctx, actor, sourceID, 1, proof, request); err != nil {
		t.Fatalf("EnableSSO() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)
	proof, request = proofFor(iam.ReauthenticationOperationSSODisable)
	if err := service.DisableSSO(ctx, actor, sourceID, 2, proof, request); err != nil {
		t.Fatalf("DisableSSO() error = %v", err)
	}
	auditRequests = append(auditRequests, request.RequestID)
	var loginMode iam.LoginMode
	var sourceStatus iam.IdentitySourceStatus
	var sourceVersion int64
	if err := pool.QueryRow(ctx, `SELECT login_mode FROM iam_login_state WHERE singleton=TRUE`).Scan(&loginMode); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status, version FROM identity_sources WHERE id=$1`, sourceID).Scan(&sourceStatus, &sourceVersion); err != nil {
		t.Fatal(err)
	}
	if loginMode != iam.LoginModeLocal || sourceStatus != iam.IdentitySourceStatusDisabled || sourceVersion != 3 {
		t.Fatalf("SSO lifecycle state: mode=%s source_status=%s source_version=%d", loginMode, sourceStatus, sourceVersion)
	}
	var mutationAuditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id = ANY($1::uuid[]) AND action IN (
        'identity.role_binding.create', 'identity.role_binding.delete', 'identity.user.disable', 'identity.user.enable',
        'identity.user.revoke_sessions', 'identity.sso.enable', 'identity.sso.disable')`, auditRequests).Scan(&mutationAuditCount); err != nil {
		t.Fatal(err)
	}
	if mutationAuditCount != 7 {
		t.Fatalf("business mutation audit count = %d", mutationAuditCount)
	}

	rollbackSession := insertSession("business-audit-rollback-session")
	rollbackProof, rollbackRequest := proofFor(iam.ReauthenticationOperationUserRevokeSessions)
	failingBusiness, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: failingIAMAuditAppender{}, Sessions: repository, Passwords: passwords,
		HighRisk: reauthentication, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := failingBusiness.RevokeUserSessions(ctx, actor, userID, 3, "audit rollback", rollbackProof, rollbackRequest); !errors.Is(err, errIntegrationAuditFailure) {
		t.Fatalf("RevokeUserSessions(audit failure) error = %v", err)
	}
	var revokedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT revoked_at FROM local_sessions WHERE id=$1`, rollbackSession).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt != nil {
		t.Fatalf("business mutation committed despite audit failure: revoked_at=%s", revokedAt)
	}
	if err := service.RevokeUserSessions(ctx, actor, userID, 3, "replay after rollback", rollbackProof, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.103"}); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("consumed proof replay error = %v", err)
	}
}

func TestIAMPostgresRoleBindingCatalogScopeRejectsTOCTOUAndDirectGhostAuthorization(t *testing.T) {
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
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM/catalog tables: %v", err)
	}

	now := time.Date(2026, 8, 20, 20, 0, 0, 0, time.UTC)
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, username, display_name, user_kind, status, version, created_at, updated_at)
VALUES ($1, 'scope.target', 'Scope Target', 'local', 'active', 1, $2, $2)`, userID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "scope.admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "scope-admin-token"}

	for name, scopeType := range map[string]iam.ScopeType{"product": iam.ScopeTypeProduct, "channel": iam.ScopeTypeChannel} {
		t.Run(name+" disappears after preflight", func(t *testing.T) {
			productID := "scope-" + name + "-" + uuid.NewString()
			insertIntegrationProduct(t, ctx, pool, productID)
			channelName := ""
			if scopeType == iam.ScopeTypeChannel {
				channelName = "stable"
				if _, insertErr := pool.Exec(ctx, `
INSERT INTO product_channels (product_id, name, display_name, position, created_at)
VALUES ($1, $2, 'Stable', 0, $3)`, productID, channelName, now.Add(-time.Hour)); insertErr != nil {
					t.Fatal(insertErr)
				}
			}
			blockingProof := &blockingIntegrationHighRiskAuthorizer{reached: make(chan struct{}), release: make(chan struct{})}
			repository := iam.NewPostgresRepository(pool)
			service, serviceErr := iam.NewService(iam.ServiceConfig{
				Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Sessions: repository,
				Passwords: passwords, HighRisk: blockingProof, Clock: func() time.Time { return now },
			})
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			result := make(chan error, 1)
			go func() {
				_, createErr := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
					SubjectType: iam.SubjectTypeUser, SubjectID: userID, SubjectVersion: 1,
					Role: identity.RoleViewer, ScopeType: scopeType, ProductID: productID,
					ChannelName: channelName, Effect: iam.BindingEffectAllow,
				}, iam.HighRiskProof{Confirmed: true, ChallengeID: "scope", Evidence: "scope"}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.120"})
				result <- createErr
			}()
			select {
			case <-blockingProof.reached:
			case <-ctx.Done():
				t.Fatal("role-binding create did not reach proof consumption")
			}
			if scopeType == iam.ScopeTypeChannel {
				_, err = pool.Exec(ctx, `DELETE FROM product_channels WHERE product_id=$1 AND name=$2`, productID, channelName)
			} else {
				_, err = pool.Exec(ctx, `DELETE FROM products WHERE id=$1`, productID)
			}
			if err != nil {
				t.Fatalf("remove preflight scope: %v", err)
			}
			close(blockingProof.release)
			if createErr := <-result; !errors.Is(createErr, iam.ErrRoleBindingInvalid) {
				t.Fatalf("CreateRoleBinding(after scope removal) error = %v", createErr)
			}
			if blockingProof.calls.Load() != 1 {
				t.Fatalf("proof consumption calls = %d", blockingProof.calls.Load())
			}
			var bindingCount int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE product_id=$1`, productID).Scan(&bindingCount); err != nil {
				t.Fatal(err)
			}
			if bindingCount != 0 {
				t.Fatalf("ghost role bindings = %d", bindingCount)
			}
		})
	}

	databaseGuardProductID := "scope-db-" + uuid.NewString()
	insertIntegrationProduct(t, ctx, pool, databaseGuardProductID)
	ghostBindingID := uuid.New()
	_, err = pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, product_id, channel_name,
    effect, valid_from, created_by, version, created_at, updated_at
) VALUES ($1, 'user', $2, 'viewer', 'channel', $3, 'ghost',
          'allow', $4, 'database-bypass', 1, $4, $4)`, ghostBindingID, userID, databaseGuardProductID, now)
	if err == nil {
		_, _ = pool.Exec(ctx, `DELETE FROM role_bindings WHERE id=$1`, ghostBindingID)
		t.Fatal("database accepted a channel-scoped ghost role binding")
	}
}

func TestIAMPostgresBreakGlassInvariantUsesCredentialAndEffectiveAdministratorAccess(t *testing.T) {
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
	now := time.Date(2026, 8, 20, 21, 0, 0, 0, time.UTC)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "breakglass.admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "breakglass-admin-token"}

	for _, test := range []struct {
		name           string
		credential     bool
		inheritedAllow bool
		directAllow    bool
		directDeny     bool
		expiredAllow   bool
		wantError      bool
	}{
		{name: "credential missing", directAllow: true, wantError: true},
		{name: "administrator binding missing", credential: true, wantError: true},
		{name: "organization administrator allow", credential: true, inheritedAllow: true},
		{name: "direct deny overrides organization allow", credential: true, inheritedAllow: true, directDeny: true, wantError: true},
		{name: "expired administrator allow", credential: true, expiredAllow: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, resetErr := pool.Exec(ctx, `
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); resetErr != nil {
				t.Fatal(resetErr)
			}
			sourceID, emergencyID, organizationID := uuid.New(), uuid.New(), uuid.New()
			if _, seedErr := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, required_mappings_complete, verified_configuration_version, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Break Glass OIDC', 'oidc', 'verified', TRUE, 1, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); seedErr != nil {
				t.Fatal(seedErr)
			}
			if _, seedErr := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, 'effective.breakglass', 'Effective Break Glass', 'emergency', 'active', TRUE, $2, 1, $2, $2)`, emergencyID, now.Add(-time.Hour)); seedErr != nil {
				t.Fatal(seedErr)
			}
			if test.credential {
				if _, seedErr := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts,
    password_changed_at, mfa_secret_reference
) VALUES ($1, 'argon2id', 'm=19456,t=1,p=1,l=32', decode(repeat('11', 16), 'hex'),
          decode(repeat('22', 32), 'hex'), 0, $2, 'secret://mfa/effective-breakglass')`, emergencyID, now.Add(-time.Hour)); seedErr != nil {
					t.Fatal(seedErr)
				}
			}
			if test.inheritedAllow {
				if _, seedErr := pool.Exec(ctx, `
INSERT INTO organization_units (id, external_id, name, source_owned, status, version, created_at, updated_at)
VALUES ($1, '', 'Emergency Administrators', FALSE, 'active', 1, $2, $2)`, organizationID, now.Add(-time.Hour)); seedErr != nil {
					t.Fatal(seedErr)
				}
				if _, seedErr := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id, user_id, source_owned, status, version, created_at, updated_at)
VALUES ($1, $2, FALSE, 'active', 1, $3, $3)`, organizationID, emergencyID, now.Add(-time.Hour)); seedErr != nil {
					t.Fatal(seedErr)
				}
				if _, seedErr := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($3, 'organization', $1, 'admin', 'platform', 'allow', $2,
          'test:bootstrap', 1, $2, $2)`, organizationID, now.Add(-time.Hour), uuid.New()); seedErr != nil {
					t.Fatal(seedErr)
				}
			}
			if test.directAllow || test.directDeny || test.expiredAllow {
				effect := "allow"
				validUntil := any(nil)
				if test.directDeny {
					effect = "deny"
				}
				if test.expiredAllow {
					validUntil = now.Add(-time.Minute)
				}
				if _, seedErr := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from, valid_until,
    created_by, version, created_at, updated_at
) VALUES ($1, 'user', $2, 'admin', 'platform', $3, $4, $5,
          'test:bootstrap', 1, $4, $4)`, uuid.New(), emergencyID, effect, now.Add(-time.Hour), validUntil); seedErr != nil {
					t.Fatal(seedErr)
				}
			}
			repository := iam.NewPostgresRepository(pool)
			service, serviceErr := iam.NewService(iam.ServiceConfig{
				Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: audit.NewService(audit.NewPostgresRepository(pool)),
				Sessions: integrationSessionRevoker{}, Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
			})
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			enableErr := service.EnableSSO(ctx, actor, sourceID, 1,
				iam.HighRiskProof{Confirmed: true, ChallengeID: "effective", Evidence: "effective"},
				iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.121"})
			if test.wantError && !errors.Is(enableErr, iam.ErrSSOPreconditionFailed) {
				t.Fatalf("EnableSSO() error = %v", enableErr)
			}
			if !test.wantError && enableErr != nil {
				t.Fatalf("EnableSSO() error = %v", enableErr)
			}
		})
	}
}

func TestIAMPostgresBreakGlassScheduledPermissionContinuity(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	now := time.Date(2026, 8, 20, 21, 30, 0, 0, time.UTC)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	creator := identity.Principal{
		Subject: "scheduled.admin", Kind: identity.PrincipalKindHuman, TokenID: "scheduled-old-token", Governed: true,
		IdentitySourceID: uuid.NewString(), GovernedUserID: uuid.NewString(),
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
	actor := creator
	actor.TokenID = "scheduled-fresh-token"
	actor.AuthenticatedAt = now.Add(-time.Minute)
	actor.AuthenticationAssurance = 1
	fakeProof := iam.HighRiskProof{Confirmed: true, ChallengeID: "scheduled", Evidence: "scheduled"}
	request := func() iam.RequestContext {
		return iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.123"}
	}
	reset := func(t *testing.T) {
		t.Helper()
		if _, resetErr := pool.Exec(ctx, `
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); resetErr != nil {
			t.Fatal(resetErr)
		}
	}
	seedEmergency := func(t *testing.T, username string) (uuid.UUID, uuid.UUID) {
		t.Helper()
		userID := uuid.New()
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, $2, $2, 'emergency', 'active', TRUE, $3, 1, $3, $3)`, userID, username, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		return userID, seedIntegrationUsableEmergencyAdministrator(t, ctx, pool, userID, now)
	}
	seedSource := func(t *testing.T) uuid.UUID {
		t.Helper()
		sourceID := uuid.New()
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, required_mappings_complete, verified_configuration_version, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Scheduled OIDC', 'oidc', 'verified', TRUE, 1, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		return sourceID
	}
	newService := func(t *testing.T, authorizer iam.HighRiskAuthorizer, auditor iam.AuditAppender) *iam.Service {
		t.Helper()
		repository := iam.NewPostgresRepository(pool)
		service, serviceErr := iam.NewService(iam.ServiceConfig{
			Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: auditor,
			Sessions: integrationSessionRevoker{}, Passwords: passwords, HighRisk: authorizer, Clock: func() time.Time { return now },
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		return service
	}
	realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
	reauthenticationRepository := iam.NewPostgresRepository(pool)
	reauthentication, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: reauthenticationRepository, Auditor: realAuditor, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	proofFor := func(t *testing.T, operation iam.ReauthenticationOperation) (iam.HighRiskProof, iam.RequestContext) {
		t.Helper()
		return completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, operation)
	}

	t.Run("future deny cannot remove the only emergency administrator", func(t *testing.T) {
		reset(t)
		emergencyID, _ := seedEmergency(t, "scheduled.future.deny")
		proof, mutationRequest := proofFor(t, iam.ReauthenticationOperationRoleBindingCreate)
		service := newService(t, reauthentication, realAuditor)

		_, createErr := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
			SubjectType: iam.SubjectTypeUser, SubjectID: emergencyID, SubjectVersion: 1,
			Role: identity.RoleAdmin, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectDeny,
			ValidFrom: now.Add(time.Hour),
		}, proof, mutationRequest)

		if !errors.Is(createErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("CreateRoleBinding(future deny) error = %v", createErr)
		}
		var denyCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE subject_id=$1 AND effect='deny'`, emergencyID).Scan(&denyCount); err != nil {
			t.Fatal(err)
		}
		if denyCount != 0 {
			t.Fatalf("scheduled gap deny bindings = %d", denyCount)
		}
		requireIntegrationProofConsumedAndUnreplayable(
			t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationRoleBindingCreate, proof,
		)
	})

	t.Run("permanent allow cannot be deleted when only expiring access remains", func(t *testing.T) {
		reset(t)
		emergencyID, permanentBindingID := seedEmergency(t, "scheduled.expiring.allow")
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from, valid_until,
    created_by, version, created_at, updated_at
) VALUES ($1, 'user', $2, 'admin', 'platform', 'allow', $3, $4,
          'test:bootstrap', 1, $3, $3)`, uuid.New(), emergencyID, now.Add(-time.Hour), now.Add(time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		proof, mutationRequest := proofFor(t, iam.ReauthenticationOperationRoleBindingDelete)
		service := newService(t, reauthentication, realAuditor)

		deleteErr := service.DeleteRoleBinding(ctx, actor, permanentBindingID, 1, proof, mutationRequest)

		if !errors.Is(deleteErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("DeleteRoleBinding(permanent allow) error = %v", deleteErr)
		}
		var permanentCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE id=$1`, permanentBindingID).Scan(&permanentCount); err != nil {
			t.Fatal(err)
		}
		if permanentCount != 1 {
			t.Fatal("permanent allow deletion was committed")
		}
		requireIntegrationProofConsumedAndUnreplayable(
			t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationRoleBindingDelete, proof,
		)
	})

	t.Run("future deny is allowed when a backup remains at the boundary", func(t *testing.T) {
		reset(t)
		firstID, _ := seedEmergency(t, "scheduled.safe.one")
		_, _ = seedEmergency(t, "scheduled.safe.two")
		authorizer := &countingIntegrationHighRiskAuthorizer{}
		service := newService(t, authorizer, realAuditor)

		binding, createErr := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
			SubjectType: iam.SubjectTypeUser, SubjectID: firstID, SubjectVersion: 1,
			Role: identity.RoleAdmin, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectDeny,
			ValidFrom: now.Add(365 * 24 * time.Hour),
		}, fakeProof, request())

		if createErr != nil {
			t.Fatalf("CreateRoleBinding(future deny with backup) error = %v", createErr)
		}
		if authorizer.calls.Load() != 1 || binding.ID == uuid.Nil {
			t.Fatalf("safe scheduled mutation result: calls=%d binding=%s", authorizer.calls.Load(), binding.ID)
		}
	})

	for _, test := range []struct {
		name       string
		allow      iam.SubjectType
		futureDeny iam.SubjectType
	}{
		{name: "organization allow direct deny", allow: iam.SubjectTypeOrganization, futureDeny: iam.SubjectTypeUser},
		{name: "direct allow organization deny", allow: iam.SubjectTypeUser, futureDeny: iam.SubjectTypeOrganization},
	} {
		t.Run(test.name, func(t *testing.T) {
			reset(t)
			emergencyID, directAllowID := seedEmergency(t, "scheduled.organization")
			organizationID := uuid.New()
			if _, seedErr := pool.Exec(ctx, `
INSERT INTO organization_units (id, external_id, name, source_owned, status, version, created_at, updated_at)
VALUES ($1, '', 'Scheduled Emergency Administrators', FALSE, 'active', 1, $2, $2)`, organizationID, now.Add(-time.Hour)); seedErr != nil {
				t.Fatal(seedErr)
			}
			if _, seedErr := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id, user_id, source_owned, status, version, created_at, updated_at)
VALUES ($1, $3, FALSE, 'active', 1, $2, $2)`, organizationID, now.Add(-time.Hour), emergencyID); seedErr != nil {
				t.Fatal(seedErr)
			}
			if test.allow == iam.SubjectTypeOrganization {
				if _, seedErr := pool.Exec(ctx, `DELETE FROM role_bindings WHERE id=$1`, directAllowID); seedErr != nil {
					t.Fatal(seedErr)
				}
				if _, seedErr := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($1, 'organization', $2, 'admin', 'platform', 'allow', $3,
          'test:bootstrap', 1, $3, $3)`, uuid.New(), organizationID, now.Add(-time.Hour)); seedErr != nil {
					t.Fatal(seedErr)
				}
			}
			denySubjectID := emergencyID
			if test.futureDeny == iam.SubjectTypeOrganization {
				denySubjectID = organizationID
			}
			authorizer := &countingIntegrationHighRiskAuthorizer{}
			service := newService(t, authorizer, realAuditor)

			_, createErr := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
				SubjectType: test.futureDeny, SubjectID: denySubjectID, SubjectVersion: 1,
				Role: identity.RoleAdmin, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectDeny,
				ValidFrom: now.Add(time.Hour),
			}, fakeProof, request())

			if !errors.Is(createErr, iam.ErrLastEmergencyAdministrator) {
				t.Fatalf("CreateRoleBinding(future deny) error = %v", createErr)
			}
			if authorizer.calls.Load() != 1 {
				t.Fatalf("proof consumption calls = %d", authorizer.calls.Load())
			}
		})
	}

	t.Run("allow ending when successor starts has no gap", func(t *testing.T) {
		reset(t)
		emergencyID, currentAllowID := seedEmergency(t, "scheduled.adjacent")
		boundary := now.Add(time.Hour)
		if _, seedErr := pool.Exec(ctx, `UPDATE role_bindings SET valid_until=$2 WHERE id=$1`, currentAllowID, boundary); seedErr != nil {
			t.Fatal(seedErr)
		}
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($2, 'user', $3, 'admin', 'platform', 'allow', $1,
          'test:bootstrap', 1, $4, $4)`, boundary, uuid.New(), emergencyID, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		sourceID := seedSource(t)
		authorizer := &countingIntegrationHighRiskAuthorizer{}
		service := newService(t, authorizer, realAuditor)

		if enableErr := service.EnableSSO(ctx, actor, sourceID, 1, fakeProof, request()); enableErr != nil {
			t.Fatalf("EnableSSO(adjacent bindings) error = %v", enableErr)
		}
	})

	t.Run("SSO enable fails closed on an existing scheduled gap", func(t *testing.T) {
		reset(t)
		_, currentAllowID := seedEmergency(t, "scheduled.sso.gap")
		if _, seedErr := pool.Exec(ctx, `UPDATE role_bindings SET valid_until=$2 WHERE id=$1`, currentAllowID, now.Add(time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		sourceID := seedSource(t)
		proof, mutationRequest := proofFor(t, iam.ReauthenticationOperationSSOEnable)
		service := newService(t, reauthentication, realAuditor)

		enableErr := service.EnableSSO(ctx, actor, sourceID, 1, proof, mutationRequest)

		if !errors.Is(enableErr, iam.ErrSSOPreconditionFailed) {
			t.Fatalf("EnableSSO(scheduled gap) error = %v", enableErr)
		}
		var loginMode iam.LoginMode
		if err := pool.QueryRow(ctx, `SELECT login_mode FROM iam_login_state WHERE singleton=TRUE`).Scan(&loginMode); err != nil {
			t.Fatal(err)
		}
		if loginMode != iam.LoginModeLocal {
			t.Fatalf("login mode = %s", loginMode)
		}
		requireIntegrationProofConsumedAndUnreplayable(
			t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationSSOEnable, proof,
		)
	})

	t.Run("user disable fails closed on an existing scheduled gap", func(t *testing.T) {
		reset(t)
		firstID, _ := seedEmergency(t, "scheduled.disable.one")
		_, expiringAllowID := seedEmergency(t, "scheduled.disable.two")
		if _, seedErr := pool.Exec(ctx, `UPDATE role_bindings SET valid_until=$2 WHERE id=$1`, expiringAllowID, now.Add(time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		proof, mutationRequest := proofFor(t, iam.ReauthenticationOperationUserDisable)
		service := newService(t, reauthentication, realAuditor)

		disableErr := service.DisableUser(ctx, actor, firstID, 1, "scheduled continuity", proof, mutationRequest)

		if !errors.Is(disableErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("DisableUser(scheduled gap) error = %v", disableErr)
		}
		var status iam.UserStatus
		if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, firstID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != iam.UserStatusActive {
			t.Fatalf("emergency user status = %s", status)
		}
		requireIntegrationProofConsumedAndUnreplayable(
			t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationUserDisable, proof,
		)
	})

	t.Run("audit failure rolls back a continuity-safe scheduled mutation", func(t *testing.T) {
		reset(t)
		firstID, _ := seedEmergency(t, "scheduled.audit.one")
		_, _ = seedEmergency(t, "scheduled.audit.two")
		authorizer := &countingIntegrationHighRiskAuthorizer{}
		service := newService(t, authorizer, failingIAMAuditAppender{})

		_, createErr := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
			SubjectType: iam.SubjectTypeUser, SubjectID: firstID, SubjectVersion: 1,
			Role: identity.RoleAdmin, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectDeny,
			ValidFrom: now.Add(time.Hour),
		}, fakeProof, request())

		if !errors.Is(createErr, errIntegrationAuditFailure) {
			t.Fatalf("CreateRoleBinding(audit failure) error = %v", createErr)
		}
		if authorizer.calls.Load() != 1 {
			t.Fatalf("proof consumption calls = %d", authorizer.calls.Load())
		}
		var denyCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE subject_id=$1 AND effect='deny'`, firstID).Scan(&denyCount); err != nil {
			t.Fatal(err)
		}
		if denyCount != 0 {
			t.Fatalf("audit failure committed scheduled deny count = %d", denyCount)
		}
	})
}

func TestIAMPostgresBreakGlassInvariantSerializesConcurrentReductionsAndRollsBackAuditFailure(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	now := time.Date(2026, 8, 20, 22, 0, 0, 0, time.UTC)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "concurrency.admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "concurrency-admin-token"}
	proof := iam.HighRiskProof{Confirmed: true, ChallengeID: "concurrency", Evidence: "concurrency"}
	request := func() iam.RequestContext {
		return iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.122"}
	}
	reset := func(t *testing.T) {
		t.Helper()
		if _, resetErr := pool.Exec(ctx, `
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); resetErr != nil {
			t.Fatal(resetErr)
		}
	}
	seedEmergency := func(t *testing.T, username string) (uuid.UUID, uuid.UUID) {
		t.Helper()
		userID, bindingID := uuid.New(), uuid.New()
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, $2, $2, 'emergency', 'active', TRUE, $3, 1, $3, $3)`, userID, username, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts,
    password_changed_at, mfa_secret_reference
) VALUES ($1, 'argon2id', 'm=19456,t=1,p=1,l=32', decode(repeat('11', 16), 'hex'),
          decode(repeat('22', 32), 'hex'), 0, $2, 'secret://mfa/concurrent-breakglass')`, userID, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($3, 'user', $1, 'admin', 'platform', 'allow', $2,
          'test:bootstrap', 1, $2, $2)`, userID, now.Add(-time.Hour), bindingID); seedErr != nil {
			t.Fatal(seedErr)
		}
		return userID, bindingID
	}

	t.Run("two user disables leave one usable emergency administrator", func(t *testing.T) {
		reset(t)
		firstID, _ := seedEmergency(t, "concurrent.breakglass.one")
		secondID, _ := seedEmergency(t, "concurrent.breakglass.two")
		repository := iam.NewPostgresRepository(pool)
		auditor := newRendezvousIAMAuditor(audit.NewService(audit.NewPostgresRepository(pool)), "identity.user.disable")
		service, serviceErr := iam.NewService(iam.ServiceConfig{
			Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: auditor, Sessions: integrationSessionRevoker{},
			Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, userID := range []uuid.UUID{firstID, secondID} {
			userID := userID
			go func() {
				<-start
				results <- service.DisableUser(ctx, actor, userID, 1, "concurrent response", proof, request())
			}()
		}
		close(start)
		successes, invariantFailures := 0, 0
		for index := 0; index < 2; index++ {
			resultErr := <-results
			if resultErr == nil {
				successes++
			} else if errors.Is(resultErr, iam.ErrLastEmergencyAdministrator) {
				invariantFailures++
			} else {
				t.Fatalf("DisableUser() error = %v", resultErr)
			}
		}
		var active int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_principals WHERE user_kind='emergency' AND status='active'`).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if successes != 1 || invariantFailures != 1 || active != 1 {
			t.Fatalf("concurrent disable results: success=%d invariant=%d active=%d", successes, invariantFailures, active)
		}
	})

	t.Run("SSO enable and user disable cannot jointly remove break glass", func(t *testing.T) {
		reset(t)
		emergencyID, _ := seedEmergency(t, "sso.concurrent.breakglass")
		fakeEmergencyID := uuid.New()
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, 'sso.concurrent.fake', 'SSO Concurrent Fake', 'emergency', 'active', TRUE, $2, 1, $2, $2)`, fakeEmergencyID, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		sourceID := uuid.New()
		if _, seedErr := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, required_mappings_complete, verified_configuration_version, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Concurrent OIDC', 'oidc', 'verified', TRUE, 1, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		repository := iam.NewPostgresRepository(pool)
		auditor := newRendezvousIAMAuditor(audit.NewService(audit.NewPostgresRepository(pool)), "identity.user.disable", "identity.sso.enable")
		service, serviceErr := iam.NewService(iam.ServiceConfig{
			Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: auditor, Sessions: integrationSessionRevoker{},
			Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		start := make(chan struct{})
		enableResult, disableResult := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			enableResult <- service.EnableSSO(ctx, actor, sourceID, 1, proof, request())
		}()
		go func() {
			<-start
			disableResult <- service.DisableUser(ctx, actor, emergencyID, 1, "concurrent SSO transition", proof, request())
		}()
		close(start)
		if enableErr := <-enableResult; enableErr != nil {
			t.Fatalf("EnableSSO() error = %v", enableErr)
		}
		if disableErr := <-disableResult; !errors.Is(disableErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("DisableUser() error = %v", disableErr)
		}
		var realStatus iam.UserStatus
		if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, emergencyID).Scan(&realStatus); err != nil {
			t.Fatal(err)
		}
		if realStatus != iam.UserStatusActive {
			t.Fatalf("real emergency administrator status = %s", realStatus)
		}
	})

	t.Run("deleting last binding fails and audit outage rolls back a safe deletion", func(t *testing.T) {
		reset(t)
		firstID, firstBindingID := seedEmergency(t, "delete.breakglass.one")
		_, secondBindingID := seedEmergency(t, "delete.breakglass.two")
		repository := iam.NewPostgresRepository(pool)
		service, serviceErr := iam.NewService(iam.ServiceConfig{
			Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: failingIAMAuditAppender{}, Sessions: integrationSessionRevoker{},
			Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		if deleteErr := service.DeleteRoleBinding(ctx, actor, firstBindingID, 1, proof, request()); !errors.Is(deleteErr, errIntegrationAuditFailure) {
			t.Fatalf("DeleteRoleBinding(audit failure) error = %v", deleteErr)
		}
		var firstBindingCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE id=$1`, firstBindingID).Scan(&firstBindingCount); err != nil {
			t.Fatal(err)
		}
		if firstBindingCount != 1 {
			t.Fatal("audit failure committed administrator binding deletion")
		}
		realService, serviceErr := iam.NewService(iam.ServiceConfig{
			Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Sessions: integrationSessionRevoker{},
			Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		if deleteErr := realService.DeleteRoleBinding(ctx, actor, firstBindingID, 1, proof, request()); deleteErr != nil {
			t.Fatalf("DeleteRoleBinding(first of two) error = %v", deleteErr)
		}
		if deleteErr := realService.DeleteRoleBinding(ctx, actor, secondBindingID, 1, proof, request()); !errors.Is(deleteErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("DeleteRoleBinding(last) error = %v", deleteErr)
		}
		var userStatus iam.UserStatus
		if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, firstID).Scan(&userStatus); err != nil {
			t.Fatal(err)
		}
		if userStatus != iam.UserStatusActive {
			t.Fatalf("emergency user status = %s", userStatus)
		}
	})
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
    id, name, source_kind, status, required_mappings_complete, verified_configuration_version, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Barrier OIDC', 'oidc', 'verified', TRUE, 1, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed barrier source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at,
    version, created_at, updated_at
) VALUES ($1, 'barrier-emergency', 'Barrier Emergency', 'emergency', 'active', TRUE, $2, 1, $2, $2)`, emergencyID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed barrier emergency account: %v", err)
	}
	seedIntegrationUsableEmergencyAdministrator(t, ctx, pool, emergencyID, now)
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
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Sessions: repository,
		Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	switchDone := make(chan error, 1)
	go func() {
		switchDone <- service.EnableSSO(ctx,
			identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "barrier-admin"},
			sourceID, 1, iam.HighRiskProof{Confirmed: true, ChallengeID: "barrier", Evidence: "barrier"},
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
INSERT INTO organization_memberships (organization_id, user_id, source_owned, status, version, created_at, updated_at)
VALUES ($1, $2, FALSE, 'active', 1, $3, $3)`, organizationID, userID, now.Add(-time.Hour)); err != nil {
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
    id, name, source_kind, status, required_mappings_complete, verified_configuration_version, verified_at, previewed_at,
    version, created_at, updated_at
) VALUES ($1, 'Corporate OIDC', 'oidc', 'verified', TRUE, 1, $2, $2, 1, $2, $2)
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
	seedIntegrationUsableEmergencyAdministrator(t, ctx, pool, emergencyID, now)

	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: auditor, Sessions: integrationSessionRevoker{}, Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "admin-token"}
	err = service.EnableSSO(ctx, actor, sourceID, 1, iam.HighRiskProof{Confirmed: true, ChallengeID: "test", Evidence: "test"}, iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "127.0.0.1"})
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
	resolveHuman := func(sourceID uuid.UUID, subject string) (identity.Principal, error) {
		return resolver.ResolvePrincipal(ctx, identity.Principal{
			Subject: subject, Kind: identity.PrincipalKindHuman, IdentitySourceID: sourceID.String(),
			Roles: []identity.Role{identity.RoleAdmin}, ProductIDs: []string{"untrusted-product"},
		})
	}
	assertOnlyRole := func(t *testing.T, principal identity.Principal, userID uuid.UUID, role identity.Role) {
		t.Helper()
		if !principal.Governed || principal.GovernedUserID != userID.String() || len(principal.Roles) != 0 || len(principal.ProductIDs) != 0 || len(principal.RoleScopes) != 1 || principal.RoleScopes[0].Role != role {
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
		resolved, resolveErr := resolveHuman(sourceAID, "shared-subject")
		if resolveErr != nil {
			t.Fatalf("ResolvePrincipal() error = %v", resolveErr)
		}
		assertOnlyRole(t, resolved, sourceAUserID, identity.RoleViewer)
	})

	t.Run("subject from wrong source fails closed", func(t *testing.T) {
		_, resolveErr := resolveHuman(sourceAID, "wrong-source-only")
		assertUnavailable(t, resolveErr)
	})

	t.Run("switching active source selects the other duplicate subject", func(t *testing.T) {
		if _, updateErr := pool.Exec(ctx, `UPDATE iam_login_state SET active_source_id=$1, version=version+1, updated_at=$2 WHERE singleton=TRUE`, sourceBID, now.Add(time.Minute)); updateErr != nil {
			t.Fatal(updateErr)
		}
		resolved, resolveErr := resolveHuman(sourceBID, "shared-subject")
		if resolveErr != nil {
			t.Fatalf("ResolvePrincipal() error = %v", resolveErr)
		}
		assertOnlyRole(t, resolved, sourceBUserID, identity.RolePublisher)
	})

	t.Run("verified source binding cannot replay across active source switch", func(t *testing.T) {
		_, resolveErr := resolveHuman(sourceAID, "shared-subject")
		assertUnavailable(t, resolveErr)
	})

	t.Run("disabled active source fails closed", func(t *testing.T) {
		if _, updateErr := pool.Exec(ctx, `UPDATE identity_sources SET status='disabled', version=version+1, updated_at=$2 WHERE id=$1`, sourceBID, now.Add(2*time.Minute)); updateErr != nil {
			t.Fatal(updateErr)
		}
		_, resolveErr := resolveHuman(sourceBID, "shared-subject")
		assertUnavailable(t, resolveErr)
	})

	t.Run("disabled active-source user fails closed", func(t *testing.T) {
		if _, updateErr := pool.Exec(ctx, `UPDATE iam_login_state SET active_source_id=$1, version=version+1, updated_at=$2 WHERE singleton=TRUE`, sourceAID, now.Add(3*time.Minute)); updateErr != nil {
			t.Fatal(updateErr)
		}
		_, resolveErr := resolveHuman(sourceAID, "disabled-user")
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
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{},
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
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords, HighRisk: integrationHighRiskAuthorizer{},
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
		SubjectType: iam.SubjectTypeUser, SubjectID: userID, SubjectVersion: 1, Role: identity.RoleAuditor, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectAllow,
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

type rendezvousIAMAuditor struct {
	delegate iam.AuditAppender
	actions  map[string]struct{}
	reached  atomic.Int64
	ready    chan struct{}
	once     sync.Once
}

func newRendezvousIAMAuditor(delegate iam.AuditAppender, actions ...string) *rendezvousIAMAuditor {
	selected := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		selected[action] = struct{}{}
	}
	return &rendezvousIAMAuditor{delegate: delegate, actions: selected, ready: make(chan struct{})}
}

func (auditor *rendezvousIAMAuditor) Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	if _, selected := auditor.actions[command.Action]; selected {
		if auditor.reached.Add(1) == 2 {
			auditor.once.Do(func() { close(auditor.ready) })
		}
		select {
		case <-auditor.ready:
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return audit.Event{}, ctx.Err()
		}
	}
	return auditor.delegate.Append(ctx, tx, command)
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

func (integrationHighRiskAuthorizer) Authorize(context.Context, identity.Principal, string, iam.HighRiskProof, iam.RequestContext) error {
	return nil
}

type countingIntegrationHighRiskAuthorizer struct{ calls atomic.Int64 }

func (authorizer *countingIntegrationHighRiskAuthorizer) Authorize(context.Context, identity.Principal, string, iam.HighRiskProof, iam.RequestContext) error {
	authorizer.calls.Add(1)
	return nil
}

type blockingIntegrationHighRiskAuthorizer struct {
	reached chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (authorizer *blockingIntegrationHighRiskAuthorizer) Authorize(ctx context.Context, _ identity.Principal, _ string, _ iam.HighRiskProof, _ iam.RequestContext) error {
	authorizer.calls.Add(1)
	close(authorizer.reached)
	select {
	case <-authorizer.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type integrationLocalReauthenticator struct{}

func (integrationLocalReauthenticator) Reauthenticate(context.Context, identity.Principal, iam.CompleteReauthenticationCommand, iam.RequestContext) error {
	return nil
}

func integrationSHA256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func seedIntegrationUsableEmergencyAdministrator(t *testing.T, ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, userID uuid.UUID, now time.Time) uuid.UUID {
	t.Helper()
	if _, err := executor.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts,
    password_changed_at, mfa_secret_reference
) VALUES ($1, 'argon2id', 'm=19456,t=1,p=1,l=32', decode(repeat('11', 16), 'hex'),
          decode(repeat('22', 32), 'hex'), 0, $2, $3)`, userID, now.Add(-time.Hour), "secret://mfa/"+userID.String()); err != nil {
		t.Fatalf("seed usable emergency credential: %v", err)
	}
	bindingID := uuid.New()
	if _, err := executor.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($1, 'user', $2, 'admin', 'platform', 'allow', $3,
          'test:bootstrap', 1, $3, $3)`, bindingID, userID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed usable emergency administrator binding: %v", err)
	}
	return bindingID
}

func completeIntegrationReauthenticationProof(
	t *testing.T,
	ctx context.Context,
	reauthentication *iam.ReauthenticationService,
	creator identity.Principal,
	completer identity.Principal,
	operation iam.ReauthenticationOperation,
) (iam.HighRiskProof, iam.RequestContext) {
	t.Helper()
	created, err := reauthentication.CreateChallenge(
		ctx,
		creator,
		operation,
		iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.100"},
	)
	if err != nil {
		t.Fatalf("CreateChallenge(%s) error = %v", operation, err)
	}
	completed, err := reauthentication.CompleteChallenge(
		ctx,
		completer,
		created.ID,
		iam.CompleteReauthenticationCommand{},
		iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.101"},
	)
	if err != nil {
		t.Fatalf("CompleteChallenge(%s) error = %v", operation, err)
	}
	return iam.HighRiskProof{
		ChallengeID: created.ID.String(),
		Evidence:    completed.Evidence,
		Confirmed:   true,
	}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.102"}
}

func requireIntegrationProofConsumedAndUnreplayable(
	t *testing.T,
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	reauthentication *iam.ReauthenticationService,
	actor identity.Principal,
	operation iam.ReauthenticationOperation,
	proof iam.HighRiskProof,
) {
	t.Helper()
	challengeID, err := uuid.Parse(proof.ChallengeID)
	if err != nil || challengeID.Version() != 7 {
		t.Fatalf("proof challenge ID is not a production UUIDv7: %v", err)
	}
	var status iam.ReauthenticationStatus
	var consumedAt *time.Time
	var actorBound, operationBound, tokenBound bool
	if err := queryer.QueryRow(ctx, `
SELECT status,
       consumed_at,
       actor_subject=$2 AND actor_kind=$3,
       operation=$4,
       verified_token_digest=$5
FROM iam_reauthentication_challenges
WHERE id=$1`, challengeID, actor.Subject, actor.Kind, operation, integrationSHA256Hex(actor.TokenID)).Scan(
		&status,
		&consumedAt,
		&actorBound,
		&operationBound,
		&tokenBound,
	); err != nil {
		t.Fatalf("load consumed reauthentication challenge: %v", err)
	}
	if status != iam.ReauthenticationStatusConsumed || consumedAt == nil || !actorBound || !operationBound || !tokenBound {
		t.Fatalf(
			"reauthentication challenge terminal state: status=%s consumed=%t actor_bound=%t operation_bound=%t token_bound=%t",
			status,
			consumedAt != nil,
			actorBound,
			operationBound,
			tokenBound,
		)
	}
	if err := reauthentication.Authorize(
		ctx,
		actor,
		string(operation),
		proof,
		iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.124"},
	); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("replayed production proof error = %v", err)
	}
}
