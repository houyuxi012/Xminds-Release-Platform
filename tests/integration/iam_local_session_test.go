package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

const (
	integrationLocalSessionUsername = "session.integration.admin"
	integrationLocalSessionPassword = "Session-Integration-Password-2026!"
)

func TestIAMLocalSessionSurvivesServiceReconstruction(t *testing.T) {
	harness := newIntegrationLocalSessionHarness(t)
	login := harness.login(t)

	restartedRepository := iam.NewPostgresRepository(harness.pool)
	restartedVerifier, err := iam.NewSessionVerifier(restartedRepository, iam.DefaultLocalAuthPolicy(), harness.clock)
	if err != nil {
		t.Fatal(err)
	}
	restartedResolver, err := iam.NewGovernedPrincipalResolver(restartedRepository, harness.clock)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := restartedVerifier.Verify(harness.ctx, login.AccessToken)
	if err != nil {
		t.Fatalf("Verify() after service reconstruction error=%v", err)
	}
	governed, err := restartedResolver.ResolvePrincipal(harness.ctx, verified)
	if err != nil {
		t.Fatalf("ResolvePrincipal() after service reconstruction error=%v", err)
	}

	if governed.Subject != integrationLocalSessionUsername || governed.Kind != identity.PrincipalKindLocal ||
		!governed.Governed || governed.GovernedUserID != harness.userID.String() || governed.TokenID == "" ||
		governed.AuthenticationAssurance != 1 {
		t.Fatalf("governed principal=%+v", governed)
	}
	if len(governed.RoleScopes) != 1 || governed.RoleScopes[0] != (identity.RoleScope{
		Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform",
	}) {
		t.Fatalf("governed role scopes=%+v", governed.RoleScopes)
	}

	var persistedSubject uuid.UUID
	var active bool
	if err := harness.pool.QueryRow(harness.ctx, `
SELECT subject_id, revoked_at IS NULL
FROM local_sessions
WHERE id=$1`, governed.TokenID).Scan(&persistedSubject, &active); err != nil {
		t.Fatal(err)
	}
	if persistedSubject != harness.userID || !active {
		t.Fatalf("persisted session subject=%s active=%t", persistedSubject, active)
	}
}

func TestIAMLogoutRevokesOnlyCurrentPersistedSession(t *testing.T) {
	harness := newIntegrationLocalSessionHarness(t)
	firstLogin := harness.login(t)
	secondLogin := harness.login(t)

	verifier, err := iam.NewSessionVerifier(iam.NewPostgresRepository(harness.pool), iam.DefaultLocalAuthPolicy(), harness.clock)
	if err != nil {
		t.Fatal(err)
	}
	firstPrincipal, err := verifier.Verify(harness.ctx, firstLogin.AccessToken)
	if err != nil {
		t.Fatalf("Verify(first) error=%v", err)
	}
	secondPrincipal, err := verifier.Verify(harness.ctx, secondLogin.AccessToken)
	if err != nil {
		t.Fatalf("Verify(second) error=%v", err)
	}
	logoutRequest := iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.45"}
	if err := harness.service.LogoutCurrentSession(harness.ctx, firstPrincipal, logoutRequest); err != nil {
		t.Fatalf("LogoutCurrentSession() error=%v", err)
	}

	if _, err := verifier.Verify(harness.ctx, firstLogin.AccessToken); !errors.Is(err, identity.ErrAuthenticationFailed) {
		t.Fatalf("Verify(revoked first) error=%v, want authentication failure", err)
	}
	if _, err := verifier.Verify(harness.ctx, secondLogin.AccessToken); err != nil {
		t.Fatalf("Verify(active second) error=%v", err)
	}

	firstSessionID := uuid.MustParse(firstPrincipal.TokenID)
	secondSessionID := uuid.MustParse(secondPrincipal.TokenID)
	var revokedSessionCount, activeSessionCount, logoutAuditCount int
	if err := harness.pool.QueryRow(harness.ctx, `
SELECT count(*) FROM local_sessions
WHERE id=$1 AND revoked_at IS NOT NULL AND revocation_reason <> ''`, firstSessionID).Scan(&revokedSessionCount); err != nil {
		t.Fatal(err)
	}
	if err := harness.pool.QueryRow(harness.ctx, `
SELECT count(*) FROM local_sessions
WHERE id=$1 AND revoked_at IS NULL AND revocation_reason = ''`, secondSessionID).Scan(&activeSessionCount); err != nil {
		t.Fatal(err)
	}
	if err := harness.pool.QueryRow(harness.ctx, `
SELECT count(*) FROM audit_events
WHERE request_id=$1 AND action='identity.session.logout' AND resource_type='local_session'
  AND resource_id=$2 AND outcome='success'`, logoutRequest.RequestID, firstSessionID.String()).Scan(&logoutAuditCount); err != nil {
		t.Fatal(err)
	}
	if revokedSessionCount != 1 || activeSessionCount != 1 || logoutAuditCount != 1 {
		t.Fatalf("revoked=%d active=%d logout_audit=%d", revokedSessionCount, activeSessionCount, logoutAuditCount)
	}
}

type integrationLocalSessionHarness struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	service *iam.LocalAuthService
	clock   func() time.Time
	userID  uuid.UUID
	mfa     *integrationMFAVerifier
}

func newIntegrationLocalSessionHarness(t *testing.T) *integrationLocalSessionHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, integrationDatabaseURL(t), "iam_local_session_")
	t.Cleanup(func() {
		pool.Close()
		dropContext, dropCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dropCancel()
		_, _ = adminPool.Exec(dropContext, `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	requirePostgreSQLMajorVersion(t, ctx, pool)

	now := time.Date(2026, 8, 30, 4, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	passwordDigest, err := passwords.Hash(ctx, integrationLocalSessionPassword)
	if err != nil {
		t.Fatal(err)
	}
	dummyPassword, err := iam.NewDummyPasswordDigest(ctx, passwords)
	if err != nil {
		t.Fatal(err)
	}

	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled,
    credential_rotated_at, version, created_at, updated_at
) VALUES ($1,$2,'Session Integration Administrator','local','active',TRUE,$3,1,$3,$3)`,
		userID, integrationLocalSessionUsername, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts,
    password_changed_at, mfa_secret_reference, mfa_last_counter
) VALUES ($1,$2,$3,$4,$5,0,$6,$7,-1)`, userID, passwordDigest.Algorithm,
		passwordDigest.Parameters, passwordDigest.Salt, passwordDigest.DerivedKey,
		now.Add(-time.Hour), "secret://iam-mfa/integration-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($1,'user',$2,'admin','platform','allow',$3,'test:bootstrap',1,$3,$3)`,
		uuid.New(), userID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	repository := iam.NewPostgresRepository(pool)
	mfa := &integrationMFAVerifier{}
	service, err := iam.NewLocalAuthService(iam.LocalAuthConfig{
		Repository:    repository,
		Auditor:       audit.NewService(audit.NewPostgresRepository(pool)),
		Passwords:     passwords,
		DummyPassword: dummyPassword,
		MFA:           mfa,
		Policy:        iam.DefaultLocalAuthPolicy(),
		Clock:         clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &integrationLocalSessionHarness{
		ctx: ctx, pool: pool, service: service, clock: clock, userID: userID, mfa: mfa,
	}
}

func (harness *integrationLocalSessionHarness) login(t *testing.T) iam.LoginResult {
	t.Helper()
	result, err := harness.service.LoginLocal(harness.ctx, iam.LocalLoginCommand{
		Username: integrationLocalSessionUsername,
		Password: integrationLocalSessionPassword,
		MFAProof: "123456",
	}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.44"})
	if err != nil {
		t.Fatalf("LoginLocal() error=%v", err)
	}
	if result.AccessToken == "" || result.Subject.ID != harness.userID {
		t.Fatalf("LoginLocal() returned invalid subject or empty token")
	}
	return result
}
