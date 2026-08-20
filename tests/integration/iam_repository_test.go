package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

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
		Repository: repository, Auditor: auditor, Sessions: integrationSessionRevoker{}, Passwords: passwords,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "admin-token"}
	err = service.EnableSSO(ctx, actor, sourceID, iam.HighRiskConfirmation{
		Confirmed: true, ReauthenticatedAt: now.Add(-time.Minute),
	}, iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "127.0.0.1"})
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

type integrationBreachChecker struct{}

func (integrationBreachChecker) IsBreached(context.Context, string) (bool, error) { return false, nil }

type integrationSessionRevoker struct{}

func (integrationSessionRevoker) RevokeSubject(context.Context, uuid.UUID, string) error { return nil }
