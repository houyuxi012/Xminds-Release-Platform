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
	passwords, err := iam.NewActivationCredentialManager()
	if err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords,
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
	passwords, err := iam.NewActivationCredentialManager()
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
	request := iam.RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e92", SourceIP: "127.0.0.1"}
	organization, err := service.CreateOrganization(ctx, actor, iam.CreateOrganizationCommand{Name: "Release Engineering"}, request)
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	if _, err := service.CreateRoleBinding(ctx, actor, iam.CreateRoleBindingCommand{
		SubjectType: iam.SubjectTypeUser, SubjectID: userID, Role: identity.RoleAuditor, ScopeType: iam.ScopeTypePlatform, Effect: iam.BindingEffectAllow,
	}, request); err != nil {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action IN ('identity.organization.create', 'identity.role_binding.create', 'identity.source.create')`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 3 {
		t.Fatalf("governed resource audit count = %d", auditCount)
	}
}

type integrationBreachChecker struct{}

func (integrationBreachChecker) IsBreached(context.Context, string) (bool, error) { return false, nil }

type integrationSessionRevoker struct{}

func (integrationSessionRevoker) RevokeSubject(context.Context, uuid.UUID, string) error { return nil }
