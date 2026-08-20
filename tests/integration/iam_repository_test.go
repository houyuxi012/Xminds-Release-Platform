package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

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
	authenticator, err := iam.NewLocalAuthService(iam.LocalAuthConfig{
		Repository: repository, Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Passwords: passwords,
		MFA: &integrationMFAVerifier{}, Policy: iam.DefaultLocalAuthPolicy(), Clock: func() time.Time { return now },
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
	if err := repository.RevokeSubject(ctx, userID, "integration-test"); err != nil {
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
	request := iam.RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e92", SourceIP: "127.0.0.1"}
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action IN ('identity.organization.create', 'identity.role_binding.create', 'identity.source.create')`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 3 {
		t.Fatalf("governed resource audit count = %d", auditCount)
	}
}

type integrationBreachChecker struct{}

func (integrationBreachChecker) IsBreached(context.Context, string) (bool, error) { return false, nil }

type integrationMFAVerifier struct{ counter atomic.Int64 }

func (verifier *integrationMFAVerifier) Verify(context.Context, string, string) (iam.MFAAssertion, error) {
	return iam.MFAAssertion{Counter: verifier.counter.Add(1)}, nil
}

type integrationSessionRevoker struct{}

func (integrationSessionRevoker) RevokeSubject(context.Context, uuid.UUID, string) error { return nil }

type integrationHighRiskAuthorizer struct{}

func (integrationHighRiskAuthorizer) Authorize(context.Context, identity.Principal, string, iam.HighRiskProof) error {
	return nil
}
