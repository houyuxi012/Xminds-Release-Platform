package integration_test

import (
	"context"
	"errors"
	"sync"
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

func TestIdentitySourceVerificationAuditFailureRollsBackCapabilityGeneration(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetIdentitySourceCapabilityFixture(t, ctx, pool)
	now := time.Date(2026, 8, 21, 15, 0, 0, 0, time.UTC)
	sourceID := seedDraftIdentitySourceCapabilityFixture(t, ctx, pool, now, 3, 4)
	service := newIdentitySourceCapabilityService(t, pool, successfulIdentitySourceDirectoryAdapter{}, failingIAMAuditAppender{}, now)

	_, err = service.VerifyIdentitySourceVersioned(ctx, identitySourceCapabilityActor(), sourceID, 4, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.101"})
	if !errors.Is(err, errIntegrationAuditFailure) {
		t.Fatalf("VerifyIdentitySourceVersioned() error = %v", err)
	}

	var status iam.IdentitySourceStatus
	var mappingsComplete bool
	var verifiedConfigurationVersion *int64
	var verifiedAt *time.Time
	var configurationVersion, version int64
	if err := pool.QueryRow(ctx, `
SELECT status, required_mappings_complete, verified_configuration_version, verified_at, configuration_version, version
FROM identity_sources WHERE id=$1`, sourceID).Scan(&status, &mappingsComplete, &verifiedConfigurationVersion, &verifiedAt, &configurationVersion, &version); err != nil {
		t.Fatal(err)
	}
	if status != iam.IdentitySourceStatusDraft || mappingsComplete || verifiedConfigurationVersion != nil || verifiedAt != nil || configurationVersion != 3 || version != 4 {
		t.Fatalf("verification rollback state: status=%s mappings=%t verified_configuration=%v verified_at=%v configuration=%d version=%d", status, mappingsComplete, verifiedConfigurationVersion, verifiedAt, configurationVersion, version)
	}
}

func TestIdentitySourceVerificationAndPatchRaceCommitsOnlyCurrentConfiguration(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetIdentitySourceCapabilityFixture(t, ctx, pool)
	now := time.Date(2026, 8, 21, 15, 30, 0, 0, time.UTC)
	sourceID := seedDraftIdentitySourceCapabilityFixture(t, ctx, pool, now, 1, 1)
	adapter := &blockingIdentitySourceDirectoryAdapter{reached: make(chan struct{}), release: make(chan struct{})}
	verifyingService := newIdentitySourceCapabilityService(t, pool, adapter, audit.NewService(audit.NewPostgresRepository(pool)), now)
	patchingService := newIdentitySourceCapabilityService(t, pool, successfulIdentitySourceDirectoryAdapter{}, audit.NewService(audit.NewPostgresRepository(pool)), now.Add(time.Second))
	verifyResult := make(chan error, 1)

	go func() {
		_, verifyErr := verifyingService.VerifyIdentitySourceVersioned(ctx, identitySourceCapabilityActor(), sourceID, 1, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.102"})
		verifyResult <- verifyErr
	}()
	select {
	case <-adapter.reached:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	name := "Corporate OIDC v2"
	patched, err := patchingService.PatchIdentitySourceDraft(ctx, identitySourceCapabilityActor(), sourceID, iam.PatchIdentitySourceCommand{Name: &name, Version: 1}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.103"})
	if err != nil {
		t.Fatal(err)
	}
	close(adapter.release)
	if verifyErr := <-verifyResult; !errors.Is(verifyErr, iam.ErrIAMConflict) {
		t.Fatalf("VerifyIdentitySourceVersioned() race error = %v", verifyErr)
	}
	if patched.ConfigurationVersion != 2 || patched.Version != 2 || patched.RequiredMappingsComplete || patched.VerifiedConfigurationVersion != 0 {
		t.Fatalf("patched source = %+v", patched)
	}

	var storedName string
	var status iam.IdentitySourceStatus
	var mappingsComplete bool
	var verifiedConfigurationVersion *int64
	var configurationVersion, version int64
	if err := pool.QueryRow(ctx, `
SELECT name, status, required_mappings_complete, verified_configuration_version, configuration_version, version
FROM identity_sources WHERE id=$1`, sourceID).Scan(&storedName, &status, &mappingsComplete, &verifiedConfigurationVersion, &configurationVersion, &version); err != nil {
		t.Fatal(err)
	}
	if storedName != name || status != iam.IdentitySourceStatusDraft || mappingsComplete || verifiedConfigurationVersion != nil || configurationVersion != 2 || version != 2 {
		t.Fatalf("race state: name=%q status=%s mappings=%t verified_configuration=%v configuration=%d version=%d", storedName, status, mappingsComplete, verifiedConfigurationVersion, configurationVersion, version)
	}
}

// Mutation caught: checking only the preflight capability (or reporting the
// stale aggregate version first) lets a proof-consumed SSO request obscure the
// authoritative post-proof capability failure.
func TestEnableSSORechecksCapabilityAfterPersistedProofConsumption(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetIdentitySourceCapabilityFixture(t, ctx, pool)
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	sourceID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, secret_reference, required_mappings_complete,
    configuration_version, verified_configuration_version, verified_at, previewed_at, version, created_at, updated_at
) VALUES ($1, 'Corporate OIDC', 'oidc', 'verified', 'secret://iam/corporate', TRUE, 1, 1, $2, $2, 1, $2, $2)`, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	emergencyID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled, credential_rotated_at, version, created_at, updated_at
) VALUES ($1, 'capability.breakglass', 'Capability Break Glass', 'emergency', 'active', TRUE, $2, 1, $2, $2)`, emergencyID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	seedIntegrationUsableEmergencyAdministrator(t, ctx, pool, emergencyID, now)

	repository := iam.NewPostgresRepository(pool)
	realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
	reauthentication, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: realAuditor, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	creator := identity.Principal{
		Subject: "capability.admin", Kind: identity.PrincipalKindHuman, TokenID: "capability-old-token", Governed: true,
		IdentitySourceID: uuid.NewString(), GovernedUserID: uuid.NewString(),
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
	actor := creator
	actor.TokenID = "capability-fresh-token"
	actor.AuthenticatedAt = now.Add(-time.Minute)
	actor.AuthenticationAssurance = 1
	proof, request := completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, iam.ReauthenticationOperationSSOEnable)
	blockingProof := &blockingAfterIdentitySourceProofAuthorizer{delegate: reauthentication, reached: make(chan struct{}), release: make(chan struct{})}
	enablingService := newIdentitySourceCapabilityServiceWithConfig(t, iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository),
		Auditor: realAuditor, Sessions: repository, Directory: successfulIdentitySourceDirectoryAdapter{},
		HighRisk: blockingProof, Clock: func() time.Time { return now },
	})
	verifyService := newIdentitySourceCapabilityService(t, pool, incompleteIdentitySourceDirectoryAdapter{}, realAuditor, now.Add(time.Second))
	enableResult := make(chan error, 1)

	go func() {
		enableResult <- enablingService.EnableSSO(ctx, actor, sourceID, 1, proof, request)
	}()
	select {
	case <-blockingProof.reached:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := verifyService.VerifyIdentitySourceVersioned(ctx, identitySourceCapabilityActor(), sourceID, 1, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.104"}); err != nil {
		t.Fatal(err)
	}
	close(blockingProof.release)
	if enableErr := <-enableResult; !errors.Is(enableErr, iam.ErrSSOPreconditionFailed) {
		t.Fatalf("EnableSSO(post-proof capability race) error = %v", enableErr)
	}

	var loginMode iam.LoginMode
	var status iam.IdentitySourceStatus
	var mappingsComplete bool
	var verifiedConfigurationVersion *int64
	var version int64
	if err := pool.QueryRow(ctx, `SELECT login_mode FROM iam_login_state WHERE singleton=TRUE`).Scan(&loginMode); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status,required_mappings_complete,verified_configuration_version,version FROM identity_sources WHERE id=$1`, sourceID).Scan(&status, &mappingsComplete, &verifiedConfigurationVersion, &version); err != nil {
		t.Fatal(err)
	}
	if loginMode != iam.LoginModeLocal || status != iam.IdentitySourceStatusVerified || mappingsComplete || verifiedConfigurationVersion != nil || version != 2 {
		t.Fatalf("post-proof rollback state: mode=%s status=%s mappings=%t verified_configuration=%v version=%d", loginMode, status, mappingsComplete, verifiedConfigurationVersion, version)
	}
	requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationSSOEnable, proof)
}

func TestDirectorySyncJobHistoryUsesSourceScopedTotalOrder(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetIdentitySourceCapabilityFixture(t, ctx, pool)
	now := time.Date(2026, 8, 21, 16, 30, 0, 0, time.UTC)
	sourceID := seedDraftIdentitySourceCapabilityFixture(t, ctx, pool, now, 1, 1)
	otherSourceID := seedDraftIdentitySourceCapabilityFixture(t, ctx, pool, now.Add(time.Second), 1, 1)
	jobIDs := []uuid.UUID{
		uuid.MustParse("0198c1d5-00b0-7000-8000-000000000001"),
		uuid.MustParse("0198c1d5-00b0-7000-8000-000000000002"),
		uuid.MustParse("0198c1d5-00b0-7000-8000-000000000003"),
	}
	for _, jobID := range jobIDs {
		if _, err := pool.Exec(ctx, `
INSERT INTO directory_sync_jobs (
    id, identity_source_id, source_version, run_marker, mode, status, phase,
    requested_by, request_id, created_at, updated_at, completed_at
) VALUES ($1, $2, 1, $1, 'preview', 'completed', 'finalize', 'test:history', $3, $4, $4, $4)`, jobID, sourceID, uuid.New(), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO directory_sync_jobs (
    id, identity_source_id, source_version, run_marker, mode, status, phase,
    requested_by, request_id, created_at, updated_at, completed_at
) VALUES ($1, $2, 1, $1, 'preview', 'completed', 'finalize', 'test:other-source', $3, $4, $4, $4)`, uuid.New(), otherSourceID, uuid.New(), now); err != nil {
		t.Fatal(err)
	}

	repository := iam.NewPostgresRepository(pool)
	page := iam.Page{Limit: 1}
	seen := make([]uuid.UUID, 0, len(jobIDs))
	for range jobIDs {
		result, err := repository.ListDirectorySyncJobs(ctx, sourceID, page)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != 1 {
			t.Fatalf("history page = %+v", result)
		}
		seen = append(seen, result.Items[0].ID)
		page.BeforeTime = result.Items[0].CreatedAt
		page.BeforeID = result.Items[0].ID
	}
	if seen[0] != jobIDs[2] || seen[1] != jobIDs[1] || seen[2] != jobIDs[0] {
		t.Fatalf("source-scoped total order = %v", seen)
	}
	finalPage, err := repository.ListDirectorySyncJobs(ctx, sourceID, page)
	if err != nil {
		t.Fatal(err)
	}
	if len(finalPage.Items) != 0 {
		t.Fatalf("cross-source job leaked: %+v", finalPage.Items)
	}
}

func resetIdentitySourceCapabilityFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
}

func seedDraftIdentitySourceCapabilityFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, now time.Time, configurationVersion, version int64) uuid.UUID {
	t.Helper()
	sourceID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, secret_reference, configuration_version, version, created_at, updated_at
) VALUES ($1, $5, 'oidc', 'draft', 'secret://iam/corporate', $2, $3, $4, $4)`, sourceID, configurationVersion, version, now, "Corporate OIDC "+sourceID.String()); err != nil {
		t.Fatal(err)
	}
	return sourceID
}

func newIdentitySourceCapabilityService(t *testing.T, pool *pgxpool.Pool, directory iam.DirectoryAdapter, auditor iam.AuditAppender, now time.Time) *iam.Service {
	t.Helper()
	repository := iam.NewPostgresRepository(pool)
	return newIdentitySourceCapabilityServiceWithConfig(t, iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository),
		Auditor: auditor, Directory: directory, Clock: func() time.Time { return now },
	})
}

func newIdentitySourceCapabilityServiceWithConfig(t *testing.T, config iam.ServiceConfig) *iam.Service {
	t.Helper()
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	config.Passwords = passwords
	service, err := iam.NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func identitySourceCapabilityActor() identity.Principal {
	return identity.Principal{Subject: "capability.admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
}

type successfulIdentitySourceDirectoryAdapter struct{}

func (successfulIdentitySourceDirectoryAdapter) Verify(context.Context, iam.IdentitySource) (iam.CapabilityReport, error) {
	return iam.CapabilityReport{Reachable: true, RequiredAttributes: []string{"subject", "roles"}, RequiredMappingsComplete: true, SupportsPagination: true}, nil
}

func (successfulIdentitySourceDirectoryAdapter) Preview(context.Context, iam.IdentitySource) (iam.SyncDiff, error) {
	return iam.SyncDiff{}, nil
}

func (successfulIdentitySourceDirectoryAdapter) Sync(context.Context, iam.IdentitySource, string) (iam.SyncPage, error) {
	return iam.SyncPage{}, nil
}

type incompleteIdentitySourceDirectoryAdapter struct{}

func (incompleteIdentitySourceDirectoryAdapter) Verify(context.Context, iam.IdentitySource) (iam.CapabilityReport, error) {
	return iam.CapabilityReport{Reachable: true, RequiredAttributes: []string{"subject", "roles"}, RequiredMappingsComplete: false, SupportsPagination: true}, nil
}

func (incompleteIdentitySourceDirectoryAdapter) Preview(context.Context, iam.IdentitySource) (iam.SyncDiff, error) {
	return iam.SyncDiff{}, nil
}

func (incompleteIdentitySourceDirectoryAdapter) Sync(context.Context, iam.IdentitySource, string) (iam.SyncPage, error) {
	return iam.SyncPage{}, nil
}

type blockingAfterIdentitySourceProofAuthorizer struct {
	delegate iam.HighRiskAuthorizer
	reached  chan struct{}
	release  chan struct{}
}

func (authorizer *blockingAfterIdentitySourceProofAuthorizer) Authorize(ctx context.Context, actor identity.Principal, operation string, proof iam.HighRiskProof, request iam.RequestContext) error {
	if err := authorizer.delegate.Authorize(ctx, actor, operation, proof, request); err != nil {
		return err
	}
	close(authorizer.reached)
	select {
	case <-authorizer.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type blockingIdentitySourceDirectoryAdapter struct {
	once    sync.Once
	reached chan struct{}
	release chan struct{}
}

func (adapter *blockingIdentitySourceDirectoryAdapter) Verify(ctx context.Context, _ iam.IdentitySource) (iam.CapabilityReport, error) {
	adapter.once.Do(func() { close(adapter.reached) })
	select {
	case <-adapter.release:
		return successfulIdentitySourceDirectoryAdapter{}.Verify(ctx, iam.IdentitySource{})
	case <-ctx.Done():
		return iam.CapabilityReport{}, ctx.Err()
	}
}

func (adapter *blockingIdentitySourceDirectoryAdapter) Preview(context.Context, iam.IdentitySource) (iam.SyncDiff, error) {
	return iam.SyncDiff{}, nil
}

func (adapter *blockingIdentitySourceDirectoryAdapter) Sync(context.Context, iam.IdentitySource, string) (iam.SyncPage, error) {
	return iam.SyncPage{}, nil
}
