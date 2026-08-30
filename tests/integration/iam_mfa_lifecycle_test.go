package integration_test

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

// Mutation caught: omitting the MFA lifecycle migration leaves enrollment and
// recovery-code state outside the transactional IAM authority.
func TestIAMMFALifecycleMigrationCreatesOwnedState(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_lifecycle_migration_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 19)); err != nil {
		t.Fatalf("apply migrations 1..19: %v", err)
	}

	for _, table := range []string{"iam_mfa_enrollments", "iam_mfa_recovery_codes", "iam_mfa_secret_gc"} {
		assertIntegrationTablePresence(t, ctx, pool, table, false)
	}
	checksums := migrationChecksums(t, ctx, pool, 19)
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("upgrade v19 to v20: %v", err)
	}
	for _, table := range []string{"iam_mfa_enrollments", "iam_mfa_recovery_codes", "iam_mfa_secret_gc"} {
		assertIntegrationTablePresence(t, ctx, pool, table, true)
	}
	for version, checksum := range checksums {
		var current string
		if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, version).Scan(&current); err != nil || current != checksum {
			t.Fatalf("migration %d checksum changed: before=%s after=%s error=%v", version, checksum, current, err)
		}
	}

	now := time.Date(2026, 8, 21, 15, 0, 0, 0, time.UTC)
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,$2,'MFA Fixture','local','pending',1,$3,$3)`, userID, "mfa.fixture."+userID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO local_credentials (user_id,failed_attempts,activation_digest,activation_expires_at) VALUES ($1,0,$2,$3)`, userID, strings.Repeat("a", 64), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	enrollmentID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	reference := "secret://iam-mfa/mfa-" + enrollmentID.String() + ".totp"
	if _, err := pool.Exec(ctx, `INSERT INTO iam_mfa_enrollments (id,user_id,purpose,status,secret_reference,expected_user_version,expires_at,version,created_at,updated_at) VALUES ($1,$2,'activation','pending',$3,1,$4,1,$5,$5)`, enrollmentID, userID, reference, now.Add(10*time.Minute), now); err != nil {
		t.Fatalf("insert valid pending enrollment: %v", err)
	}
	for _, test := range []struct {
		name      string
		statement string
		arguments []any
	}{
		{name: "non uuidv7 id", statement: `INSERT INTO iam_mfa_enrollments (id,user_id,purpose,status,secret_reference,expected_user_version,expires_at,version,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000001',$1,'activation','pending','secret://iam-mfa/mfa-00000000-0000-4000-8000-000000000001.totp',1,$2,1,$3,$3)`, arguments: []any{userID, now.Add(10 * time.Minute), now}},
		{name: "activation with creator binding", statement: `UPDATE iam_mfa_enrollments SET created_by_user_id=$2,creator_binding_version=1,creator_binding_digest=decode($3,'hex') WHERE id=$1`, arguments: []any{enrollmentID, userID, strings.Repeat("c", 64)}},
		{name: "rotation without creator binding", statement: `UPDATE iam_mfa_enrollments SET purpose='rotation' WHERE id=$1`, arguments: []any{enrollmentID}},
		{name: "confirmed null time", statement: `UPDATE iam_mfa_enrollments SET status='confirmed',confirmed_at=NULL WHERE id=$1`, arguments: []any{enrollmentID}},
		{name: "pending with time", statement: `UPDATE iam_mfa_enrollments SET confirmed_at=$2 WHERE id=$1`, arguments: []any{enrollmentID, now.Add(time.Minute)}},
		{name: "expired with time", statement: `UPDATE iam_mfa_enrollments SET status='expired',confirmed_at=$2 WHERE id=$1`, arguments: []any{enrollmentID, now.Add(time.Minute)}},
	} {
		assertIntegrationCheckViolation(t, ctx, pool, test.name, test.statement, test.arguments...)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO iam_mfa_recovery_codes (user_id,code_digest,generation_id,created_at) VALUES ($1,$2,$3,$4)`, userID, strings.Repeat("b", 64), enrollmentID, now); err != nil {
		t.Fatalf("insert valid recovery digest: %v", err)
	}
	assertIntegrationCheckViolation(t, ctx, pool, "uppercase digest", `INSERT INTO iam_mfa_recovery_codes (user_id,code_digest,generation_id,created_at) VALUES ($1,$2,$3,$4)`, userID, strings.Repeat("B", 64), enrollmentID, now)
	assertIntegrationCheckViolation(t, ctx, pool, "used before created", `UPDATE iam_mfa_recovery_codes SET used_at=$2 WHERE user_id=$1`, userID, now.Add(-time.Second))
	if _, err := pool.Exec(ctx, `INSERT INTO iam_mfa_secret_gc (secret_reference,state,not_before,attempts,last_error_code,created_at,updated_at) VALUES ($1,'pending',$2,0,'',$3,$3)`, reference, now.Add(time.Hour), now); err != nil {
		t.Fatalf("insert valid MFA secret GC item: %v", err)
	}
	var leaseColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='iam_mfa_secret_gc' AND column_name IN ('state','lease_token','leased_until')`).Scan(&leaseColumns); err != nil || leaseColumns != 3 {
		t.Fatalf("MFA secret GC lease columns=%d error=%v, want 3", leaseColumns, err)
	}
	assertIntegrationCheckViolation(t, ctx, pool, "GC negative attempts", `UPDATE iam_mfa_secret_gc SET attempts=-1 WHERE secret_reference=$1`, reference)
	assertIntegrationCheckViolation(t, ctx, pool, "GC dynamic error body", `UPDATE iam_mfa_secret_gc SET attempts=1,last_error_code='unlink failed: /secret/path' WHERE secret_reference=$1`, reference)
	assertIntegrationCheckViolation(t, ctx, pool, "GC pending with lease", `UPDATE iam_mfa_secret_gc SET lease_token=$2,leased_until=$3 WHERE secret_reference=$1`, reference, enrollmentID, now.Add(2*time.Hour))
	assertIntegrationCheckViolation(t, ctx, pool, "GC leased without token", `UPDATE iam_mfa_secret_gc SET state='leased',lease_token=NULL,leased_until=$2 WHERE secret_reference=$1`, reference, now.Add(2*time.Hour))
	assertIntegrationCheckViolation(t, ctx, pool, "GC leased without expiry", `UPDATE iam_mfa_secret_gc SET state='leased',lease_token=$2,leased_until=NULL WHERE secret_reference=$1`, reference, enrollmentID)
	assertIntegrationCheckViolation(t, ctx, pool, "GC non UUIDv7 lease", `UPDATE iam_mfa_secret_gc SET state='leased',lease_token='00000000-0000-4000-8000-000000000001',leased_until=$2 WHERE secret_reference=$1`, reference, now.Add(2*time.Hour))

	downSQL, err := fs.ReadFile(migrations.FS, "000020_mfa_lifecycle.down.sql")
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
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=20`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"iam_mfa_enrollments", "iam_mfa_recovery_codes", "iam_mfa_secret_gc"} {
		assertIntegrationTablePresence(t, ctx, pool, table, false)
	}
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("reapply v20: %v", err)
	}
}

// Mutation caught: queueing every replaced credential reference attempts to
// write legacy secret://iam references into the iam-mfa-only GC authority and
// either aborts rotation or crosses the read-only legacy root boundary.
func TestIAMMFARotationFromLegacyReferenceRetainsLegacyRootOutsideGC(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_legacy_rotation_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)
	sourceID, actorID, targetID := uuid.New(), uuid.New(), uuid.New()
	legacyReference := "secret://iam/legacy-emergency-admin.totp"
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id,name,source_kind,status,required_mappings_complete,configuration_version,
    verified_configuration_version,verified_at,version,created_at,updated_at
) VALUES ($1,'MFA Governance OIDC','oidc','enabled',TRUE,1,1,$2,1,$2,$2)
`, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed legacy rotation source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id,identity_source_id,external_subject,username,display_name,user_kind,status,
    version,created_at,updated_at
) VALUES ($1,$2,'mfa-governance-admin','mfa.governance.admin','MFA Governance Admin','external','active',1,$3,$3)
`, actorID, sourceID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed legacy rotation actor: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id,username,display_name,user_kind,status,mfa_enrolled,credential_rotated_at,
    version,created_at,updated_at
) VALUES ($1,'legacy.emergency.admin','Legacy Emergency Admin','emergency','active',TRUE,$2,1,$2,$2)
`, targetID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed legacy rotation target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id,algorithm,parameters,salt,derived_key,failed_attempts,password_changed_at,
    mfa_secret_reference,mfa_last_counter
) VALUES ($1,'argon2id','m=19456,t=1,p=1,l=32',$2,$3,0,$4,$5,9)
`, targetID, make([]byte, 16), make([]byte, 32), now.Add(-time.Hour), legacyReference); err != nil {
		t.Fatalf("seed legacy rotation credential: %v", err)
	}

	repository := iam.NewPostgresRepository(pool)
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	store := &integrationMFASecretStore{values: make(map[string][]byte)}
	verifier := &integrationMFAVerifier{}
	verifier.counter.Store(9)
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository),
		Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Sessions: repository, Passwords: passwords,
		HighRisk: integrationHighRiskAuthorizer{}, MFASecrets: store, MFAVerifier: verifier,
		MFAEnrollmentTTL: 10 * time.Minute, MFAIssuer: "Xminds Release Platform", Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{
		Subject: "mfa.governance.admin", Kind: identity.PrincipalKindHuman, Governed: true,
		GovernedUserID: actorID.String(), IdentitySourceID: sourceID.String(), TokenID: "mfa-governance-token",
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, ScopeType: "platform", Effect: "allow"}},
	}
	started, err := service.BeginMFARotation(ctx, actor, targetID, iam.BeginMFARotationCommand{UserVersion: 1, Reason: "Rotate legacy emergency factor."}, iam.HighRiskProof{Confirmed: true, ChallengeID: "test", Evidence: "test"}, iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("BeginMFARotation: %v", err)
	}
	if _, err := service.ConfirmMFARotation(ctx, actor, targetID, started.ID, iam.ConfirmMFARotationCommand{UserVersion: 1, MFAProof: "123456", Reason: "Confirm legacy factor replacement."}, iam.RequestContext{RequestID: uuid.New().String(), SourceIP: "127.0.0.1"}); err != nil {
		t.Fatalf("ConfirmMFARotation: %v", err)
	}

	var userVersion, gcRows, retainedAudit int
	var activeReference string
	if err := pool.QueryRow(ctx, `SELECT version FROM user_principals WHERE id=$1`, targetID).Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT mfa_secret_reference FROM local_credentials WHERE user_id=$1`, targetID).Scan(&activeReference); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_secret_gc WHERE secret_reference=$1`, legacyReference).Scan(&gcRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='identity.mfa_enrollment.confirm' AND metadata->>'legacy_reference_retained'='true'`).Scan(&retainedAudit); err != nil {
		t.Fatal(err)
	}
	if userVersion != 2 || activeReference != "secret://iam-mfa/mfa-"+started.ID.String()+".totp" || gcRows != 0 || retainedAudit != 1 || store.deleteCount.Load() != 0 {
		t.Fatalf("legacy rotation version=%d active=%q gc=%d retained_audit=%d deletes=%d", userVersion, activeReference, gcRows, retainedAudit, store.deleteCount.Load())
	}
}

// Mutation caught: coupling production proof consumption to emergency-user
// persistence permits replay after an audit outage and can expose a partially
// provisioned break-glass aggregate.
func TestIAMEmergencyProvisionAndReissueAuditFailureRollbackButConsumeProof(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_emergency_management_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)
	actorID := uuid.New()
	seedOrganizationMembershipEmergencyAdministrator(t, ctx, pool, actorID, now)
	repository := iam.NewPostgresRepository(pool)
	realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
	reauthentication, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: realAuditor, Local: integrationLocalReauthenticator{},
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
	newService := func(auditor iam.AuditAppender) *iam.Service {
		service, serviceErr := iam.NewService(iam.ServiceConfig{
			Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository),
			Auditor: auditor, Sessions: repository, Passwords: passwords, HighRisk: reauthentication, Clock: func() time.Time { return now },
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		return service
	}
	actor := organizationMembershipIntegrationActor(actorID, now)
	command := iam.CreateEmergencyUserCommand{
		Username: "emergency.secondary.pg", DisplayName: "Secondary Emergency PG", Email: "emergency.secondary.pg@example.com",
		Reason: "Provision secondary emergency administrator.",
	}
	proof, request := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationEmergencyUserCreate)
	if _, err := newService(failingIAMAuditAppender{}).ProvisionEmergencyUser(ctx, actor, command, proof, request); !errors.Is(err, errIntegrationAuditFailure) {
		t.Fatalf("ProvisionEmergencyUser(audit failure) error=%v", err)
	}
	var userRows, credentialRows, bindingRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_principals WHERE username=$1`, command.Username).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_credentials c JOIN user_principals u ON u.id=c.user_id WHERE u.username=$1`, command.Username).Scan(&credentialRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings b JOIN user_principals u ON u.id=b.subject_id WHERE b.subject_type='user' AND u.username=$1`, command.Username).Scan(&bindingRows); err != nil {
		t.Fatal(err)
	}
	if userRows != 0 || credentialRows != 0 || bindingRows != 0 {
		t.Fatalf("audit failure leaked emergency aggregate users=%d credentials=%d bindings=%d", userRows, credentialRows, bindingRows)
	}
	requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationEmergencyUserCreate, proof)

	freshProof, freshRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationEmergencyUserCreate)
	created, err := newService(realAuditor).ProvisionEmergencyUser(ctx, actor, command, freshProof, freshRequest)
	if err != nil {
		t.Fatalf("ProvisionEmergencyUser(recovery): %v", err)
	}
	var kind, status, activationDigest, role, scopeType, effect string
	var version int64
	var mfaEnrolled bool
	var activationExpiresAt time.Time
	if err := pool.QueryRow(ctx, `
SELECT u.user_kind,u.status,u.mfa_enrolled,u.version,c.activation_digest,c.activation_expires_at,
       b.role_name,b.scope_type,b.effect
FROM user_principals u
JOIN local_credentials c ON c.user_id=u.id
JOIN role_bindings b ON b.subject_type='user' AND b.subject_id=u.id
WHERE u.id=$1`, created.User.ID).Scan(&kind, &status, &mfaEnrolled, &version, &activationDigest, &activationExpiresAt, &role, &scopeType, &effect); err != nil {
		t.Fatal(err)
	}
	if kind != "emergency" || status != "pending" || mfaEnrolled || version != 1 || activationDigest == created.ActivationToken || activationDigest != integrationSHA256Hex(created.ActivationToken) || !activationExpiresAt.Equal(now.Add(24*time.Hour)) || role != "admin" || scopeType != "platform" || effect != "allow" {
		t.Fatalf("created emergency kind=%s status=%s mfa=%t version=%d digest=%q expires=%s binding=%s/%s/%s", kind, status, mfaEnrolled, version, activationDigest, activationExpiresAt, role, scopeType, effect)
	}

	expiredAt := now.Add(-time.Minute)
	if _, err := pool.Exec(ctx, `UPDATE local_credentials SET activation_expires_at=$2 WHERE user_id=$1`, created.User.ID, expiredAt); err != nil {
		t.Fatal(err)
	}
	oldDigest := activationDigest
	reissueProof, reissueRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationEmergencyActivationReissue)
	if _, err := newService(failingIAMAuditAppender{}).ReissueEmergencyActivation(ctx, actor, created.User.ID, iam.ReissueEmergencyActivationCommand{UserVersion: 1, Reason: "Reissue expired emergency activation."}, reissueProof, reissueRequest); !errors.Is(err, errIntegrationAuditFailure) {
		t.Fatalf("ReissueEmergencyActivation(audit failure) error=%v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT u.version,c.activation_digest,c.activation_expires_at FROM user_principals u JOIN local_credentials c ON c.user_id=u.id WHERE u.id=$1`, created.User.ID).Scan(&version, &activationDigest, &activationExpiresAt); err != nil {
		t.Fatal(err)
	}
	if version != 1 || activationDigest != oldDigest || !activationExpiresAt.Equal(expiredAt) {
		t.Fatalf("reissue audit rollback version=%d digest=%q expires=%s", version, activationDigest, activationExpiresAt)
	}
	requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationEmergencyActivationReissue, reissueProof)

	freshReissueProof, freshReissueRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationEmergencyActivationReissue)
	reissued, err := newService(realAuditor).ReissueEmergencyActivation(ctx, actor, created.User.ID, iam.ReissueEmergencyActivationCommand{UserVersion: 1, Reason: "Reissue expired emergency activation."}, freshReissueProof, freshReissueRequest)
	if err != nil {
		t.Fatalf("ReissueEmergencyActivation(recovery): %v", err)
	}
	if reissued.User.Version != 2 || reissued.ActivationToken == "" || reissued.ActivationToken == created.ActivationToken || !reissued.ActivationExpires.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("reissued=%+v", reissued)
	}
}

func TestIAMMFAProductionActivationLifecycleAuditRollbackAndOrphanConcurrency(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_activation_lifecycle_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	clock := &integrationAdvancingClock{now: time.Date(2026, 8, 21, 21, 0, 0, 0, time.UTC)}
	store := &integrationMFASecretStore{clock: clock.Now}
	realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
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
	verifier := &integrationMFAVerifier{}
	newEnrollmentService := func(auditor iam.AuditAppender) *iam.MFAService {
		t.Helper()
		service, serviceErr := iam.NewMFAService(iam.MFAServiceConfig{
			Repository: repository, Auditor: auditor, Secrets: store, Policy: iam.DefaultLocalAuthPolicy(),
			EnrollmentTTL: 10 * time.Minute, Issuer: "Xminds Release Platform", Clock: clock.Now,
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		return service
	}
	newLocalAuth := func(auditor iam.AuditAppender) *iam.LocalAuthService {
		t.Helper()
		service, serviceErr := iam.NewLocalAuthService(iam.LocalAuthConfig{
			Repository: repository, Auditor: auditor, Passwords: passwords, DummyPassword: dummyPassword,
			MFA: verifier, Policy: iam.DefaultLocalAuthPolicy(), Clock: clock.Now,
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		return service
	}
	seedPending := func(username, token string) uuid.UUID {
		t.Helper()
		userID := uuid.New()
		if _, seedErr := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,$2,$2,'local','pending',1,$3,$3)`, userID, username, clock.Now().Add(-time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		if _, seedErr := pool.Exec(ctx, `INSERT INTO local_credentials (user_id,failed_attempts,activation_digest,activation_expires_at) VALUES ($1,0,$2,$3)`, userID, integrationSHA256Hex(token), clock.Now().Add(time.Hour)); seedErr != nil {
			t.Fatal(seedErr)
		}
		return userID
	}
	request := func() iam.RequestContext {
		return iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.80"}
	}

	t.Run("begin audit failure removes unreferenced file and rolls back database state", func(t *testing.T) {
		token := "activation-begin-audit-failure-token-with-entropy"
		userID := seedPending("mfa.begin.audit", token)
		if _, err := newEnrollmentService(failingIAMAuditAppender{}).BeginActivationEnrollment(ctx, token, request()); !errors.Is(err, errIntegrationAuditFailure) {
			t.Fatalf("BeginActivationEnrollment error=%v", err)
		}
		var enrollmentRows, gcRows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_enrollments WHERE user_id=$1`, userID).Scan(&enrollmentRows); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_secret_gc`).Scan(&gcRows); err != nil {
			t.Fatal(err)
		}
		if enrollmentRows != 0 || gcRows != 0 || store.valueCount() != 0 {
			t.Fatalf("begin rollback enrollments=%d gc=%d files=%d", enrollmentRows, gcRows, store.valueCount())
		}
	})

	t.Run("confirm audit failure preserves pending state and successful retry confirms once", func(t *testing.T) {
		token := "activation-confirm-audit-failure-token-with-entropy"
		userID := seedPending("mfa.confirm.audit", token)
		started, err := newEnrollmentService(realAuditor).BeginActivationEnrollment(ctx, token, request())
		if err != nil {
			t.Fatal(err)
		}
		if !store.contains("secret://iam-mfa/mfa-" + started.ID.String() + ".totp") {
			t.Fatal("begin did not persist the referenced secret")
		}
		activation := iam.ActivateLocalAccountCommand{
			ActivationToken: token, NewPassword: "Lifecycle-Activation-Password-2026!",
			MFAEnrollmentID: started.ID, MFAProof: "123456",
		}
		if result, err := newLocalAuth(failingIAMAuditAppender{}).ActivateWithResult(ctx, activation, request()); !errors.Is(err, errIntegrationAuditFailure) || len(result.RecoveryCodes) != 0 {
			t.Fatalf("activation audit failure result=%+v error=%v", result, err)
		}
		var status, enrollmentStatus, credentialReference string
		var recoveryRows, gcRows int
		if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, userID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_mfa_enrollments WHERE id=$1`, started.ID).Scan(&enrollmentStatus); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT mfa_secret_reference FROM local_credentials WHERE user_id=$1`, userID).Scan(&credentialReference); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_recovery_codes WHERE user_id=$1`, userID).Scan(&recoveryRows); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_secret_gc WHERE secret_reference=$1`, "secret://iam-mfa/mfa-"+started.ID.String()+".totp").Scan(&gcRows); err != nil {
			t.Fatal(err)
		}
		if status != "pending" || enrollmentStatus != "pending" || credentialReference != "" || recoveryRows != 0 || gcRows != 0 {
			t.Fatalf("confirm rollback user=%s enrollment=%s credential=%q recovery=%d gc=%d", status, enrollmentStatus, credentialReference, recoveryRows, gcRows)
		}
		result, err := newLocalAuth(realAuditor).ActivateWithResult(ctx, activation, request())
		if err != nil {
			t.Fatal(err)
		}
		if len(result.RecoveryCodes) != 10 {
			t.Fatalf("recovery code count=%d, want 10", len(result.RecoveryCodes))
		}
		var mfaEnrolled bool
		if err := pool.QueryRow(ctx, `SELECT status,mfa_enrolled FROM user_principals WHERE id=$1`, userID).Scan(&status, &mfaEnrolled); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_mfa_enrollments WHERE id=$1`, started.ID).Scan(&enrollmentStatus); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT mfa_secret_reference FROM local_credentials WHERE user_id=$1`, userID).Scan(&credentialReference); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_recovery_codes WHERE user_id=$1`, userID).Scan(&recoveryRows); err != nil {
			t.Fatal(err)
		}
		if status != "active" || !mfaEnrolled || enrollmentStatus != "confirmed" || credentialReference != "secret://iam-mfa/mfa-"+started.ID.String()+".totp" || recoveryRows != 10 {
			t.Fatalf("confirmed user=%s mfa=%t enrollment=%s credential=%q recovery=%d", status, mfaEnrolled, enrollmentStatus, credentialReference, recoveryRows)
		}
	})

	t.Run("superseding begin expires old enrollment and audit failure rolls it back", func(t *testing.T) {
		token := "activation-expire-audit-failure-token-with-entropy"
		userID := seedPending("mfa.expire.audit", token)
		first, err := newEnrollmentService(realAuditor).BeginActivationEnrollment(ctx, token, request())
		if err != nil {
			t.Fatal(err)
		}
		fileCount := store.valueCount()
		if _, err := newEnrollmentService(failingIAMAuditAppender{}).BeginActivationEnrollment(ctx, token, request()); !errors.Is(err, errIntegrationAuditFailure) {
			t.Fatalf("superseding audit failure error=%v", err)
		}
		var firstStatus string
		var gcRows int
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_mfa_enrollments WHERE id=$1`, first.ID).Scan(&firstStatus); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_secret_gc WHERE secret_reference=$1`, "secret://iam-mfa/mfa-"+first.ID.String()+".totp").Scan(&gcRows); err != nil {
			t.Fatal(err)
		}
		if firstStatus != "pending" || gcRows != 0 || store.valueCount() != fileCount {
			t.Fatalf("supersede rollback old=%s gc=%d files=%d want=%d", firstStatus, gcRows, store.valueCount(), fileCount)
		}
		second, err := newEnrollmentService(realAuditor).BeginActivationEnrollment(ctx, token, request())
		if err != nil {
			t.Fatal(err)
		}
		var secondStatus string
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_mfa_enrollments WHERE id=$1`, first.ID).Scan(&firstStatus); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_mfa_enrollments WHERE id=$1`, second.ID).Scan(&secondStatus); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_secret_gc WHERE secret_reference=$1`, "secret://iam-mfa/mfa-"+first.ID.String()+".totp").Scan(&gcRows); err != nil {
			t.Fatal(err)
		}
		if firstStatus != "expired" || secondStatus != "pending" || gcRows != 1 || !store.contains("secret://iam-mfa/mfa-"+first.ID.String()+".totp") || !store.contains("secret://iam-mfa/mfa-"+second.ID.String()+".totp") {
			t.Fatalf("supersede old=%s new=%s gc=%d old_file=%t new_file=%t user=%s", firstStatus, secondStatus, gcRows, store.contains("secret://iam-mfa/mfa-"+first.ID.String()+".totp"), store.contains("secret://iam-mfa/mfa-"+second.ID.String()+".totp"), userID)
		}
	})

	t.Run("orphan reconciliation concurrent with begin never deletes the fresh reference", func(t *testing.T) {
		token := "activation-orphan-concurrency-token-with-entropy"
		userID := seedPending("mfa.orphan.concurrent", token)
		orphanID, _ := uuid.NewV7()
		orphanReference := "secret://iam-mfa/mfa-" + orphanID.String() + ".totp"
		store.put(orphanReference, "ORPHAN-SEED", clock.Now().Add(-2*time.Hour))
		created := make(chan string, 1)
		createRelease := make(chan struct{})
		store.mutex.Lock()
		store.createHook = func(reference string) {
			created <- reference
			select {
			case <-createRelease:
			case <-ctx.Done():
			}
		}
		store.mutex.Unlock()
		beginResult := make(chan iam.MFAEnrollmentStart, 1)
		beginError := make(chan error, 1)
		go func() {
			result, beginErr := newEnrollmentService(realAuditor).BeginActivationEnrollment(ctx, token, request())
			beginResult <- result
			beginError <- beginErr
		}()
		var freshReference string
		select {
		case freshReference = <-created:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		worker, err := iam.NewMFASecretGCWorker(iam.MFASecretGCWorkerConfig{Repository: repository, Secrets: store, Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := worker.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if !store.contains(freshReference) || store.contains(orphanReference) {
			t.Fatalf("during begin fresh_present=%t old_orphan_present=%t", store.contains(freshReference), store.contains(orphanReference))
		}
		close(createRelease)
		if err := <-beginError; err != nil {
			t.Fatal(err)
		}
		started := <-beginResult
		if freshReference != "secret://iam-mfa/mfa-"+started.ID.String()+".totp" || !store.contains(freshReference) {
			t.Fatalf("begin reference=%q started=%s present=%t user=%s", freshReference, started.ID, store.contains(freshReference), userID)
		}
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM iam_mfa_enrollments WHERE id=$1 AND user_id=$2`, started.ID, userID).Scan(&status); err != nil || status != "pending" {
			t.Fatalf("fresh enrollment status=%q error=%v", status, err)
		}
		store.mutex.Lock()
		store.createHook = nil
		store.mutex.Unlock()
	})
}

// Mutation caught: separating the tombstone check from reference insertion,
// or consuming recovery codes with a read-then-write sequence, permits secret
// resurrection and one-time factor replay under concurrency.
func TestIAMMFARepositoryEnrollmentRecoveryAndGCCAS(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_repository_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	userID := uuid.New()
	blockedUserID := uuid.New()
	for _, fixture := range []struct {
		id       uuid.UUID
		username string
	}{
		{id: userID, username: "mfa.repository.primary"},
		{id: blockedUserID, username: "mfa.repository.blocked"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,$2,'MFA Repository','local','pending',1,$3,$3)`, fixture.id, fixture.username, now); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO local_credentials (user_id,failed_attempts,activation_digest,activation_expires_at) VALUES ($1,0,$2,$3)`, fixture.id, integrationSHA256Hex("activation-"+fixture.username), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	enrollmentID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	enrollment := iam.MFAEnrollment{
		ID: enrollmentID, UserID: userID, Purpose: iam.MFAEnrollmentPurposeActivation, Status: iam.MFAEnrollmentStatusPending,
		SecretReference: "secret://iam-mfa/mfa-" + enrollmentID.String() + ".totp", ExpectedUserVersion: 1,
		ExpiresAt: now.Add(10 * time.Minute), Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.InsertMFAEnrollment(ctx, tx, enrollment)
	}); err != nil {
		t.Fatalf("InsertMFAEnrollment: %v", err)
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		loaded, loadErr := repository.GetMFAEnrollmentForUpdate(ctx, tx, enrollmentID)
		if loadErr != nil {
			return loadErr
		}
		if loaded.SecretReference != enrollment.SecretReference || loaded.Status != iam.MFAEnrollmentStatusPending || loaded.Version != 1 {
			t.Fatalf("loaded enrollment=%+v", loaded)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	generationID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	digest := integrationSHA256Hex("MFA-RECOVERY-CODE")
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.ReplaceMFARecoveryCodes(ctx, tx, userID, generationID, []string{digest}, now)
	}); err != nil {
		t.Fatal(err)
	}
	var recoverySuccess atomic.Int64
	var recoveryWait sync.WaitGroup
	recoveryWait.Add(2)
	for range 2 {
		go func() {
			defer recoveryWait.Done()
			err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
				consumed, consumeErr := repository.ConsumeMFARecoveryCode(ctx, tx, userID, digest, now.Add(time.Minute))
				if consumed {
					recoverySuccess.Add(1)
				}
				return consumeErr
			})
			if err != nil {
				t.Errorf("ConsumeMFARecoveryCode: %v", err)
			}
		}()
	}
	recoveryWait.Wait()
	if recoverySuccess.Load() != 1 {
		t.Fatalf("recovery consumption successes=%d, want 1", recoverySuccess.Load())
	}

	blockedEnrollmentID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	blockedReference := "secret://iam-mfa/mfa-" + blockedEnrollmentID.String() + ".totp"
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.EnqueueMFASecretGC(ctx, tx, blockedReference, now, now)
	}); err != nil {
		t.Fatal(err)
	}
	firstLeaseToken, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	secondLeaseToken, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	firstLeased := false
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var leaseErr error
		firstLeased, leaseErr = repository.LeaseDueMFASecretGC(ctx, tx, blockedReference, now, firstLeaseToken, now.Add(30*time.Second))
		return leaseErr
	}); err != nil || !firstLeased {
		t.Fatalf("first GC lease leased=%t error=%v", firstLeased, err)
	}
	blockedEnrollment := iam.MFAEnrollment{
		ID: blockedEnrollmentID, UserID: blockedUserID, Purpose: iam.MFAEnrollmentPurposeActivation, Status: iam.MFAEnrollmentStatusPending,
		SecretReference: blockedReference, ExpectedUserVersion: 1, ExpiresAt: now.Add(10 * time.Minute), Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.InsertMFAEnrollment(ctx, tx, blockedEnrollment)
	}); !errors.Is(err, iam.ErrIAMConflict) {
		t.Fatalf("writer reused leased tombstone error=%v", err)
	}
	secondLeased := false
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var leaseErr error
		secondLeased, leaseErr = repository.LeaseDueMFASecretGC(ctx, tx, blockedReference, now.Add(time.Minute), secondLeaseToken, now.Add(90*time.Second))
		return leaseErr
	}); err != nil || !secondLeased {
		t.Fatalf("expired lease takeover leased=%t error=%v", secondLeased, err)
	}
	for name, mutation := range map[string]func(context.Context, pgx.Tx) error{
		"complete": func(callCtx context.Context, tx pgx.Tx) error {
			return repository.CompleteMFASecretGC(callCtx, tx, blockedReference, firstLeaseToken)
		},
		"fail": func(callCtx context.Context, tx pgx.Tx) error {
			return repository.FailMFASecretGC(callCtx, tx, blockedReference, firstLeaseToken, now.Add(2*time.Minute), "DELETE_FAILED", now.Add(time.Minute))
		},
	} {
		if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error { return mutation(ctx, tx) }); !errors.Is(err, iam.ErrIAMConflict) {
			t.Errorf("old lease token %s error=%v", name, err)
		}
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.CompleteMFASecretGC(ctx, tx, blockedReference, secondLeaseToken)
	}); err != nil {
		t.Fatalf("complete current lease: %v", err)
	}
}

func TestIAMMFASecretGCWorkerSerializesDeleteCancelsLiveAndPersistsFailure(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_gc_worker_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	now := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)
	clock := now
	store := &integrationMFASecretStore{}
	newWorker := func() *iam.MFASecretGCWorker {
		worker, err := iam.NewMFASecretGCWorker(iam.MFASecretGCWorkerConfig{
			Repository: repository, Secrets: store, Clock: func() time.Time { return clock },
		})
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}

	deleteID, _ := uuid.NewV7()
	deleteReference := "secret://iam-mfa/mfa-" + deleteID.String() + ".totp"
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.EnqueueMFASecretGC(ctx, tx, deleteReference, now, now)
	}); err != nil {
		t.Fatal(err)
	}
	workers := []*iam.MFASecretGCWorker{newWorker(), newWorker()}
	var wait sync.WaitGroup
	wait.Add(2)
	for _, worker := range workers {
		go func(worker *iam.MFASecretGCWorker) {
			defer wait.Done()
			if _, err := worker.RunOnce(ctx); err != nil {
				t.Errorf("RunOnce: %v", err)
			}
		}(worker)
	}
	wait.Wait()
	if store.deleteCount.Load() != 1 {
		t.Fatalf("dual-worker delete count=%d, want 1", store.deleteCount.Load())
	}
	assertMFASecretGCCount(t, ctx, pool, deleteReference, 0)

	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,$2,'MFA GC Live','local','pending',1,$3,$3)`, userID, "mfa.gc.live."+userID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO local_credentials (user_id,failed_attempts,activation_digest,activation_expires_at) VALUES ($1,0,$2,$3)`, userID, integrationSHA256Hex("mfa-gc-live"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	liveID, _ := uuid.NewV7()
	liveReference := "secret://iam-mfa/mfa-" + liveID.String() + ".totp"
	liveEnrollment := iam.MFAEnrollment{
		ID: liveID, UserID: userID, Purpose: iam.MFAEnrollmentPurposeActivation, Status: iam.MFAEnrollmentStatusPending,
		SecretReference: liveReference, ExpectedUserVersion: 1, ExpiresAt: now.Add(10 * time.Minute),
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := repository.InsertMFAEnrollment(ctx, tx, liveEnrollment); err != nil {
			return err
		}
		return repository.EnqueueMFASecretGC(ctx, tx, liveReference, now, now)
	}); err != nil {
		t.Fatal(err)
	}
	beforeLive := store.deleteCount.Load()
	if _, err := newWorker().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if store.deleteCount.Load() != beforeLive {
		t.Fatal("live reference was deleted")
	}
	assertMFASecretGCCount(t, ctx, pool, liveReference, 0)

	failureID, _ := uuid.NewV7()
	failureReference := "secret://iam-mfa/mfa-" + failureID.String() + ".totp"
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.EnqueueMFASecretGC(ctx, tx, failureReference, now, now)
	}); err != nil {
		t.Fatal(err)
	}
	store.failDelete.Store(true)
	if _, err := newWorker().RunOnce(ctx); err == nil {
		t.Fatal("RunOnce error=nil, want persisted delete failure")
	}
	var state string
	var attempts int
	var errorCode string
	if err := pool.QueryRow(ctx, `SELECT state,attempts,last_error_code FROM iam_mfa_secret_gc WHERE secret_reference=$1`, failureReference).Scan(&state, &attempts, &errorCode); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || attempts != 1 || errorCode != "SECRET_DELETE_FAILED" {
		t.Fatalf("persisted failure state=%s attempts=%d code=%s", state, attempts, errorCode)
	}
	store.failDelete.Store(false)
	clock = now.Add(2 * time.Minute)
	if _, err := newWorker().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertMFASecretGCCount(t, ctx, pool, failureReference, 0)
}

func TestIAMMFASecretGCWorkerStartsLeaseFromLeaseTransactionTime(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_gc_lease_clock_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	clock := &integrationAdvancingClock{now: time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)}
	referenceID, _ := uuid.NewV7()
	reference := "secret://iam-mfa/mfa-" + referenceID.String() + ".totp"
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.EnqueueMFASecretGC(ctx, tx, reference, clock.Now(), clock.Now())
	}); err != nil {
		t.Fatal(err)
	}
	deleteStarted := make(chan struct{})
	deleteRelease := make(chan struct{})
	store := &integrationMFASecretStore{
		listHook:      func() { clock.Advance(31 * time.Second) },
		deleteStarted: deleteStarted,
		deleteRelease: deleteRelease,
	}
	worker, err := iam.NewMFASecretGCWorker(iam.MFASecretGCWorkerConfig{
		Repository: repository,
		Secrets:    store,
		Clock:      clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan error, 1)
	go func() {
		_, runErr := worker.RunOnce(ctx)
		workerDone <- runErr
	}()
	select {
	case <-deleteStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var leasedUntil time.Time
	if err := pool.QueryRow(ctx, `SELECT leased_until FROM iam_mfa_secret_gc WHERE secret_reference=$1 AND state='leased'`, reference).Scan(&leasedUntil); err != nil {
		close(deleteRelease)
		t.Fatal(err)
	}
	if !leasedUntil.After(clock.Now()) {
		close(deleteRelease)
		t.Fatalf("lease committed already expired: leased_until=%s current=%s", leasedUntil, clock.Now())
	}
	close(deleteRelease)
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
}

func TestIAMMFASecretGCWorkerSchedulesRetryFromDeleteFailureTime(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_gc_failure_clock_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	clock := &integrationAdvancingClock{now: time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)}
	referenceID, _ := uuid.NewV7()
	reference := "secret://iam-mfa/mfa-" + referenceID.String() + ".totp"
	if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return repository.EnqueueMFASecretGC(ctx, tx, reference, clock.Now(), clock.Now())
	}); err != nil {
		t.Fatal(err)
	}
	deleteFailure := errors.New("injected delete completion failure")
	store := &integrationMFASecretStore{
		clock: clock.Now,
		deleteHook: func(context.Context, int64, string) error {
			clock.Advance(45 * time.Second)
			return deleteFailure
		},
	}
	worker, err := iam.NewMFASecretGCWorker(iam.MFASecretGCWorkerConfig{Repository: repository, Secrets: store, Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(ctx); !errors.Is(err, deleteFailure) {
		t.Fatalf("RunOnce error=%v", err)
	}
	var state string
	var updatedAt, retryAt time.Time
	if err := pool.QueryRow(ctx, `SELECT state,updated_at,not_before FROM iam_mfa_secret_gc WHERE secret_reference=$1`, reference).Scan(&state, &updatedAt, &retryAt); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || !updatedAt.Equal(clock.Now()) || !retryAt.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("failure state=%s updated_at=%s retry_at=%s current=%s", state, updatedAt, retryAt, clock.Now())
	}
}

func TestIAMMFASecretGCWorkerFencesCrashedLeasesAndCompletesIdempotentTakeover(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "iam_mfa_gc_crash_matrix_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	clock := &integrationAdvancingClock{now: time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)}
	newWorker := func(workerRepository integrationMFASecretGCRepository, store iam.MFASecretStore) *iam.MFASecretGCWorker {
		t.Helper()
		worker, err := iam.NewMFASecretGCWorker(iam.MFASecretGCWorkerConfig{Repository: workerRepository, Secrets: store, Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}

	t.Run("pause after lease rejects writer and expired takeover fences old token", func(t *testing.T) {
		referenceID, _ := uuid.NewV7()
		reference := "secret://iam-mfa/mfa-" + referenceID.String() + ".totp"
		userID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,$2,'GC Writer','local','pending',1,$3,$3)`, userID, "gc.writer."+userID.String(), clock.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO local_credentials (user_id,failed_attempts,activation_digest,activation_expires_at) VALUES ($1,0,$2,$3)`, userID, integrationSHA256Hex("gc-writer-token"), clock.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			return repository.EnqueueMFASecretGC(ctx, tx, reference, clock.Now(), clock.Now())
		}); err != nil {
			t.Fatal(err)
		}
		firstStarted, firstRelease := make(chan struct{}), make(chan struct{})
		secondStarted, secondRelease := make(chan struct{}), make(chan struct{})
		store := &integrationMFASecretStore{clock: clock.Now}
		store.put(reference, "FIRST-SEED", clock.Now().Add(-2*time.Hour))
		store.deleteHook = func(callCtx context.Context, call int64, _ string) error {
			var started, release chan struct{}
			switch call {
			case 1:
				started, release = firstStarted, firstRelease
			case 2:
				started, release = secondStarted, secondRelease
			default:
				return errors.New("unexpected delete call")
			}
			close(started)
			select {
			case <-release:
				return nil
			case <-callCtx.Done():
				return callCtx.Err()
			}
		}
		firstDone := make(chan error, 1)
		go func() {
			_, runErr := newWorker(repository, store).RunOnce(ctx)
			firstDone <- runErr
		}()
		select {
		case <-firstStarted:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		var firstToken uuid.UUID
		var firstLeaseUntil time.Time
		if err := pool.QueryRow(ctx, `SELECT lease_token,leased_until FROM iam_mfa_secret_gc WHERE secret_reference=$1 AND state='leased'`, reference).Scan(&firstToken, &firstLeaseUntil); err != nil {
			t.Fatal(err)
		}
		writerEnrollment := iam.MFAEnrollment{
			ID: referenceID, UserID: userID, Purpose: iam.MFAEnrollmentPurposeActivation, Status: iam.MFAEnrollmentStatusPending,
			SecretReference: reference, ExpectedUserVersion: 1, ExpiresAt: clock.Now().Add(10 * time.Minute),
			Version: 1, CreatedAt: clock.Now(), UpdatedAt: clock.Now(),
		}
		if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			return repository.InsertMFAEnrollment(ctx, tx, writerEnrollment)
		}); !errors.Is(err, iam.ErrIAMConflict) {
			t.Fatalf("writer reused leased tombstone error=%v", err)
		}
		clock.Set(firstLeaseUntil.Add(time.Microsecond))
		secondDone := make(chan error, 1)
		go func() {
			_, runErr := newWorker(repository, store).RunOnce(ctx)
			secondDone <- runErr
		}()
		select {
		case <-secondStarted:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		var secondToken uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT lease_token FROM iam_mfa_secret_gc WHERE secret_reference=$1 AND state='leased'`, reference).Scan(&secondToken); err != nil {
			t.Fatal(err)
		}
		if secondToken == firstToken {
			t.Fatal("expired takeover reused the old lease token")
		}
		for name, mutation := range map[string]func(context.Context, pgx.Tx) error{
			"complete": func(callCtx context.Context, tx pgx.Tx) error {
				return repository.CompleteMFASecretGC(callCtx, tx, reference, firstToken)
			},
			"fail": func(callCtx context.Context, tx pgx.Tx) error {
				return repository.FailMFASecretGC(callCtx, tx, reference, firstToken, clock.Now().Add(time.Minute), "OLD_WORKER_FAILED", clock.Now())
			},
		} {
			if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error { return mutation(ctx, tx) }); !errors.Is(err, iam.ErrIAMConflict) {
				t.Errorf("old token %s error=%v", name, err)
			}
		}
		close(secondRelease)
		if err := <-secondDone; err != nil {
			t.Fatalf("takeover worker: %v", err)
		}
		close(firstRelease)
		if err := <-firstDone; !errors.Is(err, iam.ErrIAMConflict) {
			t.Fatalf("stale worker error=%v, want fenced conflict", err)
		}
		assertMFASecretGCCount(t, ctx, pool, reference, 0)
		if store.contains(reference) {
			t.Fatal("takeover left deleted secret present")
		}
	})

	t.Run("unlink before completion crash is recovered after lease expiry", func(t *testing.T) {
		referenceID, _ := uuid.NewV7()
		reference := "secret://iam-mfa/mfa-" + referenceID.String() + ".totp"
		if err := repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
			return repository.EnqueueMFASecretGC(ctx, tx, reference, clock.Now(), clock.Now())
		}); err != nil {
			t.Fatal(err)
		}
		store := &integrationMFASecretStore{clock: clock.Now}
		store.put(reference, "CRASH-SEED", clock.Now().Add(-2*time.Hour))
		crashingRepository := &integrationFailCompleteRepository{PostgresRepository: repository}
		crashingRepository.failOnce.Store(true)
		if _, err := newWorker(crashingRepository, store).RunOnce(ctx); !errors.Is(err, errIntegrationGCCompleteCrash) {
			t.Fatalf("crash worker error=%v", err)
		}
		var state string
		var firstToken uuid.UUID
		var leasedUntil time.Time
		if err := pool.QueryRow(ctx, `SELECT state,lease_token,leased_until FROM iam_mfa_secret_gc WHERE secret_reference=$1`, reference).Scan(&state, &firstToken, &leasedUntil); err != nil {
			t.Fatal(err)
		}
		if state != "leased" || store.contains(reference) {
			t.Fatalf("post-unlink crash state=%s secret_present=%t", state, store.contains(reference))
		}
		clock.Set(leasedUntil.Add(time.Microsecond))
		if _, err := newWorker(repository, store).RunOnce(ctx); err != nil {
			t.Fatalf("idempotent takeover: %v", err)
		}
		assertMFASecretGCCount(t, ctx, pool, reference, 0)
		if store.deleteCount.Load() != 2 {
			t.Fatalf("delete calls=%d, want unlink plus idempotent ENOENT", store.deleteCount.Load())
		}
	})
}

type integrationMFASecretStore struct {
	deleteCount   atomic.Int64
	failDelete    atomic.Bool
	mutex         sync.Mutex
	values        map[string][]byte
	createdAt     map[string]time.Time
	clock         func() time.Time
	listHook      func()
	createHook    func(string)
	deleteHook    func(context.Context, int64, string) error
	deleteStarted chan struct{}
	deleteRelease chan struct{}
}

func (store *integrationMFASecretStore) Resolve(_ context.Context, reference string) ([]byte, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	value, exists := store.values[reference]
	if !exists {
		return nil, iam.ErrSecretReferenceInvalid
	}
	return append([]byte(nil), value...), nil
}

func (store *integrationMFASecretStore) Create(_ context.Context, enrollmentID uuid.UUID, seed string) (string, error) {
	reference := "secret://iam-mfa/mfa-" + enrollmentID.String() + ".totp"
	store.mutex.Lock()
	if store.values == nil {
		store.values = make(map[string][]byte)
	}
	if store.createdAt == nil {
		store.createdAt = make(map[string]time.Time)
	}
	store.values[reference] = []byte(seed)
	createdAt := time.Now().UTC()
	if store.clock != nil {
		createdAt = store.clock().UTC()
	}
	store.createdAt[reference] = createdAt
	createHook := store.createHook
	store.mutex.Unlock()
	if createHook != nil {
		createHook(reference)
	}
	return reference, nil
}

func (store *integrationMFASecretStore) Delete(ctx context.Context, reference string) error {
	deleteCall := store.deleteCount.Add(1)
	if store.deleteStarted != nil {
		close(store.deleteStarted)
	}
	if store.deleteRelease != nil {
		select {
		case <-store.deleteRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if store.failDelete.Load() {
		return errors.New("injected unlink failure")
	}
	store.mutex.Lock()
	deleteHook := store.deleteHook
	store.mutex.Unlock()
	if deleteHook != nil {
		if err := deleteHook(ctx, deleteCall, reference); err != nil {
			return err
		}
	}
	store.mutex.Lock()
	delete(store.values, reference)
	delete(store.createdAt, reference)
	store.mutex.Unlock()
	return nil
}

func (store *integrationMFASecretStore) ListOrphanCandidates(_ context.Context, olderThan time.Time, limit int) ([]string, error) {
	if store.listHook != nil {
		store.listHook()
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	candidates := make([]string, 0, limit)
	for reference, createdAt := range store.createdAt {
		if createdAt.Before(olderThan) {
			candidates = append(candidates, reference)
		}
	}
	sort.Strings(candidates)
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates, nil
}

func (store *integrationMFASecretStore) put(reference, seed string, createdAt time.Time) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.values == nil {
		store.values = make(map[string][]byte)
	}
	if store.createdAt == nil {
		store.createdAt = make(map[string]time.Time)
	}
	store.values[reference] = []byte(seed)
	store.createdAt[reference] = createdAt.UTC()
}

func (store *integrationMFASecretStore) contains(reference string) bool {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	_, exists := store.values[reference]
	return exists
}

func (store *integrationMFASecretStore) valueCount() int {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return len(store.values)
}

type integrationAdvancingClock struct {
	mutex sync.Mutex
	now   time.Time
}

func (clock *integrationAdvancingClock) Now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.now
}

func (clock *integrationAdvancingClock) Advance(duration time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.now = clock.now.Add(duration)
}

func (clock *integrationAdvancingClock) Set(at time.Time) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.now = at.UTC()
}

type integrationFailCompleteRepository struct {
	*iam.PostgresRepository
	failOnce atomic.Bool
}

type integrationMFASecretGCRepository interface {
	WithinTransaction(context.Context, func(pgx.Tx) error) error
	ListDueMFASecretGC(context.Context, time.Time, int) ([]iam.MFASecretGCItem, error)
	LeaseDueMFASecretGC(context.Context, pgx.Tx, string, time.Time, uuid.UUID, time.Time) (bool, error)
	CompleteMFASecretGC(context.Context, pgx.Tx, string, uuid.UUID) error
	FailMFASecretGC(context.Context, pgx.Tx, string, uuid.UUID, time.Time, string, time.Time) error
	LockMFASecretReference(context.Context, pgx.Tx, string) error
	MFASecretReferenceIsLive(context.Context, pgx.Tx, string, time.Time) (bool, error)
	MFASecretReferenceHasTombstone(context.Context, pgx.Tx, string) (bool, error)
	EnqueueMFASecretGC(context.Context, pgx.Tx, string, time.Time, time.Time) error
}

func (repository *integrationFailCompleteRepository) CompleteMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, leaseToken uuid.UUID) error {
	if repository.failOnce.CompareAndSwap(true, false) {
		return errIntegrationGCCompleteCrash
	}
	return repository.PostgresRepository.CompleteMFASecretGC(ctx, tx, reference, leaseToken)
}

var errIntegrationGCCompleteCrash = errors.New("integration GC completion crash")

func assertMFASecretGCCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, reference string, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_mfa_secret_gc WHERE secret_reference=$1`, reference).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("GC row count for %s=%d, want %d", reference, count, want)
	}
}

func assertIntegrationTablePresence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Errorf("table %s presence=%t, want %t", table, exists, want)
	}
}

func assertIntegrationCheckViolation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, statement string, arguments ...any) {
	t.Helper()
	_, err := pool.Exec(ctx, statement, arguments...)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23514" {
		t.Errorf("%s error=%v, want SQLSTATE 23514", name, err)
	}
}
