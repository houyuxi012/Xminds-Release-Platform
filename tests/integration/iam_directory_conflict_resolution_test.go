package integration_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/migrations"
)

func TestDirectoryConflictResolutionMigrationV16UpgradeRollbackAndReapply(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "directory_conflict_migration_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})

	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 16)); err != nil {
		t.Fatalf("apply migrations 1..16: %v", err)
	}
	now := time.Date(2026, 8, 21, 15, 0, 0, 0, time.UTC)
	sourceID, jobID, legacyConflictID := seedDirectoryConflictResolutionFixture(t, ctx, pool, now, "completed", "resolved")
	checksums := map[int]string{}
	rows, err := pool.Query(ctx, `SELECT version, checksum FROM schema_migrations WHERE version BETWEEN 1 AND 16 ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			t.Fatal(err)
		}
		checksums[version] = checksum
	}
	rows.Close()

	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 17)); err != nil {
		t.Fatalf("upgrade v16 to v17: %v", err)
	}
	var status string
	var decision, reason, resolvedBy, resolvedAt any
	var version int64
	if err := pool.QueryRow(ctx, `SELECT status, resolution_decision, resolution_reason, resolved_by, resolved_at, version FROM directory_sync_conflicts WHERE id=$1`, legacyConflictID).
		Scan(&status, &decision, &reason, &resolvedBy, &resolvedAt, &version); err != nil {
		t.Fatal(err)
	}
	if status != "open" || decision != nil || reason != nil || resolvedBy != nil || resolvedAt != nil || version != 1 {
		t.Fatalf("legacy conflict was not reopened safely: status=%q decision=%v reason=%v resolved_by=%v resolved_at=%v version=%d", status, decision, reason, resolvedBy, resolvedAt, version)
	}
	var maximumVersion int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&maximumVersion); err != nil || maximumVersion != 17 {
		t.Fatalf("maximum migration version=%d error=%v", maximumVersion, err)
	}
	for migrationVersion, checksum := range checksums {
		var current string
		if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, migrationVersion).Scan(&current); err != nil || current != checksum {
			t.Fatalf("migration %d checksum changed: before=%s after=%s error=%v", migrationVersion, checksum, current, err)
		}
	}

	challengeID, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx, `INSERT INTO iam_reauthentication_challenges (
		id, actor_subject, actor_kind, actor_binding_version, actor_binding_digest, created_token_digest,
		operation, status, created_at, challenge_expires_at, created_request_id, version
	) VALUES ($1, 'migration-admin', 'human', 1, repeat('a',64), repeat('b',64),
		'identity.directory_conflict.resolve', 'pending', $2, $3, $4, 1)`, challengeID, now, now.Add(time.Minute), uuid.New()); err != nil {
		t.Fatalf("v17 rejected conflict-resolution reauthentication operation: %v", err)
	}
	resolvedConflictID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO directory_sync_conflicts (
		id, sync_job_id, identity_source_id, object_type, external_id, conflict_code, details, status,
		resolution_decision, resolution_reason, resolved_by, resolved_at, version, created_at
	) VALUES ($1,$2,$3,'user','second','AMBIGUOUS_EMAIL','{}','resolved','keep_last_safe',
		'confirmed migration reason',$4,$5,2,$5)`, resolvedConflictID, jobID, sourceID, uuid.NewString(), now); err != nil {
		t.Fatalf("insert resolved v17 conflict: %v", err)
	}

	downSQL, err := fs.ReadFile(migrations.FS, "000017_directory_conflict_resolution.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(downSQL)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("apply v17 down: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=17`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM directory_sync_conflicts WHERE id=$1`, resolvedConflictID).Scan(&status); err != nil || status != "open" {
		t.Fatalf("down did not reopen resolved conflict: status=%q error=%v", status, err)
	}
	var resolutionColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='directory_sync_conflicts' AND column_name IN ('resolution_decision','resolution_reason','version')`).Scan(&resolutionColumns); err != nil || resolutionColumns != 0 {
		t.Fatalf("resolution columns after down=%d error=%v", resolutionColumns, err)
	}
	var challengeRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_reauthentication_challenges WHERE operation='identity.directory_conflict.resolve'`).Scan(&challengeRows); err != nil || challengeRows != 0 {
		t.Fatalf("new operation challenge rows after down=%d error=%v", challengeRows, err)
	}
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 17)); err != nil {
		t.Fatalf("reapply v17: %v", err)
	}
}

func TestDirectoryConflictResolutionPostgresConcurrencyAndAuditRollback(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "directory_conflict_runtime_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 16, 30, 0, 0, time.UTC)
	var serverVersion string
	if err := pool.QueryRow(ctx, `SHOW server_version`).Scan(&serverVersion); err != nil || !strings.HasPrefix(serverVersion, "17.10") {
		t.Fatalf("PostgreSQL server_version=%q error=%v, require 17.10", serverVersion, err)
	}
	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	reauthentication, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: auditor, Local: integrationLocalReauthenticator{}, Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{
		Subject: "conflict-admin", Kind: identity.PrincipalKindHuman, IdentitySourceID: uuid.NewString(), GovernedUserID: uuid.NewString(), Governed: true,
		TokenID: "test-token-binding", AuthenticatedAt: now.Add(-time.Minute), AuthenticationAssurance: 2,
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
	proofFor := func() (iam.HighRiskProof, iam.RequestContext) {
		request := iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.81"}
		challenge, err := reauthentication.CreateChallenge(ctx, actor, iam.ReauthenticationOperationDirectoryConflictResolve, request)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := reauthentication.CompleteChallenge(ctx, actor, challenge.ID, iam.CompleteReauthenticationCommand{}, request)
		if err != nil {
			t.Fatal(err)
		}
		return iam.HighRiskProof{ChallengeID: challenge.ID.String(), Evidence: evidence.Evidence, Confirmed: true}, request
	}
	sourceID, _, conflictID := seedDirectoryConflictResolutionFixture(t, ctx, pool, now, "completed", "open")
	proofOne, requestOne := proofFor()
	proofTwo, requestTwo := proofFor()
	ready, release := make(chan struct{}, 2), make(chan struct{})
	barrier := &barrierHighRiskAuthorizer{delegate: reauthentication, ready: ready, release: release}
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, HighRisk: barrier,
		Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsByResolution := make(chan error, 2)
	var group sync.WaitGroup
	for _, input := range []struct {
		proof   iam.HighRiskProof
		request iam.RequestContext
	}{{proofOne, requestOne}, {proofTwo, requestTwo}} {
		group.Add(1)
		go func(input struct {
			proof   iam.HighRiskProof
			request iam.RequestContext
		}) {
			defer group.Done()
			<-start
			_, resolveErr := service.ResolveConflict(ctx, actor, sourceID, conflictID, iam.ResolveDirectorySyncConflictCommand{Version: 1, Decision: iam.DirectoryConflictResolutionKeepLastSafe, Reason: "confirmed concurrent upstream collision"}, input.proof, input.request)
			errorsByResolution <- resolveErr
		}(input)
	}
	close(start)
	<-ready
	<-ready
	close(release)
	group.Wait()
	close(errorsByResolution)
	successes, conflicts := 0, 0
	for resolveErr := range errorsByResolution {
		switch {
		case resolveErr == nil:
			successes++
		case errors.Is(resolveErr, iam.ErrIAMConflict):
			conflicts++
		default:
			t.Fatalf("concurrent resolution error=%v", resolveErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes successes=%d conflicts=%d", successes, conflicts)
	}
	var resolutionAuditCount, resolvedRows, consumedProofs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='identity.directory_conflict.resolve' AND resource_id=$1`, conflictID.String()).Scan(&resolutionAuditCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_conflicts WHERE id=$1 AND status='resolved' AND version=2`, conflictID).Scan(&resolvedRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_reauthentication_challenges WHERE id=ANY($1) AND status='consumed'`, []uuid.UUID{uuid.MustParse(proofOne.ChallengeID), uuid.MustParse(proofTwo.ChallengeID)}).Scan(&consumedProofs); err != nil {
		t.Fatal(err)
	}
	if resolutionAuditCount != 1 || resolvedRows != 1 || consumedProofs != 2 {
		t.Fatalf("concurrent durable state audit=%d resolved=%d consumed_proofs=%d", resolutionAuditCount, resolvedRows, consumedProofs)
	}
	for _, table := range []string{"user_principals", "organization_units", "organization_memberships", "role_bindings"} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("resolution changed %s count=%d error=%v", table, count, err)
		}
	}
	newJobID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO directory_sync_jobs (
		id,identity_source_id,source_version,run_marker,mode,status,phase,requested_by,request_id,created_at,updated_at,completed_at
	) VALUES ($1,$2,3,$3,'apply','completed','finalize','test:admin',$4,$5,$5,$5)`, newJobID, sourceID, uuid.New(), uuid.New(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO directory_sync_conflicts (id,sync_job_id,identity_source_id,object_type,external_id,conflict_code,details,status,created_at)
		VALUES ($1,$2,$3,'user','external-1','AMBIGUOUS_EMAIL','{}','open',$4)`, uuid.New(), newJobID, sourceID, now.Add(time.Minute)); err != nil {
		t.Fatalf("subsequent job could not create a new open conflict: %v", err)
	}
	listService, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, HighRisk: reauthentication,
		Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	openPage, err := listService.ListConflicts(ctx, actor, sourceID, iam.DirectorySyncConflictStatusOpen, iam.Page{Limit: 10})
	if err != nil || len(openPage.Items) != 1 || openPage.Items[0].Status != "open" || openPage.Items[0].Version != 1 {
		t.Fatalf("open conflict page=%#v error=%v", openPage, err)
	}
	resolvedPage, err := listService.ListConflicts(ctx, actor, sourceID, iam.DirectorySyncConflictStatusResolved, iam.Page{Limit: 10})
	if err != nil || len(resolvedPage.Items) != 1 || resolvedPage.Items[0].ID != conflictID || resolvedPage.Items[0].ResolutionDecision != iam.DirectoryConflictResolutionKeepLastSafe || resolvedPage.Items[0].ResolvedAt == nil {
		t.Fatalf("resolved conflict page=%#v error=%v", resolvedPage, err)
	}
	allFirst, err := listService.ListConflicts(ctx, actor, sourceID, iam.DirectorySyncConflictStatusAll, iam.Page{Limit: 1})
	if err != nil || len(allFirst.Items) != 1 || allFirst.NextCursor == "" {
		t.Fatalf("all first page=%#v error=%v", allFirst, err)
	}
	allSecond, err := listService.ListConflicts(ctx, actor, sourceID, iam.DirectorySyncConflictStatusAll, iam.Page{Limit: 1, Cursor: allFirst.NextCursor})
	if err != nil || len(allSecond.Items) != 1 || allSecond.Items[0].ID == allFirst.Items[0].ID {
		t.Fatalf("all second page=%#v error=%v", allSecond, err)
	}
	if _, err := listService.ListConflicts(ctx, actor, sourceID, iam.DirectorySyncConflictStatusOpen, iam.Page{Limit: 1, Cursor: allFirst.NextCursor}); !errors.Is(err, iam.ErrPageInvalid) {
		t.Fatalf("cross-status cursor replay error=%v", err)
	}

	rollbackSourceID, _, rollbackConflictID := seedDirectoryConflictResolutionFixture(t, ctx, pool, now.Add(2*time.Minute), "failed", "open")
	rollbackProof, rollbackRequest := proofFor()
	failingService, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: failingDirectoryResolutionAuditor{err: errors.New("audit injection")}, HighRisk: reauthentication,
		Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingService.ResolveConflict(ctx, actor, rollbackSourceID, rollbackConflictID, iam.ResolveDirectorySyncConflictCommand{Version: 1, Decision: iam.DirectoryConflictResolutionKeepLastSafe, Reason: "confirmed audit rollback condition"}, rollbackProof, rollbackRequest); err == nil || !strings.Contains(err.Error(), "audit injection") {
		t.Fatalf("audit failure resolution error=%v", err)
	}
	var rollbackStatus, challengeStatus string
	var rollbackVersion int64
	if err := pool.QueryRow(ctx, `SELECT status, version FROM directory_sync_conflicts WHERE id=$1`, rollbackConflictID).Scan(&rollbackStatus, &rollbackVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, uuid.MustParse(rollbackProof.ChallengeID)).Scan(&challengeStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='identity.directory_conflict.resolve' AND resource_id=$1`, rollbackConflictID.String()).Scan(&resolutionAuditCount); err != nil {
		t.Fatal(err)
	}
	if rollbackStatus != "open" || rollbackVersion != 1 || challengeStatus != "consumed" || resolutionAuditCount != 0 {
		t.Fatalf("audit rollback state conflict=%s/%d challenge=%s audit=%d", rollbackStatus, rollbackVersion, challengeStatus, resolutionAuditCount)
	}
	if _, err := failingService.ResolveConflict(ctx, actor, rollbackSourceID, rollbackConflictID, iam.ResolveDirectorySyncConflictCommand{Version: 1, Decision: iam.DirectoryConflictResolutionKeepLastSafe, Reason: "confirmed audit rollback condition"}, rollbackProof, rollbackRequest); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("consumed proof replay error=%v", err)
	}
	recoveryProof, recoveryRequest := proofFor()
	recoveryService, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, HighRisk: reauthentication,
		Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoveryService.ResolveConflict(ctx, actor, rollbackSourceID, rollbackConflictID, iam.ResolveDirectorySyncConflictCommand{Version: 1, Decision: iam.DirectoryConflictResolutionKeepLastSafe, Reason: "confirmed recovery with fresh proof"}, recoveryProof, recoveryRequest); err != nil {
		t.Fatalf("fresh proof recovery error=%v", err)
	}
}

func isolatedIntegrationDatabase(t *testing.T, ctx context.Context, databaseURL, prefix string) (*pgxpool.Pool, *pgxpool.Pool, string) {
	t.Helper()
	adminPool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := prefix + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminPool.Exec(ctx, `CREATE DATABASE `+databaseName); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	configuration.ConnConfig.Database = databaseName
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	return adminPool, pool, databaseName
}

func seedDirectoryConflictResolutionFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, now time.Time, jobStatus, conflictStatus string) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	sourceID, jobID, conflictID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO identity_sources (
		id, name, source_kind, status, secret_reference, required_mappings_complete, verified_at, version, created_at, updated_at
	) VALUES ($1,$2,'scim','verified','secret://iam/conflict',TRUE,$3,3,$3,$3)`, sourceID, "Conflict SCIM "+sourceID.String(), now); err != nil {
		t.Fatal(err)
	}
	completedAt := any(nil)
	if jobStatus == "completed" || jobStatus == "failed" {
		completedAt = now
	}
	if _, err := pool.Exec(ctx, `INSERT INTO directory_sync_jobs (
		id, identity_source_id, source_version, run_marker, mode, status, phase, requested_by, request_id, created_at, updated_at, completed_at
	) VALUES ($1,$2,3,$3,'apply',$4,'finalize','test:admin',$5,$6,$6,$7)`, jobID, sourceID, uuid.New(), jobStatus, uuid.New(), now, completedAt); err != nil {
		t.Fatal(err)
	}
	resolvedAt := any(nil)
	resolvedBy := any(nil)
	if conflictStatus == "resolved" {
		resolvedAt, resolvedBy = now, "legacy-actor"
	}
	if _, err := pool.Exec(ctx, `INSERT INTO directory_sync_conflicts (
		id,sync_job_id,identity_source_id,object_type,external_id,conflict_code,details,status,resolved_by,resolved_at,created_at
	) VALUES ($1,$2,$3,'user','external-1','AMBIGUOUS_EMAIL','{}',$4,$5,$6,$7)`, conflictID, jobID, sourceID, conflictStatus, resolvedBy, resolvedAt, now); err != nil {
		t.Fatal(err)
	}
	return sourceID, jobID, conflictID
}

type barrierHighRiskAuthorizer struct {
	delegate iam.HighRiskAuthorizer
	ready    chan struct{}
	release  <-chan struct{}
}

func (authorizer *barrierHighRiskAuthorizer) Authorize(ctx context.Context, actor identity.Principal, operation string, proof iam.HighRiskProof, request iam.RequestContext) error {
	if err := authorizer.delegate.Authorize(ctx, actor, operation, proof, request); err != nil {
		return err
	}
	authorizer.ready <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-authorizer.release:
		return nil
	}
}

type failingDirectoryResolutionAuditor struct{ err error }

func (auditor failingDirectoryResolutionAuditor) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, auditor.err
}
