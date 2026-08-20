package integration_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
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

func TestIAMDirectorySyncJobCreationIsDurableAtomicAndSingleActivePerSource(t *testing.T) {
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
TRUNCATE TABLE outbox_jobs, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM directory tables: %v", err)
	}
	sourceID := uuid.New()
	now := time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, secret_reference, required_mappings_complete,
    verified_at, version, created_at, updated_at
) VALUES ($1, 'Corporate SCIM', 'scim', 'verified', 'secret://iam/scim', TRUE, $2, 5, $2, $2)`, sourceID, now); err != nil {
		t.Fatalf("insert source: %v", err)
	}

	repository := iam.NewPostgresRepository(pool)
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncService() error = %v", err)
	}
	start := make(chan struct{})
	errorsByStart := make(chan error, 2)
	jobsByStart := make(chan iam.DirectorySyncJob, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			job, startErr := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModePreview, 5, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.22"})
			jobsByStart <- job
			errorsByStart <- startErr
		}()
	}
	close(start)
	group.Wait()
	close(errorsByStart)
	close(jobsByStart)
	succeeded, activeConflicts := 0, 0
	for startErr := range errorsByStart {
		switch {
		case startErr == nil:
			succeeded++
		case errors.Is(startErr, iam.ErrDirectorySyncActive):
			activeConflicts++
		default:
			t.Fatalf("concurrent Start() error = %v", startErr)
		}
	}
	if succeeded != 1 || activeConflicts != 1 {
		t.Fatalf("start outcomes success=%d active_conflict=%d", succeeded, activeConflicts)
	}
	var syncJobCount, outboxCount, auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_jobs WHERE identity_source_id=$1`, sourceID).Scan(&syncJobCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE kind=$1`, iam.JobKindDirectorySync).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM audit_events
WHERE action='identity.directory_sync.preview.request'
  AND resource_id=(SELECT id::text FROM directory_sync_jobs WHERE identity_source_id=$1)`, sourceID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if syncJobCount != 1 || outboxCount != 1 || auditCount != 1 {
		t.Fatalf("durable counts sync=%d outbox=%d audit=%d", syncJobCount, outboxCount, auditCount)
	}
	for created := range jobsByStart {
		if created.ID == uuid.Nil {
			continue
		}
		loaded, loadErr := service.GetJob(ctx, directorySyncIntegrationAdmin(), sourceID, created.ID)
		if loadErr != nil {
			t.Fatalf("GetJob() error = %v", loadErr)
		}
		if loaded.Cursor != "" || loaded.RunMarker != uuid.Nil || loaded.Phase != "" {
			t.Fatalf("GetJob() exposed worker state: %#v", loaded)
		}
		if _, loadErr := service.GetJob(ctx, directorySyncIntegrationAdmin(), uuid.New(), created.ID); !errors.Is(loadErr, iam.ErrDirectorySyncNotFound) {
			t.Fatalf("cross-source GetJob() error = %v", loadErr)
		}
	}
}

func TestDirectorySyncMigrationConvergesLegacyPartialAndMultipleActiveJobs(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	databaseName := "directory_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminPool.Exec(ctx, `CREATE DATABASE `+databaseName); err != nil {
		t.Fatal(err)
	}
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ConnConfig.Database = databaseName
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
	})
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 13)); err != nil {
		t.Fatalf("apply migrations 1..13: %v", err)
	}
	now := time.Date(2026, 8, 21, 12, 40, 0, 0, time.UTC)
	sourceID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (id, name, source_kind, status, secret_reference, required_mappings_complete, verified_at, version, created_at, updated_at)
VALUES ($1, 'Legacy SCIM', 'scim', 'verified', 'secret://iam/legacy', TRUE, $2, 3, $2, $2)`, sourceID, now); err != nil {
		t.Fatal(err)
	}
	for index, status := range []string{"pending", "running", "partial"} {
		if _, err := pool.Exec(ctx, `
INSERT INTO directory_sync_jobs (id, identity_source_id, mode, status, cursor, requested_by, request_id, created_at, updated_at)
VALUES ($1, $2, 'apply', $3, '', 'migration:test', $4, $5, $5)`, uuid.New(), sourceID, status, uuid.New(), now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 14)); err != nil {
		t.Fatalf("apply migration 14: %v", err)
	}
	var failed, coded, completed int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE status='failed'),
       count(*) FILTER (WHERE error_code='directory_migration_restart_required'),
       count(*) FILTER (WHERE completed_at IS NOT NULL)
FROM directory_sync_jobs WHERE identity_source_id=$1`, sourceID).Scan(&failed, &coded, &completed); err != nil {
		t.Fatal(err)
	}
	if failed != 3 || coded != 3 || completed != 3 {
		t.Fatalf("legacy convergence failed=%d coded=%d completed=%d", failed, coded, completed)
	}
	var statusConstraint string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='directory_sync_jobs'::regclass AND conname='directory_sync_jobs_status_check'`).Scan(&statusConstraint); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statusConstraint, "partial") {
		t.Fatalf("status constraint still permits partial: %s", statusConstraint)
	}
}

func TestIAMDirectorySyncJobCreationRollsBackOnAuditFailure(t *testing.T) {
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
TRUNCATE TABLE outbox_jobs, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	sourceID := uuid.New()
	now := time.Date(2026, 8, 21, 11, 30, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (
    id, name, source_kind, status, secret_reference, required_mappings_complete,
    verified_at, version, created_at, updated_at
) VALUES ($1, 'Corporate SCIM', 'scim', 'verified', 'secret://iam/scim', TRUE, $2, 5, $2, $2)`, sourceID, now); err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: iam.NewPostgresRepository(pool), Jobs: jobs.NewPostgresRepository(pool), Auditor: directoryIntegrationFailingAudit{}, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModePreview, 5, iam.RequestContext{RequestID: uuid.NewString()})
	if err == nil {
		t.Fatal("Start() error = nil, want audit failure")
	}
	var jobCount, outboxCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_jobs WHERE identity_source_id=$1`, sourceID).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE kind=$1`, iam.JobKindDirectorySync).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if jobCount != 0 || outboxCount != 0 {
		t.Fatalf("audit failure committed job=%d outbox=%d", jobCount, outboxCount)
	}
}

func TestIAMDirectorySyncApplyBatchAuditFailureRollsBackBusinessProgressAndSessions(t *testing.T) {
	for _, scenario := range []string{"users", "organizations", "memberships"} {
		t.Run(scenario, func(t *testing.T) {
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
			resetDirectoryIntegrationTables(t, ctx, pool)
			now := time.Date(2026, 8, 21, 11, 35, 0, 0, time.UTC)
			sourceID := uuid.New()
			seedDirectoryIntegrationSource(t, ctx, pool, sourceID, iam.IdentitySourceSCIM, now, 5)
			page := iam.SyncPage{Complete: true}
			switch scenario {
			case "users":
				userID, sessionID := uuid.New(), uuid.New()
				if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, identity_source_id, external_subject, username, display_name, email, user_kind, status, version, created_at, updated_at)
VALUES ($1, $2, 'user-existing', 'existing.user', 'Existing User', 'existing@example.com', 'external', 'active', 1, $3, $3)`, userID, sourceID, now); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at, last_used_at, absolute_expires_at, idle_expires_at)
VALUES ($1, repeat('b',64), $2, 'local_password', 0, $3::timestamptz, $3::timestamptz, $3::timestamptz + interval '2 hours', $3::timestamptz + interval '1 hour')`, sessionID, userID, now); err != nil {
					t.Fatal(err)
				}
				page.Users = []iam.DirectoryUser{{ExternalSubject: "user-existing", Username: "existing.user", DisplayName: "Disabled Upstream", Email: "existing@example.com", Enabled: false}}
			case "organizations":
				page.Organizations = []iam.DirectoryOrganization{{ExternalID: "organization-new", Name: "New Organization"}}
			case "memberships":
				page.Users = []iam.DirectoryUser{{ExternalSubject: "member-new", Username: "member.new", DisplayName: "Member New", Email: "member@example.com", Enabled: true}}
				page.Organizations = []iam.DirectoryOrganization{{ExternalID: "organization-new", Name: "New Organization"}}
				page.Memberships = []iam.DirectoryMembership{{OrganizationExternalID: "organization-new", UserExternalSubject: "member-new"}}
			}

			realAudit := audit.NewService(audit.NewPostgresRepository(pool))
			gate := &directoryIntegrationAuditGate{delegate: realAudit, failAction: "identity.directory_sync.batch.apply", failPhase: "apply_" + scenario, remainingFailures: 1}
			repository := iam.NewPostgresRepository(pool)
			service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: gate, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now)})
			if err != nil {
				t.Fatal(err)
			}
			executor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{Pool: pool, Auditor: gate, Sessions: repository, Clock: func() time.Time { return now }, BatchSize: 1})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := iam.NewDirectorySyncHandler(iam.DirectorySyncHandlerConfig{Executor: executor, Directory: &directoryIntegrationAdapter{pages: map[string]iam.SyncPage{"": page}}, MaximumTransitions: 50})
			if err != nil {
				t.Fatal(err)
			}
			created, err := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModeApply, 5, iam.RequestContext{RequestID: uuid.NewString()})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(iam.DirectorySyncJobPayload{JobID: created.ID, SourceID: sourceID, Mode: iam.DirectorySyncModeApply})
			outboxJob := jobs.Job{ID: uuid.New(), Kind: iam.JobKindDirectorySync, AggregateID: created.ID, Payload: payload, Attempts: 1}
			if err := handler.Handle(ctx, outboxJob); err == nil {
				t.Fatal("Handle() error = nil, want injected batch audit failure")
			}
			assertDirectoryBatchRollback(t, ctx, pool, created.ID, sourceID, scenario)
			gate.clearFailure()
			outboxJob.Attempts = 2
			if err := handler.Handle(ctx, outboxJob); err != nil {
				t.Fatalf("Handle(retry) error = %v", err)
			}
			completed, err := service.GetJob(ctx, directorySyncIntegrationAdmin(), sourceID, created.ID)
			if err != nil || completed.Status != iam.DirectorySyncStatusCompleted {
				t.Fatalf("completed job=%#v error=%v", completed, err)
			}
			var batchAudits int
			if err := pool.QueryRow(ctx, `
SELECT count(*) FROM audit_events
WHERE resource_id=$1 AND action='identity.directory_sync.batch.apply'
  AND metadata->>'phase'=$2 AND (metadata->>'batch_count')::integer=1`, created.ID.String(), "apply_"+scenario).Scan(&batchAudits); err != nil {
				t.Fatal(err)
			}
			if batchAudits != 1 {
				t.Fatalf("successful batch audit count = %d", batchAudits)
			}
		})
	}
}

func TestIAMDirectorySyncCompletionAndFailAuditBehavior(t *testing.T) {
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
	resetDirectoryIntegrationTables(t, ctx, pool)
	now := time.Date(2026, 8, 21, 11, 40, 0, 0, time.UTC)
	sourceID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	seedDirectoryIntegrationSource(t, ctx, pool, sourceID, iam.IdentitySourceSCIM, now, 5)
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, identity_source_id, external_subject, username, display_name, email, user_kind, status, version, created_at, updated_at)
VALUES ($1, $2, 'missing-user', 'missing.user', 'Missing User', 'missing@example.com', 'external', 'active', 1, $3, $3)`, userID, sourceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at, last_used_at, absolute_expires_at, idle_expires_at)
VALUES ($1, repeat('c',64), $2, 'local_password', 0, $3::timestamptz, $3::timestamptz, $3::timestamptz + interval '2 hours', $3::timestamptz + interval '1 hour')`, sessionID, userID, now); err != nil {
		t.Fatal(err)
	}
	realAudit := audit.NewService(audit.NewPostgresRepository(pool))
	gate := &directoryIntegrationAuditGate{delegate: realAudit, failAction: "identity.directory_sync.apply.complete", remainingFailures: 1}
	repository := iam.NewPostgresRepository(pool)
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: gate, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now)})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{Pool: pool, Auditor: gate, Sessions: repository, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := iam.NewDirectorySyncHandler(iam.DirectorySyncHandlerConfig{Executor: executor, Directory: &directoryIntegrationAdapter{pages: map[string]iam.SyncPage{"": {Complete: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModeApply, 5, iam.RequestContext{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(iam.DirectorySyncJobPayload{JobID: created.ID, SourceID: sourceID, Mode: iam.DirectorySyncModeApply})
	outboxJob := jobs.Job{ID: uuid.New(), Kind: iam.JobKindDirectorySync, AggregateID: created.ID, Payload: payload, Attempts: 1}
	if err := handler.Handle(ctx, outboxJob); err == nil {
		t.Fatal("Handle() error = nil, want completion audit failure")
	}
	var status, phase, userStatus string
	var revokedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, phase FROM directory_sync_jobs WHERE id=$1`, created.ID).Scan(&status, &phase); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, userID).Scan(&userStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT revoked_at FROM local_sessions WHERE id=$1`, sessionID).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if status != "running" || phase != "finalize" || userStatus != "active" || revokedAt != nil {
		t.Fatalf("completion rollback status=%q phase=%q user=%q revoked=%v", status, phase, userStatus, revokedAt)
	}
	gate.clearFailure()
	outboxJob.Attempts = 2
	if err := handler.Handle(ctx, outboxJob); err != nil {
		t.Fatal(err)
	}

	resetDirectoryIntegrationTables(t, ctx, pool)
	sourceID = uuid.New()
	seedDirectoryIntegrationSource(t, ctx, pool, sourceID, iam.IdentitySourceSCIM, now, 5)
	gate = &directoryIntegrationAuditGate{delegate: realAudit, failAction: "identity.directory_sync.failed", remainingFailures: 1}
	service, err = iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: gate, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now)})
	if err != nil {
		t.Fatal(err)
	}
	created, err = service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModePreview, 5, iam.RequestContext{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	executor, err = iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{Pool: pool, Auditor: gate, Sessions: repository, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Fail(ctx, created.ID, sourceID, "directory_upstream_rejected"); err == nil {
		t.Fatal("Fail() error = nil, want audit outage")
	}
	running, err := service.GetJob(ctx, directorySyncIntegrationAdmin(), sourceID, created.ID)
	if err != nil || running.Status != iam.DirectorySyncStatusPending || running.ErrorCode != "" {
		t.Fatalf("job after audit outage=%#v error=%v", running, err)
	}
	gate.clearFailure()
	if err := executor.Fail(ctx, created.ID, sourceID, "directory_upstream_rejected"); err != nil {
		t.Fatalf("retry Fail() error = %v", err)
	}
	failed, err := service.GetJob(ctx, directorySyncIntegrationAdmin(), sourceID, created.ID)
	if err != nil || failed.Status != iam.DirectorySyncStatusFailed || failed.ErrorCode != "directory_upstream_rejected" {
		t.Fatalf("failed job=%#v error=%v", failed, err)
	}
	var failureAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='identity.directory_sync.failed' AND resource_id=$1`, created.ID.String()).Scan(&failureAudits); err != nil {
		t.Fatal(err)
	}
	if failureAudits != 1 {
		t.Fatalf("failure audit count=%d, want 1", failureAudits)
	}
}

func TestIAMDirectorySyncOIDCPreviewIsDeterministicAndNonProvisioning(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE outbox_jobs, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_password_history,
local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 11, 45, 0, 0, time.UTC)
	sourceID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (id, name, source_kind, status, secret_reference, required_mappings_complete, verified_at, version, created_at, updated_at)
VALUES ($1, 'Corporate OIDC', 'oidc', 'verified', 'secret://iam/oidc', TRUE, $2, 2, $2, $2)`, sourceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, identity_source_id, external_subject, username, display_name, email, user_kind, status, version, created_at, updated_at)
VALUES ($3, $1, 'oidc-subject', 'oidc.user', 'OIDC User', 'oidc@example.com', 'external', 'active', 1, $2, $2)`, sourceID, now, userID); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{Pool: pool, Auditor: auditor, Sessions: repository, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := iam.NewDirectorySyncHandler(iam.DirectorySyncHandlerConfig{Executor: executor, Directory: &directoryIntegrationAdapter{}})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModePreview, 2, iam.RequestContext{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(iam.DirectorySyncJobPayload{JobID: created.ID, SourceID: sourceID, Mode: iam.DirectorySyncModePreview})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(ctx, jobs.Job{ID: uuid.New(), Kind: iam.JobKindDirectorySync, AggregateID: created.ID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	completed, err := service.GetJob(ctx, directorySyncIntegrationAdmin(), sourceID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	var userStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, userID).Scan(&userStatus); err != nil {
		t.Fatal(err)
	}
	if completed.Status != iam.DirectorySyncStatusCompleted || completed.CreateCount != 0 || completed.UpdateCount != 0 || completed.DisableCount != 0 || completed.ConflictCount != 0 || userStatus != "active" {
		t.Fatalf("OIDC preview job=%#v user_status=%q", completed, userStatus)
	}
}

func TestIAMDirectorySyncSCIMTotalDriftKeepsExistingObjectsAtLastSafeState(t *testing.T) {
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
	resetDirectoryIntegrationTables(t, ctx, pool)
	now := time.Date(2026, 8, 21, 12, 20, 0, 0, time.UTC)
	sourceID, existingUserID := uuid.New(), uuid.New()
	seedDirectoryIntegrationSource(t, ctx, pool, sourceID, iam.IdentitySourceSCIM, now, 5)
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, identity_source_id, external_subject, username, display_name, email, user_kind, status, version, created_at, updated_at)
VALUES ($1, $2, 'existing-not-in-first-page', 'existing.user', 'Existing User', 'existing@example.com', 'external', 'active', 1, $3, $3)`, existingUserID, sourceID, now); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/scim+json")
		if request.URL.Path != "/scim/v2/Users" || request.Header.Get("Authorization") != "Bearer directory-bearer" {
			http.NotFound(writer, request)
			return
		}
		var response string
		switch request.URL.Query().Get("startIndex") {
		case "1":
			response = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":1,"itemsPerPage":1,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"first-page-user","userName":"first.user","active":true}]}`
		case "2":
			response = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"startIndex":2,"itemsPerPage":1,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"second-page-user","userName":"second.user","active":true}]}`
		default:
			t.Fatalf("unexpected SCIM cursor query: %s", request.URL.RawQuery)
		}
		_, _ = writer.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	resolver := directoryIntegrationSecrets{
		"secret://iam/directory": []byte(fmt.Sprintf(`{"base_url":%q,"bearer_token_reference":"secret://iam/token","ca_reference":"secret://iam/ca","page_size":1}`, server.URL+"/scim/v2")),
		"secret://iam/token":     []byte("directory-bearer"),
		"secret://iam/ca":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}),
	}
	adapter, err := iam.NewSecretBackedDirectoryAdapter(iam.SecretBackedDirectoryAdapterConfig{Secrets: resolver, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now)})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModeApply, 5, iam.RequestContext{RequestID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{Pool: pool, Auditor: auditor, Sessions: repository, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := iam.NewDirectorySyncHandler(iam.DirectorySyncHandlerConfig{Executor: executor, Directory: adapter})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(iam.DirectorySyncJobPayload{JobID: created.ID, SourceID: sourceID, Mode: iam.DirectorySyncModeApply})
	outboxJob := jobs.Job{ID: uuid.New(), Kind: iam.JobKindDirectorySync, AggregateID: created.ID, Payload: payload, Attempts: 1}
	for attempt := 0; attempt < 2; attempt++ {
		if err := handler.Handle(ctx, outboxJob); err == nil {
			t.Fatalf("Handle(attempt %d) error=nil, want totalResults drift", attempt+1)
		}
	}
	var jobStatus, jobPhase, userStatus string
	var stagedUsers int
	if err := pool.QueryRow(ctx, `SELECT status, phase FROM directory_sync_jobs WHERE id=$1`, created.ID).Scan(&jobStatus, &jobPhase); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, existingUserID).Scan(&userStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_stage_users WHERE sync_job_id=$1`, created.ID).Scan(&stagedUsers); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "running" || jobPhase != "fetch" || userStatus != "active" || stagedUsers != 1 {
		t.Fatalf("last-safe state job=%s/%s user=%s staged=%d", jobStatus, jobPhase, userStatus, stagedUsers)
	}
}

func TestIAMDirectorySyncConcurrentSourcesRevalidateUsernameAndEmailMappings(t *testing.T) {
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
	for _, scenario := range []struct {
		name, secondUsername, secondEmail, conflictCode string
		failFirstBatchAudit                             bool
	}{
		{name: "username", secondUsername: "shared.user", secondEmail: "second@example.com", conflictCode: "CANONICAL_USERNAME_CONFLICT"},
		{name: "email", secondUsername: "second.user", secondEmail: "shared@example.com", conflictCode: "AMBIGUOUS_EMAIL"},
		{name: "audit rollback and retry", secondUsername: "shared.user", secondEmail: "second@example.com", conflictCode: "CANONICAL_USERNAME_CONFLICT", failFirstBatchAudit: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			resetDirectoryIntegrationTables(t, ctx, pool)
			now := time.Date(2026, 8, 21, 13, 0, 0, 0, time.UTC)
			sourceIDs := []uuid.UUID{uuid.New(), uuid.New()}
			for _, sourceID := range sourceIDs {
				seedDirectoryIntegrationSource(t, ctx, pool, sourceID, iam.IdentitySourceSCIM, now, 5)
			}
			repository := iam.NewPostgresRepository(pool)
			realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
			var auditor iam.AuditAppender = realAuditor
			var auditGate *directoryIntegrationAuditGate
			if scenario.failFirstBatchAudit {
				auditGate = &directoryIntegrationAuditGate{delegate: realAuditor, failAction: "identity.directory_sync.batch.apply", failPhase: string(iam.DirectorySyncPhaseUsers), remainingFailures: 1}
				auditor = auditGate
			}
			service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now)})
			if err != nil {
				t.Fatal(err)
			}
			executor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{Pool: pool, Auditor: auditor, Sessions: repository, Clock: func() time.Time { return now }, BatchSize: 1})
			if err != nil {
				t.Fatal(err)
			}
			usernames := []string{"shared.user", scenario.secondUsername}
			emails := []string{"shared@example.com", scenario.secondEmail}
			preparedJobs := make([]iam.DirectorySyncJob, 2)
			preparedSources := make([]iam.IdentitySource, 2)
			for index, sourceID := range sourceIDs {
				created, err := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, iam.DirectorySyncModeApply, 5, iam.RequestContext{RequestID: uuid.NewString()})
				if err != nil {
					t.Fatal(err)
				}
				job, source, err := executor.Load(ctx, created.ID, sourceID)
				if err != nil {
					t.Fatal(err)
				}
				if err := executor.Stage(ctx, job, source, iam.SyncPage{Users: []iam.DirectoryUser{{ExternalSubject: fmt.Sprintf("user-%d", index+1), Username: usernames[index], DisplayName: fmt.Sprintf("User %d", index+1), Email: emails[index], Enabled: true}}, Complete: true}); err != nil {
					t.Fatal(err)
				}
				job, source, err = executor.Load(ctx, created.ID, sourceID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := executor.Advance(ctx, job, source); err != nil {
					t.Fatal(err)
				}
				preparedJobs[index], preparedSources[index], err = executor.Load(ctx, created.ID, sourceID)
				if err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			type advanceResult struct {
				index int
				err   error
			}
			results := make(chan advanceResult, 2)
			for index := range preparedJobs {
				index := index
				go func() {
					<-start
					_, err := executor.Advance(ctx, preparedJobs[index], preparedSources[index])
					results <- advanceResult{index: index, err: err}
				}()
			}
			close(start)
			failedIndex := -1
			for range preparedJobs {
				result := <-results
				if result.err != nil {
					if !scenario.failFirstBatchAudit || failedIndex >= 0 {
						t.Errorf("concurrent apply error=%v", result.err)
					}
					failedIndex = result.index
				}
			}
			if scenario.failFirstBatchAudit {
				if failedIndex < 0 {
					t.Fatal("injected batch audit failure did not roll back an apply")
				}
				var processed bool
				var processedUsers int
				if err := pool.QueryRow(ctx, `SELECT processed FROM directory_sync_stage_users WHERE sync_job_id=$1`, preparedJobs[failedIndex].ID).Scan(&processed); err != nil {
					t.Fatal(err)
				}
				if err := pool.QueryRow(ctx, `SELECT processed_users FROM directory_sync_jobs WHERE id=$1`, preparedJobs[failedIndex].ID).Scan(&processedUsers); err != nil {
					t.Fatal(err)
				}
				if processed || processedUsers != 0 {
					t.Fatalf("audit rollback stage processed=%v processed_users=%d", processed, processedUsers)
				}
				auditGate.clearFailure()
				preparedJobs[failedIndex], preparedSources[failedIndex], err = executor.Load(ctx, preparedJobs[failedIndex].ID, preparedSources[failedIndex].ID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := executor.Advance(ctx, preparedJobs[failedIndex], preparedSources[failedIndex]); err != nil {
					t.Fatalf("retry after audit recovery: %v", err)
				}
			}
			var users, conflicts int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_principals WHERE identity_source_id=ANY($1)`, sourceIDs).Scan(&users); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_conflicts WHERE identity_source_id=ANY($1) AND conflict_code=$2`, sourceIDs, scenario.conflictCode).Scan(&conflicts); err != nil {
				t.Fatal(err)
			}
			if users != 1 || conflicts != 1 {
				t.Fatalf("concurrent mapping users=%d conflicts=%d", users, conflicts)
			}
		})
	}
}

func TestIAMDirectorySyncPreviewAndApplyPreserveOwnershipConflictsAndLastSafeState(t *testing.T) {
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
TRUNCATE TABLE outbox_jobs, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_sessions, local_auth_rate_limits,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset IAM directory tables: %v", err)
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	sourceID := uuid.New()
	existingID, missingID, duplicateID, localID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	existingOrganizationID, missingOrganizationID, localOrganizationID, conflictingParentID, selfCycleID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	roleBindingID, sessionID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (id, name, source_kind, status, secret_reference, required_mappings_complete, verified_at, version, created_at, updated_at)
VALUES ($1, 'Corporate SCIM', 'scim', 'verified', 'secret://iam/scim', TRUE, $2, 5, $2, $2)`, sourceID, now); err != nil {
		t.Fatalf("seed directory source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id, identity_source_id, external_subject, username, display_name, email, user_kind, status, version, created_at, updated_at)
VALUES
($3, $1, 'user-existing', 'alice', 'Alice Old', 'alice-old@example.com', 'external', 'active', 1, $2, $2),
($4, $1, 'user-missing', 'missing', 'Missing User', 'missing@example.com', 'external', 'active', 1, $2, $2),
($5, $1, 'user-duplicate', 'duplicate', 'Last Safe Duplicate', 'duplicate@example.com', 'external', 'active', 1, $2, $2),
($6, NULL, '', 'local.owner', 'Local Owner', 'shared@example.com', 'local', 'active', 1, $2, $2)`,
		sourceID, now, existingID, missingID, duplicateID, localID); err != nil {
		t.Fatalf("seed directory users: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_units (id, identity_source_id, external_id, name, source_owned, status, version, created_at, updated_at)
VALUES
($3, $1, 'group-existing', 'Existing Group Old', TRUE, 'active', 1, $2, $2),
($4, $1, 'group-missing', 'Missing Group', TRUE, 'active', 1, $2, $2),
($5, NULL, '', 'Local Supplemental', FALSE, 'active', 1, $2, $2),
($6, $1, 'group-conflict-parent', 'Last Safe Parent', TRUE, 'active', 1, $2, $2),
($7, $1, 'self-cycle', 'Last Safe Self Cycle', TRUE, 'active', 1, $2, $2)`,
		sourceID, now, existingOrganizationID, missingOrganizationID, localOrganizationID, conflictingParentID, selfCycleID); err != nil {
		t.Fatalf("seed directory organizations: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (id, subject_type, subject_id, role_name, scope_type, effect, valid_from, created_by, version, created_at, updated_at)
VALUES ($1, 'user', $2, 'viewer', 'platform', 'allow', $3, 'test:admin', 1, $3, $3)`,
		roleBindingID, existingID, now); err != nil {
		t.Fatalf("seed directory role binding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at, last_used_at, absolute_expires_at, idle_expires_at)
VALUES ($1, repeat('a',64), $2, 'local_password', 0, $3::timestamptz, $3::timestamptz, $3::timestamptz + interval '2 hours', $3::timestamptz + interval '1 hour')`,
		sessionID, missingID, now); err != nil {
		t.Fatalf("seed directory session: %v", err)
	}

	repository := iam.NewPostgresRepository(pool)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	queue := jobs.NewPostgresRepository(pool)
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: queue, Auditor: auditor, Clock: func() time.Time { return now }, ConflictCursors: directoryIntegrationCursorCodec(t, now)})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{
		Pool: pool, Auditor: auditor, Sessions: repository, Clock: func() time.Time { return now }, BatchSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &directoryIntegrationAdapter{pages: map[string]iam.SyncPage{
		"": {
			Users: []iam.DirectoryUser{
				{ExternalSubject: "user-existing", Username: "alice", DisplayName: "Alice Updated", Email: "alice@example.com", Enabled: true},
				{ExternalSubject: "user-new", Username: "new.user", DisplayName: "New User", Email: "new@example.com", Enabled: true},
				{ExternalSubject: "user-duplicate", Username: "duplicate", DisplayName: "Unsafe Duplicate One", Email: "duplicate-one@example.com", Enabled: true},
				{ExternalSubject: "user-ambiguous", Username: "ambiguous", DisplayName: "Ambiguous", Email: "shared@example.com", Enabled: true},
				{ExternalSubject: "user-username-one", Username: "canonical.collision", DisplayName: "Collision One", Email: "collision-one@example.com", Enabled: true},
			},
			Organizations: []iam.DirectoryOrganization{{ExternalID: "group-conflict-parent", Name: "Unsafe Parent One"}},
			NextCursor:    "page-2",
		},
		"page-2": {
			Users: []iam.DirectoryUser{
				{ExternalSubject: "user-duplicate", Username: "duplicate.changed", DisplayName: "Unsafe Duplicate Two", Email: "duplicate-two@example.com", Enabled: false},
				{ExternalSubject: "user-username-two", Username: "CANONICAL.COLLISION", DisplayName: "Collision Two", Email: "collision-two@example.com", Enabled: true},
			},
			Organizations: []iam.DirectoryOrganization{
				{ExternalID: "group-existing", Name: "Existing Group Updated"},
				{ExternalID: "group-child", Name: "Child Group"},
				{ExternalID: "cycle-a", Name: "Cycle A"},
				{ExternalID: "cycle-b", Name: "Cycle B"},
				{ExternalID: "group-conflict-parent", Name: "Unsafe Parent Two"},
				{ExternalID: "group-dependent", Name: "Unsafe Dependent"},
				{ExternalID: "self-cycle", Name: "Unsafe Self Cycle"},
			},
			OrganizationParents: []iam.DirectoryOrganizationParent{
				{OrganizationExternalID: "group-child", ParentExternalID: "group-existing"},
				{OrganizationExternalID: "cycle-a", ParentExternalID: "cycle-b"},
				{OrganizationExternalID: "cycle-b", ParentExternalID: "cycle-a"},
				{OrganizationExternalID: "group-dependent", ParentExternalID: "group-conflict-parent"},
				{OrganizationExternalID: "self-cycle", ParentExternalID: "self-cycle"},
			},
			Memberships: []iam.DirectoryMembership{
				{OrganizationExternalID: "group-existing", UserExternalSubject: "user-existing"},
				{OrganizationExternalID: "group-existing", UserExternalSubject: "user-does-not-exist"},
				{OrganizationExternalID: "group-dependent", UserExternalSubject: "user-existing"},
			},
			Complete: true,
		},
	}}
	handler, err := iam.NewDirectorySyncHandler(iam.DirectorySyncHandlerConfig{Executor: executor, Directory: adapter, MaximumTransitions: 100})
	if err != nil {
		t.Fatal(err)
	}

	runJob := func(mode iam.DirectorySyncMode, version int64) iam.DirectorySyncJob {
		t.Helper()
		created, startErr := service.Start(ctx, directorySyncIntegrationAdmin(), sourceID, mode, version, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.23"})
		if startErr != nil {
			t.Fatalf("Start(%s) error = %v", mode, startErr)
		}
		payload, marshalErr := json.Marshal(iam.DirectorySyncJobPayload{JobID: created.ID, SourceID: sourceID, Mode: mode})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if handleErr := handler.Handle(ctx, jobs.Job{ID: uuid.New(), Kind: iam.JobKindDirectorySync, AggregateID: created.ID, Payload: payload, Attempts: 1}); handleErr != nil {
			t.Fatalf("Handle(%s) error = %v", mode, handleErr)
		}
		completed, loadErr := service.GetJob(ctx, directorySyncIntegrationAdmin(), sourceID, created.ID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if completed.Status != iam.DirectorySyncStatusCompleted {
			t.Fatalf("completed %s job = %#v", mode, completed)
		}
		return completed
	}

	preview := runJob(iam.DirectorySyncModePreview, 5)
	var previewName string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM user_principals WHERE id=$1`, existingID).Scan(&previewName); err != nil {
		t.Fatal(err)
	}
	if previewName != "Alice Old" || preview.CreateCount == 0 || preview.UpdateCount == 0 || preview.DisableCount == 0 || preview.ConflictCount < 4 {
		t.Fatalf("preview changed state or missed diff: name=%q job=%#v", previewName, preview)
	}

	apply := runJob(iam.DirectorySyncModeApply, 6)
	if apply.CreateCount != preview.CreateCount || apply.UpdateCount != preview.UpdateCount || apply.DisableCount != preview.DisableCount || apply.ConflictCount != preview.ConflictCount {
		t.Fatalf("apply diff %#v does not match preview %#v", apply, preview)
	}
	var existingName, missingStatus, duplicateName, localName, existingOrganizationName, missingOrganizationStatus, localOrganizationName, conflictingParentName, selfCycleName string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM user_principals WHERE id=$1`, existingID).Scan(&existingName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE id=$1`, missingID).Scan(&missingStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT display_name FROM user_principals WHERE id=$1`, duplicateID).Scan(&duplicateName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT display_name FROM user_principals WHERE id=$1`, localID).Scan(&localName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT name FROM organization_units WHERE id=$1`, existingOrganizationID).Scan(&existingOrganizationName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM organization_units WHERE id=$1`, missingOrganizationID).Scan(&missingOrganizationStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT name FROM organization_units WHERE id=$1`, localOrganizationID).Scan(&localOrganizationName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT name FROM organization_units WHERE id=$1`, conflictingParentID).Scan(&conflictingParentName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT name FROM organization_units WHERE id=$1`, selfCycleID).Scan(&selfCycleName); err != nil {
		t.Fatal(err)
	}
	if existingName != "Alice Updated" || missingStatus != "disabled" || duplicateName != "Last Safe Duplicate" || localName != "Local Owner" ||
		existingOrganizationName != "Existing Group Updated" || missingOrganizationStatus != "disabled" || localOrganizationName != "Local Supplemental" ||
		conflictingParentName != "Last Safe Parent" || selfCycleName != "Last Safe Self Cycle" {
		t.Fatalf("ownership state existing=%q missing=%q duplicate=%q local=%q org=%q missing_org=%q local_org=%q", existingName, missingStatus, duplicateName, localName, existingOrganizationName, missingOrganizationStatus, localOrganizationName)
	}
	var roleCount, revokedSessionCount, validMembershipCount, ambiguousCount, cycleCount, collisionCount, dependentCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE id=$1 AND subject_id=$2`, roleBindingID, existingID).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE id=$1 AND revoked_at IS NOT NULL`, sessionID).Scan(&revokedSessionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships membership JOIN organization_units organization ON organization.id=membership.organization_id JOIN user_principals principal ON principal.id=membership.user_id WHERE organization.external_id='group-existing' AND principal.external_subject='user-existing' AND membership.source_owned=TRUE`).Scan(&validMembershipCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_principals WHERE identity_source_id=$1 AND external_subject='user-ambiguous'`, sourceID).Scan(&ambiguousCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_units WHERE identity_source_id=$1 AND external_id IN ('cycle-a','cycle-b')`, sourceID).Scan(&cycleCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_principals WHERE identity_source_id=$1 AND external_subject IN ('user-username-one','user-username-two')`, sourceID).Scan(&collisionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_units WHERE identity_source_id=$1 AND external_id='group-dependent'`, sourceID).Scan(&dependentCount); err != nil {
		t.Fatal(err)
	}
	if roleCount != 1 || revokedSessionCount != 1 || validMembershipCount != 1 || ambiguousCount != 0 || cycleCount != 0 || collisionCount != 0 || dependentCount != 0 {
		t.Fatalf("preservation role=%d revoked=%d membership=%d ambiguous=%d cycles=%d collisions=%d dependents=%d", roleCount, revokedSessionCount, validMembershipCount, ambiguousCount, cycleCount, collisionCount, dependentCount)
	}
	conflicts, err := service.ListConflicts(ctx, directorySyncIntegrationAdmin(), sourceID, iam.Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	codes := make(map[string]bool)
	for _, conflict := range conflicts.Items {
		codes[conflict.Code] = true
		if len(conflict.Details) > 4096 || string(conflict.Details) == "" {
			t.Fatalf("unsafe conflict details = %s", conflict.Details)
		}
	}
	for _, code := range []string{"DUPLICATE_STABLE_SUBJECT", "AMBIGUOUS_EMAIL", "CANONICAL_USERNAME_CONFLICT", "ORGANIZATION_CYCLE", "CONFLICTING_ORGANIZATION_PARENT", "MISSING_MEMBERSHIP_SUBJECT"} {
		if !codes[code] {
			t.Fatalf("missing conflict %s in %v", code, codes)
		}
	}
}

type directoryIntegrationAdapter struct{ pages map[string]iam.SyncPage }

type directoryIntegrationSecrets map[string][]byte

func directoryIntegrationCursorCodec(t *testing.T, now time.Time) *iam.DirectoryConflictCursorCodec {
	t.Helper()
	codec, err := iam.NewDirectoryConflictCursorCodec(bytes.Repeat([]byte{0x71}, 32), func() time.Time { return now }, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func (secrets directoryIntegrationSecrets) Resolve(_ context.Context, reference string) ([]byte, error) {
	value, found := secrets[reference]
	if !found {
		return nil, errors.New("directory integration secret missing")
	}
	return append([]byte(nil), value...), nil
}

type directoryIntegrationFailingAudit struct{}

func (directoryIntegrationFailingAudit) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, errors.New("audit unavailable")
}

type directoryIntegrationAuditAppender interface {
	Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error)
}

type directoryIntegrationAuditGate struct {
	mu                sync.Mutex
	delegate          directoryIntegrationAuditAppender
	failAction        string
	failPhase         string
	remainingFailures int
}

func (gate *directoryIntegrationAuditGate) Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	gate.mu.Lock()
	phase := ""
	switch value := command.Metadata["phase"].(type) {
	case string:
		phase = value
	case iam.DirectorySyncPhase:
		phase = string(value)
	}
	shouldFail := gate.remainingFailures > 0 && command.Action == gate.failAction && (gate.failPhase == "" || phase == gate.failPhase)
	if shouldFail {
		gate.remainingFailures--
	}
	gate.mu.Unlock()
	if shouldFail {
		return audit.Event{}, errors.New("injected directory audit failure")
	}
	return gate.delegate.Append(ctx, tx, command)
}

func (gate *directoryIntegrationAuditGate) clearFailure() {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.failAction, gate.failPhase, gate.remainingFailures = "", "", 0
}

func resetDirectoryIntegrationTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE outbox_jobs, directory_sync_conflicts, directory_sync_jobs,
role_bindings, organization_memberships, organization_units, local_sessions, local_auth_rate_limits,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'test:bootstrap', clock_timestamp())`); err != nil {
		t.Fatalf("reset directory integration tables: %v", err)
	}
}

func directoryMigrationSubset(t *testing.T, maximumVersion int) fstest.MapFS {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	result := fstest.MapFS{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") || len(name) < 6 {
			continue
		}
		var version int
		if _, err := fmt.Sscanf(name[:6], "%d", &version); err != nil || version > maximumVersion {
			continue
		}
		contents, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = &fstest.MapFile{Data: contents}
	}
	return result
}

func seedDirectoryIntegrationSource(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sourceID uuid.UUID, kind iam.IdentitySourceKind, now time.Time, version int64) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_sources (id, name, source_kind, status, secret_reference, required_mappings_complete, verified_at, version, created_at, updated_at)
VALUES ($1, $5, $2, 'verified', 'secret://iam/directory', TRUE, $3, $4, $3, $3)`, sourceID, kind, now, version, "Directory Source "+sourceID.String()); err != nil {
		t.Fatalf("seed directory source: %v", err)
	}
}

func assertDirectoryBatchRollback(t *testing.T, ctx context.Context, pool *pgxpool.Pool, jobID, sourceID uuid.UUID, scenario string) {
	t.Helper()
	var phase string
	var processedUsers, processedOrganizations, processedMemberships int
	if err := pool.QueryRow(ctx, `
SELECT phase, processed_users, processed_organizations, processed_memberships
FROM directory_sync_jobs WHERE id=$1`, jobID).Scan(&phase, &processedUsers, &processedOrganizations, &processedMemberships); err != nil {
		t.Fatal(err)
	}
	switch scenario {
	case "users":
		var status string
		var revokedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT status FROM user_principals WHERE identity_source_id=$1 AND external_subject='user-existing'`, sourceID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT revoked_at FROM local_sessions WHERE subject_id=(SELECT id FROM user_principals WHERE identity_source_id=$1 AND external_subject='user-existing')`, sourceID).Scan(&revokedAt); err != nil {
			t.Fatal(err)
		}
		if phase != "apply_users" || processedUsers != 0 || status != "active" || revokedAt != nil {
			t.Fatalf("user rollback phase=%q processed=%d status=%q revoked=%v", phase, processedUsers, status, revokedAt)
		}
	case "organizations":
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_units WHERE identity_source_id=$1`, sourceID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if phase != "apply_organizations" || processedOrganizations != 0 || count != 0 {
			t.Fatalf("organization rollback phase=%q processed=%d count=%d", phase, processedOrganizations, count)
		}
	case "memberships":
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if phase != "apply_memberships" || processedMemberships != 0 || count != 0 {
			t.Fatalf("membership rollback phase=%q processed=%d count=%d", phase, processedMemberships, count)
		}
	}
}

func (adapter *directoryIntegrationAdapter) Verify(context.Context, iam.IdentitySource) (iam.CapabilityReport, error) {
	return iam.CapabilityReport{Reachable: true, SupportsPagination: true}, nil
}

func (adapter *directoryIntegrationAdapter) Preview(context.Context, iam.IdentitySource) (iam.SyncDiff, error) {
	return iam.SyncDiff{}, nil
}

func (adapter *directoryIntegrationAdapter) Sync(_ context.Context, _ iam.IdentitySource, cursor string) (iam.SyncPage, error) {
	page, found := adapter.pages[cursor]
	if !found {
		return iam.SyncPage{}, iam.ErrDirectoryResponseInvalid
	}
	return page, nil
}

func directorySyncIntegrationAdmin() identity.Principal {
	return identity.Principal{Subject: "user:directory-admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
}
