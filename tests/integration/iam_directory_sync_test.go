package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: audit.NewService(audit.NewPostgresRepository(pool)), Clock: func() time.Time { return now },
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
		Store: iam.NewPostgresRepository(pool), Jobs: jobs.NewPostgresRepository(pool), Auditor: directoryIntegrationFailingAudit{}, Clock: func() time.Time { return now },
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
		Store: repository, Jobs: jobs.NewPostgresRepository(pool), Auditor: auditor, Clock: func() time.Time { return now },
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
	existingOrganizationID, missingOrganizationID, localOrganizationID, conflictingParentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
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
($6, $1, 'group-conflict-parent', 'Last Safe Parent', TRUE, 'active', 1, $2, $2)`,
		sourceID, now, existingOrganizationID, missingOrganizationID, localOrganizationID, conflictingParentID); err != nil {
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
	service, err := iam.NewDirectorySyncService(iam.DirectorySyncServiceConfig{Store: repository, Jobs: queue, Auditor: auditor, Clock: func() time.Time { return now }})
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
			},
			OrganizationParents: []iam.DirectoryOrganizationParent{
				{OrganizationExternalID: "group-child", ParentExternalID: "group-existing"},
				{OrganizationExternalID: "cycle-a", ParentExternalID: "cycle-b"},
				{OrganizationExternalID: "cycle-b", ParentExternalID: "cycle-a"},
				{OrganizationExternalID: "group-dependent", ParentExternalID: "group-conflict-parent"},
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
	var existingName, missingStatus, duplicateName, localName, existingOrganizationName, missingOrganizationStatus, localOrganizationName, conflictingParentName string
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
	if existingName != "Alice Updated" || missingStatus != "disabled" || duplicateName != "Last Safe Duplicate" || localName != "Local Owner" ||
		existingOrganizationName != "Existing Group Updated" || missingOrganizationStatus != "disabled" || localOrganizationName != "Local Supplemental" || conflictingParentName != "Last Safe Parent" {
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

type directoryIntegrationFailingAudit struct{}

func (directoryIntegrationFailingAudit) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, errors.New("audit unavailable")
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
