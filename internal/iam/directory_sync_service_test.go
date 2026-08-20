package iam

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
)

func TestDirectorySyncServiceCreatesPreviewJobOutboxAndAuditAtomically(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	source := IdentitySource{
		ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified,
		SecretReference: "secret://iam/scim", VerifiedAt: now.Add(-time.Hour), Version: 7,
	}
	store := &directorySyncStoreFake{source: source}
	queue := &directorySyncJobQueueFake{}
	auditor := &directorySyncAuditFake{}
	service, err := NewDirectorySyncService(DirectorySyncServiceConfig{
		Store: store, Jobs: queue, Auditor: auditor, Clock: func() time.Time { return now }, ConflictCursors: newDirectoryTestConflictCursorCodec(t, func() time.Time { return now }),
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncService() error = %v", err)
	}
	created, err := service.Start(context.Background(), directorySyncAdmin(), source.ID, DirectorySyncModePreview, 7, RequestContext{
		RequestID: uuid.NewString(), SourceIP: "192.0.2.15",
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if created.ID == uuid.Nil || created.RunMarker != uuid.Nil || created.IdentitySourceID != source.ID || created.SourceVersion != 7 || created.Mode != DirectorySyncModePreview || created.Status != DirectorySyncStatusPending {
		t.Fatalf("Start() job = %#v", created)
	}
	if store.inserted.ID != created.ID || store.inserted.RunMarker == uuid.Nil || len(queue.jobs) != 1 || len(auditor.commands) != 1 || !store.committed {
		t.Fatalf("atomic effects inserted=%#v jobs=%d audits=%d committed=%v", store.inserted, len(queue.jobs), len(auditor.commands), store.committed)
	}
	if queue.jobs[0].Kind != JobKindDirectorySync || queue.jobs[0].AggregateID != created.ID {
		t.Fatalf("outbox job = %#v", queue.jobs[0])
	}
	if strings.Contains(string(queue.jobs[0].Payload), source.SecretReference) || strings.Contains(string(queue.jobs[0].Payload), "cursor") {
		t.Fatalf("outbox payload leaked secret/cursor: %s", queue.jobs[0].Payload)
	}
	var payload DirectorySyncJobPayload
	if err := json.Unmarshal(queue.jobs[0].Payload, &payload); err != nil || payload.JobID != created.ID || payload.SourceID != source.ID || payload.Mode != DirectorySyncModePreview {
		t.Fatalf("outbox payload = %#v, error = %v", payload, err)
	}
	if auditor.commands[0].Action != "identity.directory_sync.preview.request" {
		t.Fatalf("audit action = %q", auditor.commands[0].Action)
	}
}

func TestDirectorySyncServiceRejectsOIDCApplyAndStaleSourceVersionBeforeEnqueue(t *testing.T) {
	tests := []struct {
		name            string
		source          IdentitySource
		expectedVersion int64
		want            error
	}{
		{
			name: "oidc apply", source: IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusVerified, VerifiedAt: time.Now(), Version: 3},
			expectedVersion: 3, want: ErrDirectoryApplyUnsupported,
		},
		{
			name: "stale source", source: IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: time.Now(), Version: 4},
			expectedVersion: 3, want: ErrIAMConflict,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &directorySyncStoreFake{source: test.source}
			queue := &directorySyncJobQueueFake{}
			service, err := NewDirectorySyncService(DirectorySyncServiceConfig{Store: store, Jobs: queue, Auditor: &directorySyncAuditFake{}, Clock: time.Now, ConflictCursors: newDirectoryTestConflictCursorCodec(t, time.Now)})
			if err != nil {
				t.Fatalf("NewDirectorySyncService() error = %v", err)
			}
			_, err = service.Start(context.Background(), directorySyncAdmin(), test.source.ID, DirectorySyncModeApply, test.expectedVersion, RequestContext{RequestID: uuid.NewString()})
			if !errors.Is(err, test.want) {
				t.Fatalf("Start() error = %v, want %v", err, test.want)
			}
			if len(queue.jobs) != 0 || store.inserted.ID != uuid.Nil || store.committed {
				t.Fatalf("rejected start produced effects: %#v %#v", store.inserted, queue.jobs)
			}
		})
	}
}

func TestDirectorySyncServiceRollsBackWhenAuditFails(t *testing.T) {
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: time.Now(), Version: 2}
	store := &directorySyncStoreFake{source: source}
	queue := &directorySyncJobQueueFake{}
	auditor := &directorySyncAuditFake{err: errors.New("audit unavailable")}
	service, err := NewDirectorySyncService(DirectorySyncServiceConfig{Store: store, Jobs: queue, Auditor: auditor, Clock: time.Now, ConflictCursors: newDirectoryTestConflictCursorCodec(t, time.Now)})
	if err != nil {
		t.Fatalf("NewDirectorySyncService() error = %v", err)
	}
	_, err = service.Start(context.Background(), directorySyncAdmin(), source.ID, DirectorySyncModePreview, 2, RequestContext{RequestID: uuid.NewString()})
	if err == nil || store.committed {
		t.Fatalf("Start() error = %v, committed = %v", err, store.committed)
	}
}

func TestDirectorySyncServiceConflictListHidesUnknownSource(t *testing.T) {
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: time.Now(), Version: 2}
	service, err := NewDirectorySyncService(DirectorySyncServiceConfig{
		Store: &directorySyncStoreFake{source: source}, Jobs: &directorySyncJobQueueFake{}, Auditor: &directorySyncAuditFake{}, Clock: time.Now, ConflictCursors: newDirectoryTestConflictCursorCodec(t, time.Now),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ListConflicts(context.Background(), directorySyncAdmin(), uuid.New(), DirectorySyncConflictStatusOpen, Page{Limit: 50})
	if !errors.Is(err, ErrIdentitySourceNotFound) {
		t.Fatalf("ListConflicts(unknown source) error = %v", err)
	}
}

func TestDirectorySyncServiceReplacesRepositoryCursorWithBoundOpaqueCursor(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 45, 0, 0, time.UTC)
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: now, Version: 2}
	conflict := DirectorySyncConflict{ID: uuid.New(), IdentitySourceID: source.ID, CreatedAt: now.Add(-time.Minute)}
	store := &directorySyncStoreFake{source: source, conflictPage: DirectorySyncConflictPage{Items: []DirectorySyncConflict{conflict}, NextCursor: "repository-cursor-must-not-escape"}}
	service, err := NewDirectorySyncService(DirectorySyncServiceConfig{
		Store: store, Jobs: &directorySyncJobQueueFake{}, Auditor: &directorySyncAuditFake{}, Clock: func() time.Time { return now }, ConflictCursors: newDirectoryTestConflictCursorCodec(t, func() time.Time { return now }),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ListConflicts(context.Background(), directorySyncAdmin(), source.ID, DirectorySyncConflictStatusOpen, Page{Limit: 25})
	if err != nil || first.NextCursor == "" || first.NextCursor == "repository-cursor-must-not-escape" {
		t.Fatalf("ListConflicts(first)=%#v error=%v", first, err)
	}
	store.conflictPage = DirectorySyncConflictPage{}
	if _, err := service.ListConflicts(context.Background(), directorySyncAdmin(), source.ID, DirectorySyncConflictStatusOpen, Page{Limit: 25, Cursor: first.NextCursor}); err != nil {
		t.Fatal(err)
	}
	if !store.listedPage.BeforeTime.Equal(conflict.CreatedAt) || store.listedPage.BeforeID != conflict.ID {
		t.Fatalf("decoded repository page=%#v", store.listedPage)
	}
	if _, err := service.ListConflicts(context.Background(), directorySyncAdmin(), source.ID, DirectorySyncConflictStatusOpen, Page{Limit: 50, Cursor: first.NextCursor}); !errors.Is(err, ErrPageInvalid) {
		t.Fatalf("changed limit error=%v", err)
	}
}

func TestDirectoryConflictResolutionConsumesProofOnlyAfterPreflightAndAuditsDigest(t *testing.T) {
	now := time.Date(2026, 8, 21, 14, 30, 0, 0, time.UTC)
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: now, Version: 2}
	conflict := DirectorySyncConflict{
		ID: uuid.New(), SyncJobID: uuid.New(), IdentitySourceID: source.ID, ObjectType: "user", ExternalID: "external-secret",
		Code: "AMBIGUOUS_EMAIL", Details: json.RawMessage(`{"email":"private@example.com"}`), Status: "open", Version: 4, CreatedAt: now.Add(-time.Minute),
	}
	store := &directorySyncStoreFake{source: source, conflict: conflict, conflictJobStatus: DirectorySyncStatusCompleted}
	highRisk := &directoryConflictHighRiskFake{}
	auditor := &directorySyncAuditFake{}
	service, err := NewDirectorySyncService(DirectorySyncServiceConfig{
		Store: store, Jobs: &directorySyncJobQueueFake{}, Auditor: auditor, HighRisk: highRisk,
		Clock: func() time.Time { return now }, ConflictCursors: newDirectoryTestConflictCursorCodec(t, func() time.Time { return now }),
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := directorySyncAdmin()
	actor.Governed, actor.GovernedUserID = true, uuid.NewString()
	actor.RoleScopes = []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}}
	resolved, err := service.ResolveConflict(context.Background(), actor, source.ID, conflict.ID, ResolveDirectorySyncConflictCommand{
		Version: 4, Decision: DirectoryConflictResolutionKeepLastSafe, Reason: "  已核实上游目录重复账号，保留最后安全状态。  ",
	}, HighRiskProof{ChallengeID: uuid.NewString(), Evidence: "opaque", Confirmed: true}, RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.70"})
	if err != nil {
		t.Fatalf("ResolveConflict() error=%v", err)
	}
	if resolved.Status != "resolved" || resolved.Version != 5 || resolved.ResolutionDecision != DirectoryConflictResolutionKeepLastSafe ||
		resolved.ResolutionReason != "已核实上游目录重复账号，保留最后安全状态。" || resolved.ResolvedBy != actor.GovernedUserID || resolved.ResolvedAt == nil || !resolved.ResolvedAt.Equal(now) {
		t.Fatalf("resolved conflict=%#v", resolved)
	}
	if len(highRisk.operations) != 1 || highRisk.operations[0] != string(ReauthenticationOperationDirectoryConflictResolve) {
		t.Fatalf("high-risk operations=%v", highRisk.operations)
	}
	if len(auditor.commands) != 1 {
		t.Fatalf("audit count=%d", len(auditor.commands))
	}
	metadata := auditor.commands[0].Metadata
	wantDigest := "423730f8e16be5f9302075845d7bcc766f6b77a5acb311c2c713099da0953b45"
	wantMetadata := []string{"identity_source_id", "sync_job_id", "object_type", "conflict_code", "decision", "previous_status", "new_status", "previous_version", "new_version", "reason_digest", "reason_characters"}
	if len(metadata) != len(wantMetadata) {
		t.Fatalf("audit metadata keys=%v", metadata)
	}
	for _, key := range wantMetadata {
		if _, found := metadata[key]; !found {
			t.Fatalf("audit metadata missing %q: %v", key, metadata)
		}
	}
	if auditor.commands[0].Action != "identity.directory_conflict.resolve" || auditor.commands[0].ResourceType != "directory_sync_conflict" || metadata["reason_digest"] != wantDigest || metadata["reason_characters"] != 21 {
		t.Fatalf("audit=%#v", auditor.commands[0])
	}
	auditJSON, _ := json.Marshal(auditor.commands[0])
	for _, forbidden := range []string{"已核实", "external-secret", "private@example.com", "opaque"} {
		if strings.Contains(string(auditJSON), forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, auditJSON)
		}
	}
}

func TestDirectoryConflictResolutionPreflightFailuresDoNotConsumeProof(t *testing.T) {
	now := time.Date(2026, 8, 21, 14, 30, 0, 0, time.UTC)
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: now, Version: 2}
	baseConflict := DirectorySyncConflict{ID: uuid.New(), SyncJobID: uuid.New(), IdentitySourceID: source.ID, ObjectType: "user", Code: "AMBIGUOUS_EMAIL", Status: "open", Version: 4, CreatedAt: now}
	tests := []struct {
		name      string
		actor     identity.Principal
		sourceID  uuid.UUID
		conflict  DirectorySyncConflict
		jobStatus DirectorySyncStatus
		command   ResolveDirectorySyncConflictCommand
		want      error
	}{
		{name: "unauthorized", actor: identity.Principal{Subject: "viewer", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleViewer}, Governed: true, GovernedUserID: uuid.NewString()}, sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: validDirectoryResolutionCommand(4), want: identity.ErrActionDenied},
		{name: "unknown source", actor: governedDirectorySyncAdmin(), sourceID: uuid.New(), conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: validDirectoryResolutionCommand(4), want: ErrIdentitySourceNotFound},
		{name: "cross source conflict", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: DirectorySyncConflict{}, jobStatus: DirectorySyncStatusCompleted, command: validDirectoryResolutionCommand(4), want: ErrDirectoryConflictNotFound},
		{name: "stale version", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: validDirectoryResolutionCommand(3), want: ErrIAMConflict},
		{name: "already resolved", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: func() DirectorySyncConflict { value := baseConflict; value.Status = "resolved"; return value }(), jobStatus: DirectorySyncStatusCompleted, command: validDirectoryResolutionCommand(4), want: ErrIAMConflict},
		{name: "active job", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusRunning, command: validDirectoryResolutionCommand(4), want: ErrIAMConflict},
		{name: "non governed actor", actor: directorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: validDirectoryResolutionCommand(4), want: identity.ErrActionDenied},
		{name: "unknown decision", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: ResolveDirectorySyncConflictCommand{Version: 4, Decision: "merge", Reason: "valid resolution reason"}, want: ErrIdentitySourceInputInvalid},
		{name: "short reason", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: ResolveDirectorySyncConflictCommand{Version: 4, Decision: DirectoryConflictResolutionKeepLastSafe, Reason: "1234567"}, want: ErrIdentitySourceInputInvalid},
		{name: "long reason", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: ResolveDirectorySyncConflictCommand{Version: 4, Decision: DirectoryConflictResolutionKeepLastSafe, Reason: strings.Repeat("界", 513)}, want: ErrIdentitySourceInputInvalid},
		{name: "blank reason", actor: governedDirectorySyncAdmin(), sourceID: source.ID, conflict: baseConflict, jobStatus: DirectorySyncStatusCompleted, command: ResolveDirectorySyncConflictCommand{Version: 4, Decision: DirectoryConflictResolutionKeepLastSafe, Reason: "        "}, want: ErrIdentitySourceInputInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &directorySyncStoreFake{source: source, conflict: test.conflict, conflictJobStatus: test.jobStatus}
			highRisk := &directoryConflictHighRiskFake{}
			service, err := NewDirectorySyncService(DirectorySyncServiceConfig{Store: store, Jobs: &directorySyncJobQueueFake{}, Auditor: &directorySyncAuditFake{}, HighRisk: highRisk, Clock: func() time.Time { return now }, ConflictCursors: newDirectoryTestConflictCursorCodec(t, func() time.Time { return now })})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.ResolveConflict(context.Background(), test.actor, test.sourceID, baseConflict.ID, test.command, HighRiskProof{Confirmed: true}, RequestContext{RequestID: uuid.NewString()})
			if !errors.Is(err, test.want) {
				t.Fatalf("ResolveConflict() error=%v want=%v", err, test.want)
			}
			if len(highRisk.operations) != 0 {
				t.Fatalf("proof consumed for preflight failure: %v", highRisk.operations)
			}
		})
	}
}

func TestDirectoryConflictResolutionRechecksAfterProofAndRollsBackAuditFailure(t *testing.T) {
	now := time.Date(2026, 8, 21, 14, 45, 0, 0, time.UTC)
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceSCIM, Status: IdentitySourceStatusVerified, VerifiedAt: now, Version: 2}
	baseConflict := DirectorySyncConflict{ID: uuid.New(), SyncJobID: uuid.New(), IdentitySourceID: source.ID, ObjectType: "user", Code: "AMBIGUOUS_EMAIL", Status: "open", Version: 1, CreatedAt: now}
	t.Run("race after proof", func(t *testing.T) {
		store := &directorySyncStoreFake{source: source, conflict: baseConflict, conflictJobStatus: DirectorySyncStatusCompleted}
		highRisk := &directoryConflictHighRiskFake{onAuthorize: func() { store.conflict.Version++ }}
		service, err := NewDirectorySyncService(DirectorySyncServiceConfig{Store: store, Jobs: &directorySyncJobQueueFake{}, Auditor: &directorySyncAuditFake{}, HighRisk: highRisk, Clock: func() time.Time { return now }, ConflictCursors: newDirectoryTestConflictCursorCodec(t, func() time.Time { return now })})
		if err != nil {
			t.Fatal(err)
		}
		_, err = service.ResolveConflict(context.Background(), governedDirectorySyncAdmin(), source.ID, baseConflict.ID, validDirectoryResolutionCommand(1), HighRiskProof{Confirmed: true}, RequestContext{RequestID: uuid.NewString()})
		if !errors.Is(err, ErrIAMConflict) || len(highRisk.operations) != 1 || store.conflict.Status != "open" || store.conflict.Version != 2 {
			t.Fatalf("post-proof race error=%v operations=%v conflict=%#v", err, highRisk.operations, store.conflict)
		}
	})
	t.Run("audit append failure", func(t *testing.T) {
		store := &directorySyncStoreFake{source: source, conflict: baseConflict, conflictJobStatus: DirectorySyncStatusFailed}
		highRisk := &directoryConflictHighRiskFake{}
		auditor := &directorySyncAuditFake{err: errors.New("audit unavailable")}
		service, err := NewDirectorySyncService(DirectorySyncServiceConfig{Store: store, Jobs: &directorySyncJobQueueFake{}, Auditor: auditor, HighRisk: highRisk, Clock: func() time.Time { return now }, ConflictCursors: newDirectoryTestConflictCursorCodec(t, func() time.Time { return now })})
		if err != nil {
			t.Fatal(err)
		}
		_, err = service.ResolveConflict(context.Background(), governedDirectorySyncAdmin(), source.ID, baseConflict.ID, validDirectoryResolutionCommand(1), HighRiskProof{Confirmed: true}, RequestContext{RequestID: uuid.NewString()})
		if err == nil || len(highRisk.operations) != 1 || store.conflict.Status != "open" || store.conflict.Version != 1 || len(auditor.commands) != 0 {
			t.Fatalf("audit rollback error=%v operations=%v conflict=%#v audits=%d", err, highRisk.operations, store.conflict, len(auditor.commands))
		}
	})
}

func validDirectoryResolutionCommand(version int64) ResolveDirectorySyncConflictCommand {
	return ResolveDirectorySyncConflictCommand{Version: version, Decision: DirectoryConflictResolutionKeepLastSafe, Reason: "confirmed upstream conflict"}
}

func governedDirectorySyncAdmin() identity.Principal {
	actor := directorySyncAdmin()
	actor.Governed, actor.GovernedUserID = true, uuid.NewString()
	actor.RoleScopes = []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}}
	return actor
}

type directoryConflictHighRiskFake struct {
	operations  []string
	onAuthorize func()
	err         error
}

func (fake *directoryConflictHighRiskFake) Authorize(_ context.Context, _ identity.Principal, operation string, _ HighRiskProof, _ RequestContext) error {
	fake.operations = append(fake.operations, operation)
	if fake.onAuthorize != nil {
		fake.onAuthorize()
	}
	return fake.err
}

type directorySyncStoreFake struct {
	source            IdentitySource
	inserted          DirectorySyncJob
	committed         bool
	conflictPage      DirectorySyncConflictPage
	listedPage        Page
	conflict          DirectorySyncConflict
	conflictJobStatus DirectorySyncStatus
}

func (store *directorySyncStoreFake) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	conflictBefore := store.conflict
	if err := function(nil); err != nil {
		store.inserted = DirectorySyncJob{}
		store.conflict = conflictBefore
		return err
	}
	store.committed = true
	return nil
}

func (store *directorySyncStoreFake) GetIdentitySource(_ context.Context, _ pgx.Tx, id uuid.UUID) (IdentitySource, error) {
	if id != store.source.ID {
		return IdentitySource{}, ErrIdentitySourceNotFound
	}
	return store.source, nil
}

func (store *directorySyncStoreFake) InsertDirectorySyncJob(_ context.Context, _ pgx.Tx, job DirectorySyncJob) error {
	store.inserted = job
	return nil
}

func (store *directorySyncStoreFake) GetDirectorySyncJob(context.Context, uuid.UUID, uuid.UUID) (DirectorySyncJob, error) {
	return DirectorySyncJob{}, errors.New("unexpected GetDirectorySyncJob call")
}

func (store *directorySyncStoreFake) ListDirectorySyncConflicts(_ context.Context, _ uuid.UUID, _ DirectorySyncConflictStatusFilter, page Page) (DirectorySyncConflictPage, error) {
	store.listedPage = page
	return store.conflictPage, nil
}

func (store *directorySyncStoreFake) GetDirectorySyncConflict(_ context.Context, sourceID, conflictID uuid.UUID) (DirectorySyncConflict, DirectorySyncStatus, error) {
	if store.conflict.ID == uuid.Nil || store.conflict.ID != conflictID || store.conflict.IdentitySourceID != sourceID {
		return DirectorySyncConflict{}, "", ErrDirectoryConflictNotFound
	}
	return store.conflict, store.conflictJobStatus, nil
}

func (store *directorySyncStoreFake) LockDirectorySyncConflict(ctx context.Context, _ pgx.Tx, sourceID, conflictID uuid.UUID) (DirectorySyncConflict, DirectorySyncStatus, error) {
	return store.GetDirectorySyncConflict(ctx, sourceID, conflictID)
}

func (store *directorySyncStoreFake) ResolveDirectorySyncConflict(_ context.Context, _ pgx.Tx, conflict DirectorySyncConflict, expectedVersion int64) error {
	if store.conflict.Version != expectedVersion || store.conflict.Status != "open" {
		return ErrIAMConflict
	}
	store.conflict = conflict
	return nil
}

type directorySyncJobQueueFake struct{ jobs []jobs.Job }

func (queue *directorySyncJobQueueFake) Enqueue(_ context.Context, _ pgx.Tx, job jobs.Job) error {
	queue.jobs = append(queue.jobs, job)
	return nil
}

type directorySyncAuditFake struct {
	commands []audit.AppendCommand
	err      error
}

func (recorder *directorySyncAuditFake) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	if recorder.err != nil {
		return audit.Event{}, recorder.err
	}
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

func directorySyncAdmin() identity.Principal {
	return identity.Principal{Subject: "user:directory-admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}}
}
