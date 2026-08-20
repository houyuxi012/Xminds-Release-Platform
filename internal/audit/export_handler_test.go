package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
)

func TestExportHandlerWritesVerifiedImmutableJSONLinesAndCompletes(t *testing.T) {
	t.Parallel()

	fixture := newExportHandlerFixture(t)
	if err := fixture.handler.Handle(context.Background(), fixture.job); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	completed := fixture.repository.export
	if completed.Status != ExportStatusCompleted || completed.SHA256 == "" || completed.SizeBytes <= 0 || completed.ExpiresAt.IsZero() {
		t.Fatalf("completed export = %+v", completed)
	}
	if !strings.HasPrefix(completed.ObjectKey, "audit-exports/ngep/") || !strings.HasSuffix(completed.ObjectKey, "/"+completed.SHA256+".jsonl") {
		t.Fatalf("immutable object key = %q", completed.ObjectKey)
	}
	payload := fixture.store.objects[completed.ObjectKey]
	if len(bytes.Split(bytes.TrimSpace(payload), []byte("\n"))) != 2 {
		t.Fatalf("JSONL payload = %q", payload)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != completed.SHA256 {
		t.Fatalf("stored digest = %s, want %s", completed.SHA256, hex.EncodeToString(digest[:]))
	}
	for key := range fixture.store.objects {
		if strings.Contains(key, "/current/") {
			t.Fatalf("mutable export object written: %s", key)
		}
	}
}

func TestExportHandlerReplayDoesNotRequeryCompletedExport(t *testing.T) {
	t.Parallel()

	fixture := newExportHandlerFixture(t)
	if err := fixture.handler.Handle(context.Background(), fixture.job); err != nil {
		t.Fatal(err)
	}
	queryCalls := fixture.repository.queryCalls
	if err := fixture.handler.Handle(context.Background(), fixture.job); err != nil {
		t.Fatalf("replayed Handle() error = %v", err)
	}
	if fixture.repository.queryCalls != queryCalls {
		t.Fatalf("replay query calls = %d, want %d", fixture.repository.queryCalls, queryCalls)
	}
}

func TestExportHandlerReturnsStableCodeOnReadBackMismatch(t *testing.T) {
	t.Parallel()

	fixture := newExportHandlerFixture(t)
	fixture.store.corrupt = true
	err := fixture.handler.Handle(context.Background(), fixture.job)
	if got := jobs.ErrorCode(err); got != "audit_export_digest_mismatch" {
		t.Fatalf("ErrorCode() = %q, want audit_export_digest_mismatch (error=%v)", got, err)
	}
	if fixture.repository.export.Status != ExportStatusPending {
		t.Fatalf("export status = %s, want pending", fixture.repository.export.Status)
	}
}

func TestExportHandlerDeadLetterMarksExportFailed(t *testing.T) {
	t.Parallel()

	fixture := newExportHandlerFixture(t)
	if err := fixture.handler.HandleDeadLetter(context.Background(), fixture.job, "audit_export_store_failed"); err != nil {
		t.Fatalf("HandleDeadLetter() error = %v", err)
	}
	if fixture.repository.export.Status != ExportStatusFailed || fixture.repository.export.ErrorCode != "audit_export_store_failed" {
		t.Fatalf("failed export = %+v", fixture.repository.export)
	}
}

func TestServiceReturnsAuthorizedShortLivedExportDownload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 6, 0, 0, 0, time.UTC)
	exportID := uuid.New()
	repository := &exportRepositoryFake{export: Export{
		ID: exportID, ProductID: "ngep", Status: ExportStatusCompleted,
		ObjectKey: "audit-exports/ngep/id/digest.jsonl", SHA256: strings.Repeat("a", 64), SizeBytes: 100,
		ExpiresAt: now.Add(time.Hour),
	}}
	service := NewService(repository)
	service.now = func() time.Time { return now }
	principal := identity.Principal{
		Subject: "auditor", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RoleAuditor}, ProductIDs: []string{"ngep"},
	}
	grant, err := service.GetExportDownload(context.Background(), principal, exportID)
	if err != nil {
		t.Fatalf("GetExportDownload() error = %v", err)
	}
	if grant.ObjectKey != repository.export.ObjectKey || grant.SHA256 != repository.export.SHA256 || !grant.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("download grant = %+v", grant)
	}
}

type exportHandlerFixture struct {
	handler    *ExportHandler
	job        jobs.Job
	repository *exportRepositoryFake
	store      *exportStoreFake
}

func newExportHandlerFixture(t *testing.T) exportHandlerFixture {
	t.Helper()
	now := time.Date(2026, 8, 20, 6, 0, 0, 0, time.UTC)
	exportID := uuid.New()
	filter, err := json.Marshal(QueryFilter{ProductID: "ngep"})
	if err != nil {
		t.Fatal(err)
	}
	repository := &exportRepositoryFake{
		export: Export{ID: exportID, ProductID: "ngep", Filter: filter, Status: ExportStatusPending, CreatedAt: now},
		events: []Event{
			{ID: uuid.New(), OccurredAt: now.Add(-time.Minute), ProductID: "ngep", ActorSubject: "alice", ActorKind: identity.PrincipalKindHuman, Action: "release.publish", ResourceType: "release", ResourceID: "r1", Outcome: OutcomeSuccess, RequestID: uuid.New(), Metadata: json.RawMessage(`{"version":"1.2.3"}`), PreviousHash: strings.Repeat("0", 64), EventHash: strings.Repeat("1", 64)},
			{ID: uuid.New(), OccurredAt: now.Add(-2 * time.Minute), ProductID: "ngep", ActorSubject: "bob", ActorKind: identity.PrincipalKindHuman, Action: "release.approve", ResourceType: "release", ResourceID: "r1", Outcome: OutcomeSuccess, RequestID: uuid.New(), Metadata: json.RawMessage(`{}`), PreviousHash: strings.Repeat("1", 64), EventHash: strings.Repeat("2", 64)},
		},
	}
	payload, err := json.Marshal(map[string]string{"export_id": exportID.String(), "product_id": "ngep"})
	if err != nil {
		t.Fatal(err)
	}
	store := newExportStoreFake()
	handler, err := NewExportHandler(ExportHandlerConfig{
		Repository: repository, Transactor: exportTransactorFake{}, Store: store,
		Auditor: exportAuditorFake{}, Clock: func() time.Time { return now }, TempDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return exportHandlerFixture{
		handler:    handler,
		job:        jobs.Job{ID: uuid.New(), Kind: JobKindAuditExport, AggregateID: exportID, Payload: payload, Attempts: 1},
		repository: repository, store: store,
	}
}

type exportRepositoryFake struct {
	export     Export
	events     []Event
	queryCalls int
}

func (repository *exportRepositoryFake) Append(_ context.Context, _ pgx.Tx, event Event) (Event, error) {
	return event, nil
}

func (repository *exportRepositoryFake) Query(_ context.Context, filter QueryFilter) ([]Event, error) {
	repository.queryCalls++
	if filter.BeforeID != uuid.Nil {
		return nil, nil
	}
	return append([]Event(nil), repository.events...), nil
}

func (repository *exportRepositoryFake) StartExport(context.Context, pgx.Tx, Export) error {
	return nil
}

func (repository *exportRepositoryFake) GetExport(_ context.Context, id uuid.UUID) (Export, error) {
	if id != repository.export.ID {
		return Export{}, ErrExportNotFound
	}
	return repository.export, nil
}

func (repository *exportRepositoryFake) CompleteExport(_ context.Context, _ pgx.Tx, completed Export) error {
	repository.export = completed
	return nil
}

func (repository *exportRepositoryFake) FailExport(_ context.Context, _ pgx.Tx, id uuid.UUID, code string, at time.Time) error {
	repository.export.Status = ExportStatusFailed
	repository.export.ErrorCode = code
	repository.export.UpdatedAt = at
	return nil
}

type exportTransactorFake struct{}

func (exportTransactorFake) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

type exportAuditorFake struct{}

func (exportAuditorFake) Append(_ context.Context, _ pgx.Tx, _ AppendCommand) (Event, error) {
	return Event{}, nil
}

type exportStoreFake struct {
	objects map[string][]byte
	uploads map[string]*bytes.Buffer
	corrupt bool
}

func newExportStoreFake() *exportStoreFake {
	return &exportStoreFake{objects: map[string][]byte{}, uploads: map[string]*bytes.Buffer{}}
}

func (store *exportStoreFake) BeginMultipart(_ context.Context, key, _ string) (string, error) {
	id := uuid.NewString()
	store.uploads[key+id] = &bytes.Buffer{}
	return id, nil
}

func (store *exportStoreFake) PutPart(_ context.Context, key, id string, _ int, body io.Reader, size int64, digest string) (objectstore.Part, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return objectstore.Part{}, err
	}
	actual := sha256.Sum256(payload)
	if int64(len(payload)) != size || hex.EncodeToString(actual[:]) != digest {
		return objectstore.Part{}, errors.New("invalid upload")
	}
	store.uploads[key+id].Write(payload)
	return objectstore.Part{PartNumber: 1, Size: size, SHA256: digest, ETag: "part"}, nil
}

func (store *exportStoreFake) CompleteMultipart(_ context.Context, key, id string, _ []objectstore.Part) error {
	store.objects[key] = append([]byte(nil), store.uploads[key+id].Bytes()...)
	return nil
}

func (store *exportStoreFake) AbortMultipart(_ context.Context, key, id string) error {
	delete(store.uploads, key+id)
	return nil
}

func (store *exportStoreFake) Open(_ context.Context, key string, _, _ int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	payload, ok := store.objects[key]
	if !ok {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(payload)), objectstore.ObjectInfo{Key: key, Size: int64(len(payload))}, nil
}

func (store *exportStoreFake) Stat(_ context.Context, key string) (objectstore.ObjectInfo, error) {
	payload, ok := store.objects[key]
	if !ok {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return objectstore.ObjectInfo{Key: key, Size: int64(len(payload))}, nil
}

func (store *exportStoreFake) Promote(_ context.Context, source, destination string) (objectstore.ObjectInfo, error) {
	payload := append([]byte(nil), store.objects[source]...)
	if store.corrupt {
		payload = append(payload, 'x')
	}
	store.objects[destination] = payload
	delete(store.objects, source)
	return objectstore.ObjectInfo{Key: destination, Size: int64(len(payload))}, nil
}

func (store *exportStoreFake) Delete(_ context.Context, key string) error {
	delete(store.objects, key)
	return nil
}

var _ Repository = (*exportRepositoryFake)(nil)
var _ objectstore.Store = (*exportStoreFake)(nil)
