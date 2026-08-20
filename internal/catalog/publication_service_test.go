package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/release"
)

func TestPublicationKeepsCatalogInvisibleWhenAWriteFails(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	fixture.store.failDestination = "/snapshot.json"

	err := fixture.service.Publish(context.Background(), fixture.job)
	if !errors.Is(err, errPublicationStoreFailure) {
		t.Fatalf("Publish() error = %v, want store failure", err)
	}
	if fixture.catalogs.current != uuid.Nil {
		t.Fatalf("current catalog = %s, want none", fixture.catalogs.current)
	}
	for key := range fixture.store.objects {
		if strings.Contains(key, "/current/") || strings.HasPrefix(key, "catalogs/current/") {
			t.Fatalf("mutable current object was written: %s", key)
		}
	}
	if fixture.releases.completed != 0 {
		t.Fatalf("completed publication count = %d, want 0", fixture.releases.completed)
	}
}

func TestPublicationReplayReusesPersistedBundleAndCompletesAtomically(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	fixture.store.failDestination = "/snapshot.json"
	if err := fixture.service.Publish(context.Background(), fixture.job); err == nil {
		t.Fatal("first Publish() error = nil, want failure")
	}
	fixture.store.failDestination = ""

	if err := fixture.service.Publish(context.Background(), fixture.job); err != nil {
		t.Fatalf("replayed Publish() error = %v", err)
	}
	if fixture.catalogs.reserveCalls != 1 {
		t.Fatalf("ReserveVersions() calls = %d, want 1", fixture.catalogs.reserveCalls)
	}
	if fixture.builder.calls != 1 {
		t.Fatalf("Build() calls = %d, want 1", fixture.builder.calls)
	}
	if fixture.catalogs.current != fixture.catalogs.record.ID {
		t.Fatalf("current catalog = %s, want %s", fixture.catalogs.current, fixture.catalogs.record.ID)
	}
	if fixture.releases.completed != 1 {
		t.Fatalf("completed publication count = %d, want 1", fixture.releases.completed)
	}
	for _, role := range publicationRoleOrder {
		key := fixture.catalogs.record.Roles[role].ObjectKey
		if _, exists := fixture.store.objects[key]; !exists {
			t.Fatalf("role %s object %q is missing", role, key)
		}
	}
}

func TestPublicationRejectsReadBackDigestMismatch(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	fixture.store.corruptDestination = "/targets.json"

	err := fixture.service.Publish(context.Background(), fixture.job)
	if !errors.Is(err, ErrPublicationDigestMismatch) {
		t.Fatalf("Publish() error = %v, want %v", err, ErrPublicationDigestMismatch)
	}
	if fixture.catalogs.current != uuid.Nil {
		t.Fatalf("current catalog = %s, want none", fixture.catalogs.current)
	}
}

func TestPublicationHandlerExposesStableDigestFailureCode(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	fixture.store.corruptDestination = "/targets.json"

	err := fixture.service.Handle(context.Background(), fixture.job)
	if got := jobs.ErrorCode(err); got != "catalog_digest_mismatch" {
		t.Fatalf("ErrorCode() = %q, want catalog_digest_mismatch (error=%v)", got, err)
	}
}

func TestPublicationRejectsRevocationAttemptForPublishJob(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	fixture.releases.attempt.Kind = release.AttemptKindRevoke

	err := fixture.service.Publish(context.Background(), fixture.job)
	if !errors.Is(err, ErrPublicationJobInvalid) {
		t.Fatalf("Publish() error = %v, want %v", err, ErrPublicationJobInvalid)
	}
	if fixture.catalogs.reserveCalls != 0 || fixture.builder.calls != 0 {
		t.Fatalf("reserve/build calls = %d/%d, want 0/0", fixture.catalogs.reserveCalls, fixture.builder.calls)
	}
}

func TestPublicationDeadLetterMarksReleaseAndAttemptFailed(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	if err := fixture.service.HandleDeadLetter(context.Background(), fixture.job, "catalog_signing_failed"); err != nil {
		t.Fatalf("HandleDeadLetter() error = %v", err)
	}
	if fixture.releases.failed != 1 || fixture.releases.failureCode != "catalog_signing_failed" {
		t.Fatalf("failed count/code = %d/%q", fixture.releases.failed, fixture.releases.failureCode)
	}
	if fixture.releases.record.Status != release.StatusFailed || fixture.releases.attempt.Status != release.AttemptStatusFailed {
		t.Fatalf("release/attempt statuses = %s/%s", fixture.releases.record.Status, fixture.releases.attempt.Status)
	}
}

func TestRevocationPublicationSwitchesSignedCatalogAndCompletesAttempt(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	revokedAt := time.Date(2026, 8, 20, 3, 59, 0, 0, time.UTC)
	fixture.releases.record.Status = release.StatusPublished
	fixture.releases.record.RevokedAt = &revokedAt
	fixture.releases.record.RevocationReason = "critical vulnerability"
	fixture.releases.attempt.Kind = release.AttemptKindRevoke
	fixture.job.Kind = JobKindCatalogRevoke

	if err := fixture.service.Revoke(context.Background(), fixture.job); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if fixture.builder.revocationCalls != 1 {
		t.Fatalf("BuildRevocation() calls = %d, want 1", fixture.builder.revocationCalls)
	}
	if fixture.releases.revocationCompleted != 1 || fixture.releases.attempt.Status != release.AttemptStatusSucceeded {
		t.Fatalf("revocation completed/status = %d/%s", fixture.releases.revocationCompleted, fixture.releases.attempt.Status)
	}
	if fixture.catalogs.current != fixture.catalogs.record.ID {
		t.Fatalf("current catalog = %s, want %s", fixture.catalogs.current, fixture.catalogs.record.ID)
	}
}

func TestRevocationDeadLetterFailsAttemptWithoutChangingPublishedRelease(t *testing.T) {
	t.Parallel()

	fixture := newPublicationFixture(t)
	revokedAt := time.Date(2026, 8, 20, 3, 59, 0, 0, time.UTC)
	fixture.releases.record.Status = release.StatusPublished
	fixture.releases.record.RevokedAt = &revokedAt
	fixture.releases.record.RevocationReason = "critical vulnerability"
	fixture.releases.attempt.Kind = release.AttemptKindRevoke
	fixture.job.Kind = JobKindCatalogRevoke

	err := fixture.service.HandleDeadLetter(context.Background(), fixture.job, "catalog_store_failed")
	if err != nil {
		t.Fatalf("HandleDeadLetter() error = %v", err)
	}
	if fixture.releases.record.Status != release.StatusPublished || fixture.releases.attempt.Status != release.AttemptStatusFailed {
		t.Fatalf("release/attempt statuses = %s/%s", fixture.releases.record.Status, fixture.releases.attempt.Status)
	}
}

var errPublicationStoreFailure = errors.New("publication store failure")

type publicationFixture struct {
	service  *PublicationService
	job      jobs.Job
	catalogs *memoryPublicationCatalogs
	releases *memoryPublicationReleases
	builder  *fixedPublicationBuilder
	store    *memoryPublicationStore
}

func newPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	releaseID := uuid.New()
	attemptID := uuid.New()
	jobID := uuid.New()
	bundle := Bundle{
		Root:       mustReadPublicationFixture(t, "valid-root.json"),
		Targets:    mustReadPublicationFixture(t, "valid-targets.json"),
		Snapshot:   mustReadPublicationFixture(t, "valid-snapshot.json"),
		Timestamp:  mustReadPublicationFixture(t, "valid-timestamp.json"),
		Revocation: mustReadPublicationFixture(t, "valid-revocation.json"),
	}
	payload, err := json.Marshal(PublicationJobPayload{ReleaseID: releaseID, AttemptID: attemptID})
	if err != nil {
		t.Fatal(err)
	}
	catalogs := &memoryPublicationCatalogs{}
	releases := &memoryPublicationReleases{record: release.Release{
		ID: releaseID, ProductID: "ngep", Channel: "stable", Version: "1.2.3",
		Status: release.StatusPublishing, LockVersion: 4,
	}, attempt: release.Attempt{ID: attemptID, ReleaseID: releaseID, Kind: release.AttemptKindPublish, Status: release.AttemptStatusPending}}
	builder := &fixedPublicationBuilder{bundle: bundle}
	store := newMemoryPublicationStore()
	service, err := NewPublicationService(PublicationConfig{
		Catalogs: catalogs, Releases: releases, Transactor: immediatePublicationTransactor{},
		Builder: builder, Store: store, Auditor: discardPublicationAuditor{},
		Clock: func() time.Time { return time.Date(2026, 8, 20, 4, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewPublicationService() error = %v", err)
	}
	return publicationFixture{
		service:  service,
		job:      jobs.Job{ID: jobID, Kind: JobKindCatalogPublish, AggregateID: releaseID, Payload: payload, Attempts: 1},
		catalogs: catalogs, releases: releases, builder: builder, store: store,
	}
}

func mustReadPublicationFixture(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile("testdata/ngep-golden/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

type fixedPublicationBuilder struct {
	bundle          Bundle
	calls           int
	revocationCalls int
}

func (builder *fixedPublicationBuilder) RootVersion() uint64 { return 1 }

func (builder *fixedPublicationBuilder) Build(_ context.Context, _ release.Release, _ Versions) (Bundle, error) {
	builder.calls++
	return builder.bundle, nil
}

func (builder *fixedPublicationBuilder) BuildRevocation(_ context.Context, _ release.Release, _ Versions) (Bundle, error) {
	builder.revocationCalls++
	return builder.bundle, nil
}

type memoryPublicationCatalogs struct {
	record       VersionRecord
	current      uuid.UUID
	reserveCalls int
}

func (repository *memoryPublicationCatalogs) FindByAttempt(_ context.Context, attemptID uuid.UUID) (VersionRecord, error) {
	if repository.record.AttemptID == attemptID {
		return repository.record, nil
	}
	return VersionRecord{}, ErrVersionRecordNotFound
}

func (repository *memoryPublicationCatalogs) ReserveVersions(_ context.Context, _ pgx.Tx, _, _ string, root uint64) (Versions, error) {
	repository.reserveCalls++
	return Versions{Root: root, Targets: 1, Snapshot: 1, Timestamp: 1, Revocation: 1}, nil
}

func (repository *memoryPublicationCatalogs) Create(_ context.Context, _ pgx.Tx, record VersionRecord) error {
	repository.record = record
	return nil
}

func (repository *memoryPublicationCatalogs) SetCurrent(_ context.Context, _ pgx.Tx, _, _ string, id uuid.UUID, _ time.Time) error {
	repository.current = id
	return nil
}

func (repository *memoryPublicationCatalogs) Current(_ context.Context, _, _ string) (VersionRecord, error) {
	if repository.current == uuid.Nil {
		return VersionRecord{}, ErrCurrentCatalogNotFound
	}
	return repository.record, nil
}

type memoryPublicationReleases struct {
	record              release.Release
	attempt             release.Attempt
	completed           int
	failed              int
	failureCode         string
	revocationCompleted int
}

func (repository *memoryPublicationReleases) CompleteRevocation(_ context.Context, _ pgx.Tx, releaseID, attemptID uuid.UUID, _ time.Time) error {
	if releaseID != repository.record.ID || attemptID != repository.attempt.ID {
		return release.ErrAttemptNotFound
	}
	repository.attempt.Status = release.AttemptStatusSucceeded
	repository.revocationCompleted++
	return nil
}

func (repository *memoryPublicationReleases) FailPublication(_ context.Context, _ pgx.Tx, releaseID, attemptID uuid.UUID, code string, _ time.Time) error {
	if releaseID != repository.record.ID || attemptID != repository.attempt.ID {
		return release.ErrAttemptNotFound
	}
	repository.record.Status = release.StatusFailed
	repository.record.PublicationFailureCode = code
	repository.attempt.Status = release.AttemptStatusFailed
	repository.attempt.ErrorCode = code
	repository.failed++
	repository.failureCode = code
	return nil
}

func (repository *memoryPublicationReleases) FailRevocation(_ context.Context, _ pgx.Tx, releaseID, attemptID uuid.UUID, code string, _ time.Time) error {
	if releaseID != repository.record.ID || attemptID != repository.attempt.ID {
		return release.ErrAttemptNotFound
	}
	repository.attempt.Status = release.AttemptStatusFailed
	repository.attempt.ErrorCode = code
	return nil
}

func (repository *memoryPublicationReleases) GetByID(_ context.Context, id uuid.UUID) (release.Release, error) {
	if id != repository.record.ID {
		return release.Release{}, release.ErrReleaseNotFound
	}
	return repository.record, nil
}

func (repository *memoryPublicationReleases) GetAttemptByID(_ context.Context, id uuid.UUID) (release.Attempt, error) {
	if id != repository.attempt.ID {
		return release.Attempt{}, release.ErrAttemptNotFound
	}
	return repository.attempt, nil
}

func (repository *memoryPublicationReleases) CompletePublication(_ context.Context, _ pgx.Tx, releaseID, attemptID uuid.UUID, _ time.Time) error {
	if releaseID != repository.record.ID || attemptID != repository.attempt.ID {
		return release.ErrAttemptNotFound
	}
	repository.record.Status = release.StatusPublished
	repository.attempt.Status = release.AttemptStatusSucceeded
	repository.completed++
	return nil
}

type immediatePublicationTransactor struct{}

func (immediatePublicationTransactor) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

type discardPublicationAuditor struct{}

func (discardPublicationAuditor) Append(_ context.Context, _ pgx.Tx, _ audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, nil
}

type memoryPublicationStore struct {
	objects            map[string][]byte
	uploads            map[string]*bytes.Buffer
	failDestination    string
	corruptDestination string
}

func newMemoryPublicationStore() *memoryPublicationStore {
	return &memoryPublicationStore{objects: map[string][]byte{}, uploads: map[string]*bytes.Buffer{}}
}

func (store *memoryPublicationStore) BeginMultipart(_ context.Context, key, _ string) (string, error) {
	uploadID := uuid.NewString()
	store.uploads[key+"\x00"+uploadID] = &bytes.Buffer{}
	return uploadID, nil
}

func (store *memoryPublicationStore) PutPart(_ context.Context, key, uploadID string, _ int, body io.Reader, size int64, digest string) (objectstore.Part, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return objectstore.Part{}, err
	}
	if int64(len(payload)) != size {
		return objectstore.Part{}, objectstore.ErrSizeMismatch
	}
	actual := sha256.Sum256(payload)
	if hex.EncodeToString(actual[:]) != digest {
		return objectstore.Part{}, objectstore.ErrDigestMismatch
	}
	store.uploads[key+"\x00"+uploadID].Write(payload)
	return objectstore.Part{PartNumber: 1, Size: size, SHA256: digest, ETag: "part-1"}, nil
}

func (store *memoryPublicationStore) CompleteMultipart(_ context.Context, key, uploadID string, _ []objectstore.Part) error {
	store.objects[key] = append([]byte(nil), store.uploads[key+"\x00"+uploadID].Bytes()...)
	return nil
}

func (store *memoryPublicationStore) AbortMultipart(_ context.Context, key, uploadID string) error {
	delete(store.uploads, key+"\x00"+uploadID)
	return nil
}

func (store *memoryPublicationStore) Open(_ context.Context, key string, _, _ int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	payload, exists := store.objects[key]
	if !exists {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(payload)), objectstore.ObjectInfo{Key: key, Size: int64(len(payload)), ContentType: "application/json"}, nil
}

func (store *memoryPublicationStore) Stat(_ context.Context, key string) (objectstore.ObjectInfo, error) {
	payload, exists := store.objects[key]
	if !exists {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return objectstore.ObjectInfo{Key: key, Size: int64(len(payload)), ContentType: "application/json"}, nil
}

func (store *memoryPublicationStore) Promote(_ context.Context, source, destination string) (objectstore.ObjectInfo, error) {
	if store.failDestination != "" && strings.HasSuffix(destination, store.failDestination) {
		return objectstore.ObjectInfo{}, errPublicationStoreFailure
	}
	if _, exists := store.objects[destination]; exists {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectAlreadyExists
	}
	payload := append([]byte(nil), store.objects[source]...)
	if store.corruptDestination != "" && strings.HasSuffix(destination, store.corruptDestination) {
		payload = append(payload, 'x')
	}
	store.objects[destination] = payload
	delete(store.objects, source)
	return objectstore.ObjectInfo{Key: destination, Size: int64(len(payload)), ContentType: "application/json"}, nil
}

func (store *memoryPublicationStore) Delete(_ context.Context, key string) error {
	delete(store.objects, key)
	return nil
}

var _ objectstore.Store = (*memoryPublicationStore)(nil)
