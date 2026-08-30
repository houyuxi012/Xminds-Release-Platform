package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/product"
)

const abcSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestCompleteRejectsDigestMismatchAndNeverPublishesObject(t *testing.T) {
	t.Parallel()

	service, store := newTestArtifactService()
	principal := publisherPrincipal("ngep")
	upload, err := service.BeginUpload(context.Background(), principal, BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar", ContentType: "application/x-tar",
		Size: 3, SHA256: strings.Repeat("0", 64),
	}, testRequestContext())
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	if _, err := service.PutPart(context.Background(), principal, "ngep", upload.ID, PutPart{
		PartNumber: 1, Size: 3, SHA256: abcSHA256,
	}, bytes.NewBufferString("abc"), testRequestContext()); err != nil {
		t.Fatalf("PutPart() error = %v", err)
	}

	_, err = service.Complete(context.Background(), principal, "ngep", upload.ID, testRequestContext())
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Complete() error = %v, want %v", err, ErrDigestMismatch)
	}
	if store.Has(ArtifactObjectKey(abcSHA256)) {
		t.Fatalf("mismatched object was published at %q", ArtifactObjectKey(abcSHA256))
	}
	storedUpload, getErr := service.repository.GetUpload(context.Background(), upload.ID)
	if getErr != nil {
		t.Fatalf("GetUpload() error = %v", getErr)
	}
	if storedUpload.Status != UploadStatusQuarantined {
		t.Fatalf("upload status = %q, want %q", storedUpload.Status, UploadStatusQuarantined)
	}
	if len(service.jobs.(*recordingArtifactJobs).jobs) != 1 {
		t.Fatalf("cleanup jobs = %d, want 1", len(service.jobs.(*recordingArtifactJobs).jobs))
	}
}

func TestBeginUploadAcceptsOrdinaryFilenameCharactersAndRejectsNUL(t *testing.T) {
	t.Parallel()

	service, _ := newTestArtifactService()
	principal := publisherPrincipal("ngep")
	valid := BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "xminds-10.x.tar",
		ContentType: "application/x-tar", Size: 3, SHA256: abcSHA256,
	}
	if _, err := service.BeginUpload(context.Background(), principal, valid, testRequestContext()); err != nil {
		t.Fatalf("BeginUpload(valid filename) error = %v", err)
	}
	valid.Filename = "xminds\x00.tar"
	if _, err := service.BeginUpload(context.Background(), principal, valid, testRequestContext()); !errors.Is(err, ErrFilenameInvalid) {
		t.Fatalf("BeginUpload(NUL filename) error = %v, want %v", err, ErrFilenameInvalid)
	}
}

func TestRetrySamePartReplacesBytesBeforeVerifiedPublication(t *testing.T) {
	t.Parallel()

	service, store := newTestArtifactService()
	principal := publisherPrincipal("ngep")
	upload, err := service.BeginUpload(context.Background(), principal, BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar", ContentType: "application/x-tar",
		Size: 3, SHA256: abcSHA256,
	}, testRequestContext())
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	wrongDigest := sha256.Sum256([]byte("abd"))
	if _, err := service.PutPart(context.Background(), principal, "ngep", upload.ID, PutPart{
		PartNumber: 1, Size: 3, SHA256: hex.EncodeToString(wrongDigest[:]),
	}, bytes.NewBufferString("abd"), testRequestContext()); err != nil {
		t.Fatalf("first PutPart() error = %v", err)
	}
	if _, err := service.PutPart(context.Background(), principal, "ngep", upload.ID, PutPart{
		PartNumber: 1, Size: 3, SHA256: abcSHA256,
	}, bytes.NewBufferString("abc"), testRequestContext()); err != nil {
		t.Fatalf("retry PutPart() error = %v", err)
	}

	artifact, err := service.Complete(context.Background(), principal, "ngep", upload.ID, testRequestContext())
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if artifact.SHA256 != abcSHA256 || artifact.ObjectKey != ArtifactObjectKey(abcSHA256) {
		t.Fatalf("artifact = %#v", artifact)
	}
	if !store.Has(ArtifactObjectKey(abcSHA256)) {
		t.Fatal("verified object was not published")
	}
}

func TestPutPartRejectsCrossProductAccess(t *testing.T) {
	t.Parallel()

	service, _ := newTestArtifactService()
	upload, err := service.BeginUpload(context.Background(), publisherPrincipal("ngep"), BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar", ContentType: "application/x-tar",
		Size: 3, SHA256: abcSHA256,
	}, testRequestContext())
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	_, err = service.PutPart(context.Background(), publisherPrincipal("other-product"), "ngep", upload.ID, PutPart{
		PartNumber: 1, Size: 3, SHA256: abcSHA256,
	}, bytes.NewBufferString("abc"), testRequestContext())
	if !errors.Is(err, identity.ErrProductScopeDenied) {
		t.Fatalf("PutPart() error = %v, want %v", err, identity.ErrProductScopeDenied)
	}
}

func TestPutPartRejectsOversizedPartBeforeReadingBody(t *testing.T) {
	t.Parallel()

	service, _ := newTestArtifactService()
	principal := publisherPrincipal("ngep")
	upload, err := service.BeginUpload(context.Background(), principal, BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar", ContentType: "application/x-tar",
		Size: MaximumObjectSize, SHA256: abcSHA256,
	}, testRequestContext())
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	body := &panicReader{}
	_, err = service.PutPart(context.Background(), principal, "ngep", upload.ID, PutPart{
		PartNumber: 1, Size: MaximumPartSize + 1, SHA256: abcSHA256,
	}, body, testRequestContext())
	if !errors.Is(err, ErrPartSizeInvalid) {
		t.Fatalf("PutPart() error = %v, want %v", err, ErrPartSizeInvalid)
	}
}

func TestPutPartRejectsExpiredSession(t *testing.T) {
	t.Parallel()

	service, _ := newTestArtifactService()
	baseTime := time.Date(2026, time.August, 14, 8, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return baseTime }
	principal := publisherPrincipal("ngep")
	upload, err := service.BeginUpload(context.Background(), principal, BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar", ContentType: "application/x-tar",
		Size: 3, SHA256: abcSHA256,
	}, testRequestContext())
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	service.now = func() time.Time { return baseTime.Add(UploadLifetime + time.Second) }
	expiryRequest := RequestContext{RequestID: "019c1547-e880-7831-949c-7302a34724ff", SourceIP: "192.0.2.31"}
	_, err = service.PutPart(context.Background(), principal, "ngep", upload.ID, PutPart{
		PartNumber: 1, Size: 3, SHA256: abcSHA256,
	}, bytes.NewBufferString("abc"), expiryRequest)
	if !errors.Is(err, ErrUploadExpired) {
		t.Fatalf("PutPart() error = %v, want %v", err, ErrUploadExpired)
	}
	auditor := service.auditor.(*recordingArtifactAuditor)
	if len(auditor.commands) < 2 || auditor.commands[len(auditor.commands)-1].RequestID != expiryRequest.RequestID {
		t.Fatalf("expiry audit request ID = %#v, want %q", auditor.commands, expiryRequest.RequestID)
	}
}

func TestPutPartRejectsProductPathMismatchForMultiProductPublisher(t *testing.T) {
	t.Parallel()

	service, _ := newTestArtifactService()
	principal := publisherPrincipal("ngep")
	upload, err := service.BeginUpload(context.Background(), principal, BeginUpload{
		ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar", ContentType: "application/x-tar",
		Size: 3, SHA256: abcSHA256,
	}, testRequestContext())
	if err != nil {
		t.Fatalf("BeginUpload() error = %v", err)
	}
	principal.ProductIDs = []string{"ngep", "other-product"}
	_, err = service.PutPart(context.Background(), principal, "other-product", upload.ID, PutPart{
		PartNumber: 1, Size: 3, SHA256: abcSHA256,
	}, bytes.NewBufferString("abc"), testRequestContext())
	if !errors.Is(err, ErrUploadProductMismatch) {
		t.Fatalf("PutPart() error = %v, want %v", err, ErrUploadProductMismatch)
	}
}

type panicReader struct{}

func (*panicReader) Read([]byte) (int, error) {
	panic("body must not be read")
}

func newTestArtifactService() (*Service, *memoryObjectStore) {
	repository := newMemoryArtifactRepository()
	store := newMemoryObjectStore()
	products := &memoryProductReader{products: map[string]product.Product{
		"ngep": {ID: "ngep", Status: product.ProductStatusActive, ArtifactTypes: []string{"desktop", "container"}},
	}}
	service := NewService(
		repository,
		passThroughArtifactTransactor{},
		products,
		store,
		&recordingArtifactAuditor{},
		&recordingArtifactJobs{},
	)
	return service, store
}

func publisherPrincipal(productID string) identity.Principal {
	return identity.Principal{
		Subject: "publisher-1", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RolePublisher}, ProductIDs: []string{productID},
	}
}

func testRequestContext() RequestContext {
	return RequestContext{RequestID: "019c1547-e880-7831-949c-7302a34724d0", SourceIP: "192.0.2.30"}
}

type passThroughArtifactTransactor struct{}

func (passThroughArtifactTransactor) WithinTransaction(ctx context.Context, fn func(pgx.Tx) error) error {
	return fn(nil)
}

type memoryProductReader struct {
	products map[string]product.Product
}

func (reader *memoryProductReader) Get(_ context.Context, productID string) (product.Product, error) {
	item, ok := reader.products[productID]
	if !ok {
		return product.Product{}, product.ErrProductNotFound
	}
	return item, nil
}

type recordingArtifactAuditor struct {
	commands []audit.AppendCommand
}

func (recorder *recordingArtifactAuditor) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

type recordingArtifactJobs struct {
	jobs []jobs.Job
}

func (recorder *recordingArtifactJobs) Enqueue(_ context.Context, _ pgx.Tx, job jobs.Job) error {
	recorder.jobs = append(recorder.jobs, job)
	return nil
}

type memoryArtifactRepository struct {
	uploads   map[uuid.UUID]Upload
	parts     map[uuid.UUID]map[int]UploadPart
	artifacts map[uuid.UUID]Artifact
	byDigest  map[string]uuid.UUID
}

func newMemoryArtifactRepository() *memoryArtifactRepository {
	return &memoryArtifactRepository{
		uploads: map[uuid.UUID]Upload{}, parts: map[uuid.UUID]map[int]UploadPart{},
		artifacts: map[uuid.UUID]Artifact{}, byDigest: map[string]uuid.UUID{},
	}
}

func (repository *memoryArtifactRepository) CreateUpload(_ context.Context, _ pgx.Tx, upload Upload) error {
	repository.uploads[upload.ID] = upload
	repository.parts[upload.ID] = map[int]UploadPart{}
	return nil
}

func (repository *memoryArtifactRepository) GetUpload(_ context.Context, id uuid.UUID) (Upload, error) {
	upload, ok := repository.uploads[id]
	if !ok {
		return Upload{}, ErrUploadNotFound
	}
	return upload, nil
}

func (repository *memoryArtifactRepository) SavePart(_ context.Context, part UploadPart) error {
	repository.parts[part.UploadID][part.PartNumber] = part
	return nil
}

func (repository *memoryArtifactRepository) ListParts(_ context.Context, uploadID uuid.UUID) ([]UploadPart, error) {
	items := make([]UploadPart, 0, len(repository.parts[uploadID]))
	for _, part := range repository.parts[uploadID] {
		items = append(items, part)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].PartNumber < items[j].PartNumber })
	return items, nil
}

func (repository *memoryArtifactRepository) Quarantine(_ context.Context, _ pgx.Tx, uploadID uuid.UUID, at time.Time) error {
	upload := repository.uploads[uploadID]
	upload.Status = UploadStatusQuarantined
	upload.UpdatedAt = at
	repository.uploads[uploadID] = upload
	return nil
}

func (repository *memoryArtifactRepository) Expire(_ context.Context, _ pgx.Tx, uploadID uuid.UUID, at time.Time) error {
	upload := repository.uploads[uploadID]
	upload.Status = UploadStatusExpired
	upload.UpdatedAt = at
	repository.uploads[uploadID] = upload
	return nil
}

func (repository *memoryArtifactRepository) Complete(_ context.Context, _ pgx.Tx, uploadID uuid.UUID, candidate Artifact) (Artifact, error) {
	if existingID, ok := repository.byDigest[candidate.SHA256]; ok {
		existing := repository.artifacts[existingID]
		existing.ProductID = candidate.ProductID
		existing.ArtifactType = candidate.ArtifactType
		existing.Filename = candidate.Filename
		candidate = existing
	} else {
		repository.artifacts[candidate.ID] = candidate
		repository.byDigest[candidate.SHA256] = candidate.ID
	}
	upload := repository.uploads[uploadID]
	upload.Status = UploadStatusCompleted
	upload.ArtifactID = candidate.ID
	upload.UpdatedAt = candidate.CreatedAt
	repository.uploads[uploadID] = upload
	return candidate, nil
}

func (repository *memoryArtifactRepository) GetArtifact(_ context.Context, productID string, artifactID uuid.UUID) (Artifact, error) {
	item, ok := repository.artifacts[artifactID]
	if !ok {
		return Artifact{}, ErrArtifactNotFound
	}
	item.ProductID = productID
	return item, nil
}

type memoryMultipart struct {
	key   string
	parts map[int][]byte
}

type memoryObjectStore struct {
	multiparts map[string]*memoryMultipart
	objects    map[string][]byte
}

func newMemoryObjectStore() *memoryObjectStore {
	return &memoryObjectStore{multiparts: map[string]*memoryMultipart{}, objects: map[string][]byte{}}
}

func (store *memoryObjectStore) BeginMultipart(_ context.Context, key string, _ string) (string, error) {
	id := uuid.NewString()
	store.multiparts[id] = &memoryMultipart{key: key, parts: map[int][]byte{}}
	return id, nil
}

func (store *memoryObjectStore) PutPart(_ context.Context, key string, uploadID string, partNumber int, body io.Reader, size int64, digest string) (objectstore.Part, error) {
	multipart := store.multiparts[uploadID]
	if multipart == nil || multipart.key != key {
		return objectstore.Part{}, objectstore.ErrUploadNotFound
	}
	payload, err := io.ReadAll(io.LimitReader(body, size+1))
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
	multipart.parts[partNumber] = payload
	return objectstore.Part{PartNumber: partNumber, Size: size, SHA256: digest, ETag: digest[:32]}, nil
}

func (store *memoryObjectStore) CompleteMultipart(_ context.Context, key string, uploadID string, parts []objectstore.Part) error {
	multipart := store.multiparts[uploadID]
	if multipart == nil || multipart.key != key {
		return objectstore.ErrUploadNotFound
	}
	var payload []byte
	for _, part := range parts {
		payload = append(payload, multipart.parts[part.PartNumber]...)
	}
	store.objects[key] = payload
	delete(store.multiparts, uploadID)
	return nil
}

func (store *memoryObjectStore) AbortMultipart(_ context.Context, _ string, uploadID string) error {
	delete(store.multiparts, uploadID)
	return nil
}

func (store *memoryObjectStore) Open(_ context.Context, key string, offset int64, length int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	payload, ok := store.objects[key]
	if !ok {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	end := int64(len(payload))
	if length >= 0 && offset+length < end {
		end = offset + length
	}
	if offset < 0 || offset > int64(len(payload)) || end < offset {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrRangeInvalid
	}
	return io.NopCloser(bytes.NewReader(payload[offset:end])), objectstore.ObjectInfo{Key: key, Size: int64(len(payload))}, nil
}

func (store *memoryObjectStore) Stat(_ context.Context, key string) (objectstore.ObjectInfo, error) {
	payload, ok := store.objects[key]
	if !ok {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return objectstore.ObjectInfo{Key: key, Size: int64(len(payload))}, nil
}

func (store *memoryObjectStore) Promote(_ context.Context, sourceKey string, destinationKey string) (objectstore.ObjectInfo, error) {
	payload, ok := store.objects[sourceKey]
	if !ok {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	if _, exists := store.objects[destinationKey]; exists {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectAlreadyExists
	}
	store.objects[destinationKey] = append([]byte(nil), payload...)
	delete(store.objects, sourceKey)
	return objectstore.ObjectInfo{Key: destinationKey, Size: int64(len(payload))}, nil
}

func (store *memoryObjectStore) Delete(_ context.Context, key string) error {
	delete(store.objects, key)
	return nil
}

func (store *memoryObjectStore) Has(key string) bool {
	_, ok := store.objects[key]
	return ok
}
