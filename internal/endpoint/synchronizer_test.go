package endpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
)

func TestSynchronizerCopiesFiveRolesAndReferencedArtifactWithReadbackVerification(t *testing.T) {
	t.Parallel()

	endpointID := uuid.New()
	repository := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{endpointID: validEndpoint(endpointID, StatusPending)}}
	current, sourceObjects, artifactRecord := synchronizationFixture(t)
	auditor := &recordingEndpointAuditor{}
	service, err := NewService(ServiceConfig{
		Repository: repository, Transactor: endpointPassThroughTransactor{}, Catalogs: staticSyncCatalog{record: current},
		Probe: fixedEndpointProbe{}, Auditor: auditor, DefaultChannel: "stable", Clock: func() time.Time { return time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := &memoryDestination{objects: map[string][]byte{}}
	synchronizer, err := NewSynchronizer(SynchronizerConfig{
		Endpoints: service, Catalogs: staticSyncCatalog{record: current}, Artifacts: staticSyncArtifact{record: artifactRecord},
		Source: &memorySyncSource{objects: sourceObjects}, Destination: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(SyncJobPayload{EndpointID: endpointID, ProductID: "ngep", Channel: "stable"})
	job, err := jobs.New(JobKindEndpointSync, endpointID, payload, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := synchronizer.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	for _, role := range []catalog.Role{catalog.RoleRoot, catalog.RoleTargets, catalog.RoleSnapshot, catalog.RoleTimestamp, catalog.RoleRevocation} {
		path := "/releases/v1/products/ngep/channels/stable/metadata/" + string(role) + ".json"
		if len(destination.objects[path]) == 0 {
			t.Fatalf("missing synchronized role %s", role)
		}
	}
	artifactPath := "/releases/v1/products/ngep/artifacts/" + artifactRecord.SHA256
	if string(destination.objects[artifactPath]) != "verified-artifact" {
		t.Fatalf("artifact = %q", destination.objects[artifactPath])
	}
	if record := repository.records[endpointID]; record.Status != StatusActive || record.FailureCount != 0 || record.LastTimestampDigest == "" {
		t.Fatalf("endpoint after synchronization = %+v", record)
	}
}

func TestSynchronizerReadbackDigestMismatchCountsFailure(t *testing.T) {
	t.Parallel()

	endpointID := uuid.New()
	repository := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{endpointID: validEndpoint(endpointID, StatusActive)}}
	current, sourceObjects, artifactRecord := synchronizationFixture(t)
	service, err := NewService(ServiceConfig{
		Repository: repository, Transactor: endpointPassThroughTransactor{}, Catalogs: staticSyncCatalog{record: current},
		Probe: fixedEndpointProbe{}, Auditor: &recordingEndpointAuditor{}, DefaultChannel: "stable", Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := &memoryDestination{objects: map[string][]byte{}, corruptReadback: true}
	synchronizer, err := NewSynchronizer(SynchronizerConfig{
		Endpoints: service, Catalogs: staticSyncCatalog{record: current}, Artifacts: staticSyncArtifact{record: artifactRecord},
		Source: &memorySyncSource{objects: sourceObjects}, Destination: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(SyncJobPayload{EndpointID: endpointID, ProductID: "ngep", Channel: "stable"})
	job, _ := jobs.New(JobKindEndpointSync, endpointID, payload, time.Now())
	if err := synchronizer.Handle(context.Background(), job); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	if repository.records[endpointID].FailureCount != 1 {
		t.Fatalf("failure count = %d", repository.records[endpointID].FailureCount)
	}
}

func synchronizationFixture(t *testing.T) (catalog.VersionRecord, map[string][]byte, artifact.Artifact) {
	t.Helper()
	artifactBytes := []byte("verified-artifact")
	artifactHash := sha256.Sum256(artifactBytes)
	artifactDigest := hex.EncodeToString(artifactHash[:])
	targetsBytes := []byte(`{"signatures":[],"signed":{"_type":"targets","targets":{"release-1":{"hashes":{"sha256":"` + artifactDigest + `"}}}}}`)
	roleBytes := map[catalog.Role][]byte{
		catalog.RoleRoot: []byte(`{"signed":{"_type":"root"}}`), catalog.RoleTargets: targetsBytes,
		catalog.RoleSnapshot: []byte(`{"signed":{"_type":"snapshot"}}`), catalog.RoleTimestamp: []byte(`{"signed":{"_type":"timestamp"}}`),
		catalog.RoleRevocation: []byte(`{"signed":{"_type":"revocation"}}`),
	}
	record := catalog.VersionRecord{ID: uuid.New(), ProductID: "ngep", Channel: "stable", Roles: map[catalog.Role]catalog.RoleDocument{}}
	objects := make(map[string][]byte, 6)
	for role, value := range roleBytes {
		digest := sha256.Sum256(value)
		key := "catalogs/ngep/stable/version/" + string(role) + ".json"
		record.Roles[role] = catalog.RoleDocument{Role: role, EnvelopeSHA256: hex.EncodeToString(digest[:]), ObjectKey: key, Envelope: append([]byte(nil), value...)}
		objects[key] = value
	}
	artifactRecord := artifact.Artifact{ID: uuid.New(), ProductID: "ngep", SHA256: artifactDigest, Size: int64(len(artifactBytes)), ContentType: "application/octet-stream", ObjectKey: artifact.ArtifactObjectKey(artifactDigest)}
	objects[artifactRecord.ObjectKey] = artifactBytes
	return record, objects, artifactRecord
}

type staticSyncCatalog struct{ record catalog.VersionRecord }

func (reader staticSyncCatalog) Current(_ context.Context, productID, channel string) (catalog.VersionRecord, error) {
	if reader.record.ProductID != productID || reader.record.Channel != channel {
		return catalog.VersionRecord{}, catalog.ErrCurrentCatalogNotFound
	}
	return reader.record, nil
}

type staticSyncArtifact struct{ record artifact.Artifact }

func (reader staticSyncArtifact) GetByDigest(_ context.Context, productID, digest string) (artifact.Artifact, error) {
	if reader.record.ProductID != productID || reader.record.SHA256 != digest {
		return artifact.Artifact{}, artifact.ErrArtifactNotFound
	}
	return reader.record, nil
}

type memorySyncSource struct{ objects map[string][]byte }

func (source *memorySyncSource) Open(_ context.Context, key string, offset, length int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	value, exists := source.objects[key]
	if !exists {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(value)), objectstore.ObjectInfo{Key: key, Size: int64(len(value))}, nil
}

type memoryDestination struct {
	objects         map[string][]byte
	corruptReadback bool
}

func (destination *memoryDestination) Put(_ context.Context, _ Endpoint, path string, body io.Reader, size int64, _ string, _ string) error {
	value, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil || int64(len(value)) != size {
		return objectstore.ErrSizeMismatch
	}
	destination.objects[path] = value
	return nil
}

func (destination *memoryDestination) Open(_ context.Context, _ Endpoint, path string) (io.ReadCloser, int64, error) {
	value, exists := destination.objects[path]
	if !exists {
		return nil, 0, objectstore.ErrObjectNotFound
	}
	value = append([]byte(nil), value...)
	if destination.corruptReadback {
		value[0] ^= 0xff
	}
	return io.NopCloser(bytes.NewReader(value)), int64(len(value)), nil
}
