package catalog

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/platform/objectstore"
)

const (
	timestampDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	artifactDigest  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestCompatibilityPathServesConfiguredDefaultProductOnly(t *testing.T) {
	t.Parallel()

	handler := newPublicCatalogTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/metadata/timestamp.json", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"signed":{"_type":"timestamp"}}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "public, max-age=30, must-revalidate" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	if recorder.Header().Get("ETag") != `"`+timestampDigest+`"` || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %#v", recorder.Header())
	}
}

func TestPublicCatalogHandlerRejectsUnknownRoleBeforeReadingCatalog(t *testing.T) {
	t.Parallel()

	handler, err := NewPublicHTTPHandler(PublicHTTPConfig{
		DefaultProductID: "ngep", DefaultChannel: "stable",
		Catalogs: panicCatalogReader{}, Artifacts: panicArtifactReader{}, Store: panicPublicStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metadata/delegation.json", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestProductCatalogPathDoesNotFallBackToDefaultProduct(t *testing.T) {
	t.Parallel()

	handler := newPublicCatalogTestHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/products/analytics/channels/stable/metadata/timestamp.json", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPublicCatalogHandlerReturnsNotModifiedForMatchingDigestETag(t *testing.T) {
	t.Parallel()

	handler := newPublicCatalogTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/metadata/timestamp.json", nil)
	request.Header.Set("If-None-Match", `"`+timestampDigest+`"`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestPublicArtifactHandlerServesSingleByteRange(t *testing.T) {
	t.Parallel()

	handler := newPublicCatalogTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/products/ngep/artifacts/"+artifactDigest, nil)
	request.Header.Set("Range", "bytes=3-6")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPartialContent || recorder.Body.String() != "3456" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Range") != "bytes 3-6/10" || recorder.Header().Get("Content-Length") != "4" || recorder.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatalf("range headers = %#v", recorder.Header())
	}
	if recorder.Header().Get("ETag") != `"`+artifactDigest+`"` || recorder.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("cache headers = %#v", recorder.Header())
	}
	if recorder.Header().Get("Content-Disposition") != "attachment" {
		t.Fatalf("Content-Disposition = %q", recorder.Header().Get("Content-Disposition"))
	}
}

func TestPublicArtifactHandlerRejectsMultipleRanges(t *testing.T) {
	t.Parallel()

	handler := newPublicCatalogTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/products/ngep/artifacts/"+artifactDigest, nil)
	request.Header.Set("Range", "bytes=0-1,4-5")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestedRangeNotSatisfiable || recorder.Header().Get("Content-Range") != "bytes */10" {
		t.Fatalf("response = %d headers=%#v", recorder.Code, recorder.Header())
	}
}

func newPublicCatalogTestHandler(t *testing.T) http.Handler {
	t.Helper()
	record := VersionRecord{
		ID: uuid.New(), ProductID: "ngep", Channel: "stable", Roles: map[Role]RoleDocument{
			RoleTimestamp: {Role: RoleTimestamp, EnvelopeSHA256: timestampDigest, ObjectKey: "catalogs/ngep/stable/current/timestamp.json"},
		},
	}
	store := &memoryPublicStore{objects: map[string][]byte{
		"catalogs/ngep/stable/current/timestamp.json": []byte(`{"signed":{"_type":"timestamp"}}`),
		"artifacts/sha256/bb/" + artifactDigest:       []byte("0123456789"),
	}}
	handler, err := NewPublicHTTPHandler(PublicHTTPConfig{
		DefaultProductID: "ngep", DefaultChannel: "stable",
		Catalogs: mapCatalogReader{records: map[string]VersionRecord{"ngep/stable": record}},
		Artifacts: mapArtifactReader{items: map[string]artifact.Artifact{"ngep/" + artifactDigest: {
			ID: uuid.New(), ProductID: "ngep", ContentType: "application/octet-stream", Size: 10,
			SHA256: artifactDigest, ObjectKey: "artifacts/sha256/bb/" + artifactDigest,
		}}},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

type mapCatalogReader struct{ records map[string]VersionRecord }

func (reader mapCatalogReader) Current(_ context.Context, productID, channel string) (VersionRecord, error) {
	record, exists := reader.records[productID+"/"+channel]
	if !exists {
		return VersionRecord{}, ErrCurrentCatalogNotFound
	}
	return record, nil
}

type mapArtifactReader struct{ items map[string]artifact.Artifact }

func (reader mapArtifactReader) GetByDigest(_ context.Context, productID, digest string) (artifact.Artifact, error) {
	item, exists := reader.items[productID+"/"+digest]
	if !exists {
		return artifact.Artifact{}, artifact.ErrArtifactNotFound
	}
	return item, nil
}

type memoryPublicStore struct{ objects map[string][]byte }

func (store *memoryPublicStore) Open(_ context.Context, key string, offset, length int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	value, exists := store.objects[key]
	if !exists {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	end := int64(len(value))
	if length >= 0 {
		end = offset + length
	}
	return io.NopCloser(bytes.NewReader(value[offset:end])), objectstore.ObjectInfo{Key: key, Size: int64(len(value))}, nil
}

func (store *memoryPublicStore) Stat(_ context.Context, key string) (objectstore.ObjectInfo, error) {
	value, exists := store.objects[key]
	if !exists {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return objectstore.ObjectInfo{Key: key, Size: int64(len(value)), LastModified: time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)}, nil
}

type panicCatalogReader struct{}

func (panicCatalogReader) Current(context.Context, string, string) (VersionRecord, error) {
	panic("catalog read before role validation")
}

type panicArtifactReader struct{}

func (panicArtifactReader) GetByDigest(context.Context, string, string) (artifact.Artifact, error) {
	panic("artifact read on metadata route")
}

type panicPublicStore struct{}

func (panicPublicStore) Open(context.Context, string, int64, int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	panic("object read before role validation")
}

func (panicPublicStore) Stat(context.Context, string) (objectstore.ObjectInfo, error) {
	panic("object stat before role validation")
}
