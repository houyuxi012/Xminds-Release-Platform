package objectstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMinIOStoreRejectsHTTPRedirects(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+request.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	store, err := NewMinIOStore(MinIOConfig{
		EndpointURL: source.URL,
		Bucket:      "artifact-test",
		AccessKey:   "test-access-key",
		SecretKey:   "test-secret-key",
	})
	if err != nil {
		t.Fatalf("NewMinIOStore() error = %v", err)
	}
	_, err = store.Stat(context.Background(), "objects/test")
	if !errors.Is(err, ErrRedirectRejected) {
		t.Fatalf("Stat() error = %v, want %v", err, ErrRedirectRejected)
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("redirect destination requests = %d, want 0", redirectedRequests.Load())
	}
}

func TestMinIOStoreDeleteRejectsVerifiedArtifactKey(t *testing.T) {
	t.Parallel()

	store := &MinIOStore{}
	err := store.Delete(context.Background(), "artifacts/sha256/ba/"+strings.Repeat("a", 64))
	if !errors.Is(err, ErrImmutableObject) {
		t.Fatalf("Delete(verified artifact) error = %v, want %v", err, ErrImmutableObject)
	}
}

func TestMinIOStoreRequiresRetentionForObjectLocking(t *testing.T) {
	store, err := NewMinIOStore(MinIOConfig{
		EndpointURL: "https://minio.example.invalid", Bucket: "archive-test",
		AccessKey: "access", SecretKey: "secret", ObjectLocking: true,
	})
	if !errors.Is(err, ErrObjectLockInvalid) || store != nil {
		t.Fatalf("NewMinIOStore() store=%v err=%v, want object lock validation failure", store, err)
	}
}
