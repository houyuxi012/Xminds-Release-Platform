package logcenter

import (
	"bytes"
	"context"
	"io"
	"testing"

	"xminds-release-platform/internal/platform/objectstore"
)

type exportObjectStoreFake struct {
	objects map[string][]byte
}

func (s *exportObjectStoreFake) BeginMultipart(context.Context, string, string) (string, error) {
	return "upload-1", nil
}
func (s *exportObjectStoreFake) PutPart(_ context.Context, key, _ string, _ int, body io.Reader, size int64, _ string) (objectstore.Part, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return objectstore.Part{}, err
	}
	if int64(len(data)) != size {
		return objectstore.Part{}, objectstore.ErrSizeMismatch
	}
	s.objects[key] = data
	return objectstore.Part{PartNumber: 1, Size: size, ETag: "etag"}, nil
}
func (s *exportObjectStoreFake) CompleteMultipart(context.Context, string, string, []objectstore.Part) error {
	return nil
}
func (s *exportObjectStoreFake) AbortMultipart(context.Context, string, string) error { return nil }
func (s *exportObjectStoreFake) Open(_ context.Context, key string, _, _ int64) (io.ReadCloser, objectstore.ObjectInfo, error) {
	data, ok := s.objects[key]
	if !ok {
		return nil, objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), objectstore.ObjectInfo{Key: key, Size: int64(len(data))}, nil
}
func (s *exportObjectStoreFake) Stat(_ context.Context, key string) (objectstore.ObjectInfo, error) {
	data, ok := s.objects[key]
	if !ok {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	return objectstore.ObjectInfo{Key: key, Size: int64(len(data))}, nil
}
func (s *exportObjectStoreFake) Promote(_ context.Context, sourceKey, destinationKey string) (objectstore.ObjectInfo, error) {
	if _, exists := s.objects[destinationKey]; exists {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectAlreadyExists
	}
	data, ok := s.objects[sourceKey]
	if !ok {
		return objectstore.ObjectInfo{}, objectstore.ErrObjectNotFound
	}
	s.objects[destinationKey] = append([]byte(nil), data...)
	delete(s.objects, sourceKey)
	return objectstore.ObjectInfo{Key: destinationKey, Size: int64(len(data))}, nil
}
func (s *exportObjectStoreFake) Delete(_ context.Context, key string) error {
	if _, ok := s.objects[key]; !ok {
		return objectstore.ErrObjectNotFound
	}
	delete(s.objects, key)
	return nil
}

func TestPutExportObjectPromotesVerifiedContent(t *testing.T) {
	store := &exportObjectStoreFake{objects: make(map[string][]byte)}
	data := []byte("{\"event_id\":\"x\"}\n")
	key := "log-exports/export-1/archive.ndjson"
	if err := putExportObject(context.Background(), store, key, data, "application/x-ndjson"); err != nil {
		t.Fatalf("putExportObject() error = %v", err)
	}
	if got := string(store.objects[key]); got != string(data) {
		t.Fatalf("promoted object = %q, want %q", got, data)
	}
	for objectKey := range store.objects {
		if bytes.Contains([]byte(objectKey), []byte(".staging")) {
			t.Fatalf("staging object was retained: %s", objectKey)
		}
	}
}

var _ objectstore.Store = (*exportObjectStoreFake)(nil)
