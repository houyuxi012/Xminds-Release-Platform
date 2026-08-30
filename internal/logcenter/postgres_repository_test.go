package logcenter

import (
	"context"
	"testing"
	"time"
)

func TestPostgresRepositoryRejectsNilPool(t *testing.T) {
	repository := NewPostgresRepository(nil)
	err := repository.ClaimEventIdentity(context.Background(), nil, "event", "operation", "2026-08", "dedupe", []byte{1}, time.Now())
	if err != ErrRepositoryUnavailable {
		t.Fatalf("error = %v, want ErrRepositoryUnavailable", err)
	}
}
