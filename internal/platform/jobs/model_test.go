package jobs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewCreatesValidVersionSevenIdentifier(t *testing.T) {
	t.Parallel()

	job, err := New("release.catalog.publish", uuid.New(), json.RawMessage(`{"channel":"stable"}`), time.Now())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if job.ID.Version() != 7 {
		t.Fatalf("job ID version = %d, want 7", job.ID.Version())
	}
	if job.Status != StatusPending {
		t.Fatalf("job status = %q, want %q", job.Status, StatusPending)
	}
}

func TestNewRejectsInvalidPayload(t *testing.T) {
	t.Parallel()

	_, err := New("release.catalog.publish", uuid.New(), json.RawMessage(`{"channel"`), time.Now())
	if err == nil {
		t.Fatal("New() error = nil, want invalid payload error")
	}
}
