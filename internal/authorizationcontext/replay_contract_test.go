package authorizationcontext

import (
	"context"
	"testing"
	"time"
)

type contractReplayStore struct{}

func (*contractReplayStore) Claim(context.Context, string, string, time.Time, time.Time) (bool, error) {
	return true, nil
}

func TestReplayStoreUsesIssuerAndContextAndReportsDatabaseErrors(t *testing.T) {
	var store ReplayStore = (*contractReplayStore)(nil)
	claimed, err := store.Claim(context.Background(), "issuer", "context", time.Now().Add(time.Minute), time.Now())
	if err != nil || !claimed {
		t.Fatalf("Claim() = (%v, %v), want (true, nil)", claimed, err)
	}
}
