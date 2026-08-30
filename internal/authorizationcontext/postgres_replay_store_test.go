package authorizationcontext

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgresReplayStoreRequiresPool(t *testing.T) {
	store := NewPostgresReplayStore(nil)
	claimed, err := store.Claim(context.Background(), "issuer", "context", time.Now().Add(time.Minute), time.Now())
	if !errors.Is(err, ErrReplayStoreUnavailable) || claimed {
		t.Fatalf("Claim() = (%v, %v), want (false, ErrReplayStoreUnavailable)", claimed, err)
	}
}
