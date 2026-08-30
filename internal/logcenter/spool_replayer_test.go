package logcenter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSpoolReplayersClaimProcessingFileOnce(t *testing.T) {
	spool, err := NewEncryptedSpool(t.TempDir(), []byte("01234567890123456789012345678901"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.ReserveAndWrite([]byte("one")); err != nil {
		t.Fatal(err)
	}
	var consumed atomic.Int32
	consume := func(context.Context, []byte) error { consumed.Add(1); return nil }
	a := &SpoolReplayer{Spool: spool, Consume: consume}
	b := &SpoolReplayer{Spool: spool, Consume: consume}
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for _, r := range []*SpoolReplayer{a, b} {
		go func(r *SpoolReplayer) { defer wg.Done(); errs <- r.RunOnce(context.Background()) }(r)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("consumed=%d, want 1", got)
	}
}

func TestSpoolReplayerRejectsMissingConsumer(t *testing.T) {
	replayer := &SpoolReplayer{}
	if err := replayer.RunOnce(context.Background()); err != ErrRepositoryUnavailable {
		t.Fatalf("error=%v", err)
	}
}
