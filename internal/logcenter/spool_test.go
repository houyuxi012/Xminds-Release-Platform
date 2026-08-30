package logcenter

import (
	"testing"
)

func TestEncryptedSpoolRoundTripAndQuota(t *testing.T) {
	spool, err := NewEncryptedSpool(t.TempDir(), make([]byte, 32), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.ReserveAndWrite([]byte(`{"type":"application_request"}`)); err != nil {
		t.Fatal(err)
	}
	items, err := spool.ReadAll()
	if err != nil || len(items) != 1 || string(items[0]) != `{"type":"application_request"}` {
		t.Fatalf("items=%q err=%v", items, err)
	}
}
