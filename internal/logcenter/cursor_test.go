package logcenter

import (
	"testing"
	"time"
)

func TestCursorRoundTripAndBinding(t *testing.T) {
	c, e := NewCursorCodec([]byte("01234567890123456789012345678901"), 5*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	cur := LogCursor{Route: "app", FilterDigest: FilterDigest("f"), Limit: 50, LastEventID: "550e8400-e29b-41d4-a716-446655440000", LastOccurredAt: &now}
	tok, e := c.Encode(cur)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Decode(tok, "app", FilterDigest("f"), cur.ScopeDigest, 50); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Decode(tok, "other", FilterDigest("f"), cur.ScopeDigest, 50); e == nil {
		t.Fatal("binding accepted")
	}
}
