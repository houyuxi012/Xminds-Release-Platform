package logcenter

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCanonicalNDJSONAcceptsPostgresUUIDValues(t *testing.T) {
	eventID := uuid.New()
	value := pgtype.UUID{Bytes: eventID, Valid: true}
	data, err := CanonicalNDJSON([]map[string]any{{
		"event_id":    eventID,
		"occurred_at": time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
		"log_type":    string(ScopeTableOperations),
	}, {
		"event_id":    value,
		"occurred_at": time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC),
		"log_type":    string(ScopeTableAuthentications),
	}})
	if err != nil {
		t.Fatalf("CanonicalNDJSON() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("CanonicalNDJSON() returned empty data")
	}
}
