package logcenter

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestQueryValidationAndUUID(t *testing.T) {
	if validateLogFilters(LogQueryFilters{Limit: 201}) == nil {
		t.Fatal("limit accepted")
	}
	if validateLogFilters(LogQueryFilters{From: time.Now(), To: time.Now().Add(32 * 24 * time.Hour)}) == nil {
		t.Fatal("window accepted")
	}
	id := uuid.New()
	if got, ok := queryUUIDString(id); !ok || got != id.String() {
		t.Fatal(got, ok)
	}
	if got, ok := queryUUIDString(pgtype.UUID{Bytes: id, Valid: true}); !ok || got != id.String() {
		t.Fatal(got, ok)
	}
	if _, ok := queryUUIDString(struct{}{}); ok {
		t.Fatal("unknown uuid accepted")
	}
}
