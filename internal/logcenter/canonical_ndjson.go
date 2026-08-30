package logcenter

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrInvalidExportRecord = errors.New("invalid export record")

func CanonicalNDJSON(records []map[string]any) ([]byte, error) {
	out := make([]map[string]any, len(records))
	copy(out, records)
	for _, record := range out {
		if _, err := canonicalRecordKeyFor(record); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, _ := canonicalRecordKeyFor(out[i])
		right, _ := canonicalRecordKeyFor(out[j])
		return left.less(right)
	})
	var b bytes.Buffer
	for _, r := range out {
		v, e := json.Marshal(r)
		if e != nil {
			return nil, e
		}
		b.Write(v)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

type canonicalRecordKey struct {
	occurredAt time.Time
	eventID    string
	logType    string
}

func (k canonicalRecordKey) less(other canonicalRecordKey) bool {
	if !k.occurredAt.Equal(other.occurredAt) {
		return k.occurredAt.Before(other.occurredAt)
	}
	if k.eventID != other.eventID {
		return k.eventID < other.eventID
	}
	return k.logType < other.logType
}

func canonicalRecordKeyFor(record map[string]any) (canonicalRecordKey, error) {
	if record == nil {
		return canonicalRecordKey{}, ErrInvalidExportRecord
	}
	logType, ok := record["log_type"].(string)
	if !ok || !validExportLogTypes([]ScopeTable{ScopeTable(logType)}) {
		return canonicalRecordKey{}, ErrInvalidExportRecord
	}
	eventID, ok := record["event_id"].(string)
	if !ok {
		if id, uuidOK := record["event_id"].(uuid.UUID); uuidOK {
			eventID = id.String()
		} else if id, pgxOK := record["event_id"].(pgtype.UUID); pgxOK && id.Valid {
			parsed, parseErr := uuid.FromBytes(id.Bytes[:])
			if parseErr != nil {
				return canonicalRecordKey{}, ErrInvalidExportRecord
			}
			eventID = parsed.String()
		} else {
			return canonicalRecordKey{}, ErrInvalidExportRecord
		}
	}
	parsedID, err := uuid.Parse(eventID)
	if err != nil {
		return canonicalRecordKey{}, ErrInvalidExportRecord
	}
	occurredAt, err := canonicalTime(record["occurred_at"])
	if err != nil {
		return canonicalRecordKey{}, ErrInvalidExportRecord
	}
	return canonicalRecordKey{occurredAt: occurredAt.UTC(), eventID: parsedID.String(), logType: logType}, nil
}

func canonicalTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case time.Time:
		if v.IsZero() {
			return time.Time{}, ErrInvalidExportRecord
		}
		return v, nil
	case string:
		return time.Parse(time.RFC3339Nano, v)
	default:
		return time.Time{}, ErrInvalidExportRecord
	}
}
