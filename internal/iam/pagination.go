package iam

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/uuid"
)

func encodeIAMCursor(createdAt time.Time, id uuid.UUID) string {
	payload := createdAt.UTC().Format(time.RFC3339Nano) + "\n" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeIAMCursor(cursor string) (time.Time, uuid.UUID, error) {
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cursor))
	if err != nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	id, err := uuid.Parse(parts[1])
	if err != nil || id == uuid.Nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	return createdAt.UTC(), id, nil
}
